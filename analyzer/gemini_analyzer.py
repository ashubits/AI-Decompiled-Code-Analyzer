# ----------------------------------------------------------------------
# File: analyzer/gemini_analyzer.py
# Description: Manages interactions with the Gemini API using a multithreaded approach.
# ----------------------------------------------------------------------
import os
import traceback
import json
import google.generativeai as genai
import concurrent.futures
import time

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure the Gemini API client using an environment variable
api_key = os.environ.get('GEMINI_API_KEY')
if not api_key:
    raise ValueError("A GEMINI_API_KEY environment variable is required to run this application.")

genai.configure(api_key=api_key)

# Using the latest stable Gemini 3 Flash Preview model
model_name = 'gemini-3-flash-preview'
model = genai.GenerativeModel(model_name)

# Define the schema for the structured information we want from each function
FUNCTION_ANALYSIS_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "function_name": {"type": "STRING"},
        "purpose": {"type": "STRING"},
        "called_functions": { "type": "ARRAY", "items": {"type": "STRING"} },
        "suspicious_indicators": { "type": "ARRAY", "items": {"type": "STRING"} },
        "is_malicious": {"type": "BOOLEAN"},
        "malicious_reasoning": {"type": "STRING"}
    },
    "required": ["function_name", "purpose", "called_functions", "suspicious_indicators", "is_malicious", "malicious_reasoning"]
}

BATCH_ANALYSIS_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "function_analyses": {
            "type": "ARRAY",
            "items": FUNCTION_ANALYSIS_SCHEMA
        }
    },
    "required": ["function_analyses"]
}

def pack_chunks(chunks, max_tokens=50000):
    """
    Groups code chunks into larger batches to reduce API requests.
    Estimate: 1 token ≈ 4 characters for code.
    """
    batches = []
    current_batch = []
    current_length = 0
    
    for chunk in chunks:
        # Check if adding this chunk would exceed the limit
        if (current_length + len(chunk)) / 4 > max_tokens and current_batch:
            batches.append(current_batch)
            current_batch = [chunk]
            current_length = len(chunk)
        else:
            current_batch.append(chunk)
            current_length += len(chunk)
            
    if current_batch:
        batches.append(current_batch)
    return batches

def _analyze_batch(args):
    """
    Worker function to analyze a batch of code chunks.
    """
    batch_chunks, filename, index, total_batches = args
    
    # Combined code block
    combined_code = "\n\n".join([f"// --- Function {i+1} ---\n{c}" for i, c in enumerate(batch_chunks)])
    
    prompt = f"""
    Analyze the following code block from the file '{filename}'.
    It contains multiple functions/classes. For EACH function/class, extract:
    1. Function name.
    2. Primary purpose (in 4 lines or less).
    3. Functions it calls.
    4. Suspicious indicators (e.g., Windows APIs like VirtualAllocEx, crypto used on user files, etc.).
    5. 'is_malicious': Set this to TRUE ONLY if this specific code snippet provides clear and definitive evidence of malicious intent. 
    6. 'malicious_reasoning': If 'is_malicious' is TRUE, explain why in 1-2 sentences.

    Code Block:
    ```
    {combined_code}
    ```
    """

    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
                response_schema=BATCH_ANALYSIS_SCHEMA
            ),
            request_options={"timeout": 600} # Increased timeout for larger batches
        )
        batch_data = json.loads(response.text)
        tokens = response.usage_metadata.total_token_count if hasattr(response, 'usage_metadata') else 0
        
        return {
            "success": True, 
            "data": batch_data.get("function_analyses", []), 
            "tokens": tokens,
            "request_num": index + 1
        }

    except Exception as e:
        error_msg = str(e)
        is_connection_error = any(indicator in error_msg for indicator in ["503", "failed to connect", "DeadlineExceeded", "handshaker shutdown"])
        
        if is_connection_error:
            print(f"\n[!] Connection error detected during batch {index + 1}: {type(e).__name__} - {error_msg}")
            print("[!] Waiting for 1 HOUR before retrying as per requirement...")
            time.sleep(3600)
            return _analyze_batch(args)

        print(f"Error analyzing batch {index + 1}: {type(e).__name__} - {error_msg}")
        return {
            "success": False, 
            "error": error_msg, 
            "request_num": index + 1,
            "data": [] # Return empty list so loop continues
        }


def analyze_code_chunks(chunks, filename, static_analysis_text=""):
    """
    Non-streaming version of analysis for bulk processing.
    Returns structured results for all chunks and final report.
    """
    try:
        structured_summaries = []
        full_results = []
        
        # 1. Greedy Packing
        packed_batches = pack_chunks(chunks)
        total_batches = len(packed_batches)
        total_functions = len(chunks)
        
        print(f"[*] Packed {total_functions} functions into {total_batches} batches.")
        
        total_tokens = 0
        functions_processed = 0
        for i, batch in enumerate(packed_batches):
            batch_res = _analyze_batch((batch, filename, i, total_batches))
            
            if not batch_res['success']:
                print(f"    [!] Batch {i+1} failed completely.")
                continue

            batch_tokens = batch_res.get('tokens', 0)
            total_tokens += batch_tokens
            
            # Unpack function analyses
            for func_analysis in batch_res['data']:
                functions_processed += 1
                structured_summaries.append(func_analysis)
                # full_results needs a structure like the old one for compatibility
                full_results.append({"success": True, "data": func_analysis})
                
                # EARLY EXIT LOGIC: If any function in the batch is definitively malicious
                if func_analysis.get('is_malicious'):
                    reason = func_analysis.get('malicious_reasoning', 'Undisclosed malicious behavior.')
                    print(f"    [!] EARLY EXIT: Definitive malware evidence found in {func_analysis.get('function_name')}.")
                    print(f"    [!] Reason: {reason}")
                    
                    early_final_analysis = f"""
**1. Overall Functionality:**
Definitive malware evidence was discovered in batch {i+1}. The code performs malicious actions in the function '{func_analysis.get('function_name')}'.

**2. Malicious Artifacts Summary:**
- Early Detection: {reason}
- Indicators: {', '.join(func_analysis.get('suspicious_indicators', []))}

**3. Final Verdict:**
MALWARE (Early Detection)
"""
                    return {
                        "success": True,
                        "filename": filename,
                        "function_analyses": full_results,
                        "final_analysis": early_final_analysis,
                        "total_tokens": total_tokens,
                        "early_exit": True
                    }

            print(f"    [+] Analyzed batch {i+1}/{total_batches} ({len(batch)} functions, total tokens: {batch_tokens})")
        
        # Compile final report
        context_summary_lines = []
        for summary in structured_summaries:
            line = f"function {summary.get('function_name', 'N/A')}() # purpose: {summary.get('purpose', 'N/A').replace(chr(10), ' ')}"
            context_summary_lines.append(line)
            context_summary_lines.append("{")
            for called_func in (summary.get('called_functions') or []):
                context_summary_lines.append(f"  {called_func}()")
            context_summary_lines.append("}")
        context_summary = "\n".join(context_summary_lines)

        final_prompt = f"""
        You are an expert malware analyst. Based on the following function call graph and purpose summary from the file '{filename}', provide a final report.

        Function Summary:
        ```
        {context_summary}
        ```
        """
        
        if static_analysis_text:
            final_prompt += f"""
        Additionally, consider this static analysis report extracted from the original binary:
        ```
        {static_analysis_text}
        ```
        """
        
        final_prompt += """
        Based *only* on this information, provide a final report in the following format. Do not add any extra commentary.

        **1. Overall Functionality:**
        Describe the high-level purpose of the entire file.
        **2. Malicious Artifacts Summary:**
        Summarize all malicious indicators and how they work together.
        **3. Final Verdict:**
        State your final conclusion: MALWARE (with type), LEGITIMATE, or SUSPICIOUS.
        """
        
        final_response = model.generate_content(final_prompt, request_options={"timeout": 600})
        final_tokens = final_response.usage_metadata.total_token_count if hasattr(final_response, 'usage_metadata') else 0
        total_tokens += final_tokens
        
        return {
            "success": True,
            "filename": filename,
            "function_analyses": full_results,
            "final_analysis": final_response.text,
            "total_tokens": total_tokens
        }

    except Exception as e:
        print(f"Error in analyze_code_chunks: {e}")
        return {"success": False, "error": str(e), "filename": filename}