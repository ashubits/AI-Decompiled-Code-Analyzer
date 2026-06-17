import os
import json
import csv
import hashlib
import concurrent.futures
from datetime import datetime
from analyzer.chunker import chunk_code
from analyzer.gemini_analyzer import analyze_code_chunks
from analyzer.result_logger import ResultLogger
import re
import configparser
import threading
import shutil

# Configuration Loading
config = configparser.ConfigParser()
config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'config.cfg'))
if os.path.exists(config_path):
    config.read(config_path)
    config_dir = os.path.dirname(config_path)
else:
    print(f"[!] Warning: Configuration file not found at {config_path}")
    config_dir = os.path.dirname(__file__)

def get_abs_path(section, key, fallback):
    if config.has_option(section, key):
        return os.path.join(config_dir, config.get(section, key))
    return fallback

csv_lock = threading.Lock()
print_lock = threading.Lock()

# Configuration
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
OUTPUT_FILE = get_abs_path('Paths', 'output_csv', os.path.join(config_dir, "OUTPUT_RESULT.CSV"))
CACHE_DIR = "analysis_cache"
REPORTS_DIR = get_abs_path('Paths', 'reports_dir', os.path.join(config_dir, "reports"))

# CSV Headers (Global)
HEADERS = [
    "FILE NAME", "SUCCESSFULL/ERROR", "IS ERROR", "ERROR DESCRIPTION",
    "VERDICT ON FILE", "MALWARE FAMILY", "MALICIOUS ARTIFACTS",
    "NO OF FUNCTION FOUND IN FILE", "NUMBER OF FUNCTIONS SUSPICIOUS WITH FUNCTION NAME",
    "TOKENS USED", "FINAL ANALYSIS"
]

os.makedirs(CACHE_DIR, exist_ok=True)

def get_file_hash(content):
    """Calculate MD5 hash of file content."""
    return hashlib.md5(content).hexdigest()

def get_cache_path(file_hash):
    """Get the cache file path for a given file hash."""
    return os.path.join(CACHE_DIR, f"{file_hash}.json")

def load_from_cache(file_hash):
    """Load cached analysis results if available."""
    cache_path = get_cache_path(file_hash)
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading cache: {e}")
    return None

def save_to_cache(file_hash, analysis_data):
    """Save analysis results to cache."""
    cache_path = get_cache_path(file_hash)
    try:
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=2)
    except Exception as e:
        print(f"Error saving cache: {e}")

def get_already_processed_files():
    """Reads the OUTPUT_FILE and returns a set of filenames already processed."""
    processed = set()
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("FILE NAME"):
                        processed.add(row["FILE NAME"])
        except Exception as e:
            print(f"Error reading existing CSV: {e}")
    return processed

def write_results_to_csv(results):
    """Appends results to the CSV file or creates it with headers."""
    with csv_lock:
        file_exists = os.path.exists(OUTPUT_FILE)
        
        # Filter results to only include valid headers
        filtered_results = []
        for res in results:
            filtered_res = {k: v for k, v in res.items() if k in HEADERS}
            filtered_results.append(filtered_res)
        
        with open(OUTPUT_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=HEADERS)
            if not file_exists or os.path.getsize(OUTPUT_FILE) == 0:
                writer.writeheader()
            writer.writerows(filtered_results)

def extract_metadata(final_analysis_text):
    """Extract verdict, family and artifacts from the Gemini final report."""
    logger = ResultLogger()
    verdict = logger.extract_verdict(final_analysis_text)
    family = logger.extract_family(final_analysis_text)
    artifacts = logger.extract_artifacts(final_analysis_text)
    return verdict, family, artifacts

def process_file(file_info):
    """Process a single file and return the results for CSV."""
    file_path, filename = file_info
    
    result = {
        "FILE NAME": filename,
        "SUCCESSFULL/ERROR": "ERROR",
        "IS ERROR": "YES",
        "ERROR DESCRIPTION": "",
        "VERDICT ON FILE": "N/A",
        "MALWARE FAMILY": "N/A",
        "MALICIOUS ARTIFACTS": "N/A",
        "NO OF FUNCTION FOUND IN FILE": 0,
        "NUMBER OF FUNCTIONS SUSPICIOUS WITH FUNCTION NAME": "0",
        "TOKENS USED": 0,
        "FINAL ANALYSIS": "N/A",
        "is_api_error": False  # Flag for critical Gemini errors
    }

    try:
        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            result["ERROR DESCRIPTION"] = f"File size ({file_size / 1024 / 1024:.2f} MB) exceeds 5MB limit."
            return result

        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Check content-based cache
        file_hash = get_file_hash(content)
        cached_data = load_from_cache(file_hash)
        
        if cached_data:
            print(f"[*] Using cached analysis for {filename}")
            analysis = cached_data
        else:
            print(f"[*] Analyzing {filename}...")
            # Detect code content
            text_content = content.decode('utf-8', errors='ignore')
            chunks = chunk_code(filename, text_content)
            
            if not chunks:
                result["ERROR DESCRIPTION"] = "No functions or classes found in file."
                return result
            
            # Extract binary MD5 from filename (e.g. <MD5>.c)
            binary_md5 = filename.split('.')[0].lower()
            
            # Read static analysis if it exists
            static_analysis_text = ""
            static_report_path = os.path.join(REPORTS_DIR, binary_md5, "staticAnalysis.txt")
            if os.path.exists(static_report_path):
                try:
                    with open(static_report_path, "r", encoding="utf-8") as sf:
                        static_analysis_text = sf.read()
                except Exception as e:
                    print(f"    [!] Warning: Could not read static analysis report: {e}")
            
            analysis = analyze_code_chunks(chunks, filename, static_analysis_text)
            if not analysis.get("success"):
                result["ERROR DESCRIPTION"] = analysis.get("error", "AI Analysis failed.")
                result["is_api_error"] = True # Mark as critical Gemini failure
                return result
            
            # Save to cache
            save_to_cache(file_hash, analysis)

        # Process Results
        final_text = analysis.get("final_analysis", "")
        verdict, family, artifacts = extract_metadata(final_text)
        
        func_analyses = analysis.get("function_analyses", [])
        total_functions = len(func_analyses)
        tokens_used = analysis.get("total_tokens", 0)
        
        suspicious_funcs = []
        for func_res in func_analyses:
            data = func_res.get("data", {})
            indicators = data.get("suspicious_indicators") or []
            # Filter out "None" or empty indicators
            real_indicators = [i for i in indicators if i and i.lower() != 'none']
            if real_indicators:
                func_name = data.get("function_name", "Unknown")
                suspicious_funcs.append(func_name)
        
        suspicious_info = f"{len(suspicious_funcs)} ({', '.join(suspicious_funcs)})" if suspicious_funcs else "0"

        result.update({
            "SUCCESSFULL/ERROR": "SUCCESSFULL",
            "IS ERROR": "NO",
            "VERDICT ON FILE": verdict,
            "MALWARE FAMILY": family,
            "MALICIOUS ARTIFACTS": artifacts,
            "NO OF FUNCTION FOUND IN FILE": total_functions,
            "NUMBER OF FUNCTIONS SUSPICIOUS WITH FUNCTION NAME": suspicious_info,
            "TOKENS USED": tokens_used,
            "FINAL ANALYSIS": final_text.strip()
        })
        
        # --- Report Generation ---
        try:
            binary_md5 = filename.split('.')[0].lower()
            report_folder = os.path.join(REPORTS_DIR, binary_md5)
            os.makedirs(report_folder, exist_ok=True)
            
            # Copy decompiled file
            shutil.copy2(file_info[0], os.path.join(report_folder, file_info[1]))
            
            # Write overall verdict
            overall_path = os.path.join(report_folder, "overall_verdict.md")
            with open(overall_path, "w", encoding="utf-8") as rf:
                rf.write(f"# Overall Verdict for {filename}\n\n")
                rf.write(f"**MD5:** {file_hash}\n")
                rf.write(f"**Verdict:** {verdict}\n")
                rf.write(f"**Family:** {family}\n")
                rf.write(f"**Artifacts:** {artifacts}\n\n")
                rf.write(f"## Final Analysis\n\n{final_text}\n")
                
            # Write function specific reports
            func_reports_dir = os.path.join(report_folder, "individual_function_gemini_result")
            if func_analyses:
                os.makedirs(func_reports_dir, exist_ok=True)
                
            for idx, func_res in enumerate(func_analyses):
                data = func_res.get("data", {})
                func_name = data.get("function_name", f"UnknownFunction_{idx}")
                # Sanitize filename
                safe_func_name = re.sub(r'[\\/*?:"<>|]', "", func_name)
                func_path = os.path.join(func_reports_dir, f"func_{safe_func_name}.md")
                
                with open(func_path, "w", encoding="utf-8") as ff:
                    ff.write(f"# Function: {func_name}\n\n")
                    ff.write("## Suspicious Indicators\n")
                    inds = data.get("suspicious_indicators") or []
                    if not inds:
                        ff.write("None\n\n")
                    else:
                        for ind in inds:
                            ff.write(f"- {ind}\n")
                        ff.write("\n")
                    
                    ff.write("## Raw Data\n")
                    ff.write("```json\n")
                    ff.write(json.dumps(data, indent=2))
                    ff.write("\n```\n")
        except Exception as report_err:
            print(f"[!] Warning: Failed to generate report for {filename}: {report_err}")

    except Exception as e:
        result["ERROR DESCRIPTION"] = str(e)
    
    return result

def main(directory_path):
    if not os.path.isdir(directory_path):
        print(f"Error: {directory_path} is not a valid directory.")
        return

    already_processed = get_already_processed_files()
    if already_processed:
        print(f"[*] Found {len(already_processed)} entries in existing CSV. They will be skipped.")

    # 2. Gather files from directory
    supported_extensions = {'.c', '.h', '.cpp', '.cs', '.py', '.js', '.txt'}
    all_files = []
    cached_files_count = 0
    
    print(f"[*] Scanning directory: {directory_path}")
    for root, _, files in os.walk(directory_path):
        for file in files:
            if any(file.lower().endswith(ext) for ext in supported_extensions):
                full_path = os.path.join(root, file)
                # Skip if already in CSV
                if file in already_processed:
                    continue
                
                # Check if it exists in analysis_cache to avoid "processing" batch
                try:
                    with open(full_path, 'rb') as f:
                        content = f.read()
                    file_hash = get_file_hash(content)
                    cached_data = load_from_cache(file_hash)
                    
                    if cached_data:
                        # process_file will use the cache and extract metadata
                        res = process_file((full_path, file))
                        write_results_to_csv([res])
                        cached_files_count += 1
                        continue
                    file_size = os.path.getsize(full_path)
                    all_files.append((full_path, file, file_size))
                except Exception as e:
                    print(f"[!] Error checking cache for {file}: {e}")

    # 3. Sort files by size (smallest first)
    all_files.sort(key=lambda x: x[2])

    if cached_files_count > 0:
        print(f"[*] Found {cached_files_count} files in cache. CSV has been updated for them.")

    if not all_files:
        print("No new files to Analyze (all files were either in CSV or in Cache).")
        return

    print(f"[*] Found {len(all_files)} new files to analyze. Starting sequential analysis...")

    api_error_occurred = False
    files_processed_count = 0
    
    def worker(item):
        nonlocal files_processed_count
        full_path, filename, size = item
        res = process_file((full_path, filename))
        
        # Check for critical API error
        if res.get("is_api_error"):
            with print_lock:
                print(f"\n[!] CRITICAL ERROR: Gemini API request failed for {res['FILE NAME']}.")
                print(f"    Error: {res['ERROR DESCRIPTION']}")
        
        # Incremental CSV Update
        write_results_to_csv([res])
        
        with print_lock:
            files_processed_count += 1
            print(f"[+] Finished: {res['FILE NAME']} -> {res['SUCCESSFULL/ERROR']} ({res.get('TOKENS USED', 0)} tokens)")
            print(f"[+] CSV Updated. Progress: {files_processed_count}/{len(all_files)}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        executor.map(worker, all_files)

    if files_processed_count > 0:
        print(f"\n[!] Analysis session complete. {files_processed_count} new results appended to {OUTPUT_FILE}")
    else:
        print("\n[!] No new results were generated.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python bulk_analyzer.py <directory_path>")
    else:
        main(sys.argv[1])
