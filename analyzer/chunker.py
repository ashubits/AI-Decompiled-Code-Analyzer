# ----------------------------------------------------------------------
# File: analyzer/chunker.py
# Description: Handles smart chunking of code files.
# ----------------------------------------------------------------------
import re
import os
try:
    import clang.cindex
    HAS_CLANG = True
except Exception:
    HAS_CLANG = False

def chunk_code(filename, code_content):
    """Orchestrator function to select the correct chunker based on file extension."""
    _, extension = os.path.splitext(filename.lower())
    if extension in ['.c', '.h', '.cpp']:
        return _chunk_c_cpp_code(code_content)
    elif extension == '.cs':
        return _chunk_csharp_code(code_content)
    elif extension == '.py':
        return _chunk_python_code(code_content)
    elif extension == '.js':
        return _chunk_javascript_code(code_content)
    else:
        # Fallback for .txt or other files: try to detect language
        if 'def ' in code_content or 'class ' in code_content and ':' in code_content:
            return _chunk_python_code(code_content)
        elif 'function' in code_content or '=>' in code_content:
            return _chunk_javascript_code(code_content)
        else:
            return _chunk_c_cpp_code(code_content)

def _chunk_c_cpp_code(code_content, filename='temp.c'):
    """
    Parses C/C++ code using libclang (AST-based) and extracts functions.
    Falls back to regex if libclang is unavailable.
    """
    if HAS_CLANG:
        try:
            index = clang.cindex.Index.create()
            tu = index.parse(filename, args=[], unsaved_files=[(filename, code_content)])
            
            chunks = []
            for node in tu.cursor.get_children():
                if node.kind == clang.cindex.CursorKind.FUNCTION_DECL and node.is_definition():
                    start_offset = node.extent.start.offset
                    end_offset = node.extent.end.offset
                    function_code = code_content[start_offset:end_offset]
                    chunks.append(function_code.strip())
            if chunks:
                return chunks
        except Exception as e:
            print(f"[!] libclang error, falling back to regex: {e}")
            pass

    # Regex fallback
    pattern = r"(?:(?:static|inline|__inline__|_stdcall|_cdecl|_fastcall)\s+)*[\w\<\>\[\]\:\*]+\s+[\w\:\~]+\s*\([^;\{]*?\)\s*\{"
    chunks = []
    
    for match in re.finditer(pattern, code_content, re.MULTILINE | re.DOTALL):
        start_index = match.start()
        brace_start = match.end() - 1
        
        open_braces = 0
        current_pos = brace_start
        
        in_string, in_char, is_escaping = False, False, False
        in_single_line_comment, in_multi_line_comment = False, False

        while current_pos < len(code_content):
            char = code_content[current_pos]
            
            if is_escaping:
                is_escaping = False
                current_pos += 1
                continue
            
            if char == '\\' and (in_string or in_char):
                is_escaping = True
                current_pos += 1
                continue

            if in_single_line_comment:
                if char == '\n': in_single_line_comment = False
            elif in_multi_line_comment:
                if char == '*' and current_pos + 1 < len(code_content) and code_content[current_pos+1] == '/':
                    in_multi_line_comment = False
                    current_pos += 1
            elif in_string:
                if char == '"': in_string = False
            elif in_char:
                if char == "'": in_char = False
            else:
                if char == '/' and current_pos + 1 < len(code_content):
                    if code_content[current_pos+1] == '/':
                        in_single_line_comment = True
                        current_pos += 1
                    elif code_content[current_pos+1] == '*':
                        in_multi_line_comment = True
                        current_pos += 1
                elif char == '"': in_string = True
                elif char == "'": in_char = True
                elif char == '{': open_braces += 1
                elif char == '}':
                    open_braces -= 1
                    if open_braces == 0:
                        chunks.append(code_content[start_index : current_pos + 1].strip())
                        break
            current_pos += 1

    if not chunks and code_content.strip():
        return [code_content.strip()]
    return chunks

def _chunk_csharp_code(code_content):
    """
    Robustly splits C# code into chunks by identifying namespaces, classes, and methods,
    then finding their matching closing braces while ignoring syntax-internal braces.
    """
    # Regex to identify the start of significant C# blocks
    # Matches: namespace Name {, class Name {, [Attributes] public void Method() {
    modifiers = r"(?:(?:\[.*\]\s*)*(?:public|private|internal|protected|static|async|unsafe|partial|override|virtual|abstract|sealed)\s+)*"
    method_pattern = r"(?:[\w\<\>\[\]\?]+\s+){1,2}\w+\s*\(.*?\)\s*(?::\s*[\w\.\s,<>]+)?\s*"
    type_pattern = r"(?:namespace\s+[\w\.]+|class\s+[\w\<\>]+|struct\s+[\w\<\>]+|interface\s+[\w\<\>]+|enum\s+[\w\<\>]+)(?:\s*:\s*[\w\.\s,<>]+)?\s*"
    
    pattern = rf"(?:^|\n)\s*(?P<header>{modifiers}(?:{method_pattern}|{type_pattern}))\{{"
    
    chunks = []
    # We use finditer to locate potential block starts
    for match in re.finditer(pattern, code_content, re.MULTILINE | re.DOTALL):
        start_index = match.start()
        header_text = match.group('header')
        
        # The opening brace is at the end of the entire match
        brace_start = match.end() - 1
        
        open_braces = 0
        current_pos = brace_start
        in_string = False
        in_char = False
        in_single_line_comment = False
        in_multi_line_comment = False
        is_escaping = False
        
        # Scanner loop to find the matching '}'
        while current_pos < len(code_content):
            char = code_content[current_pos]
            
            # Escape character handling
            if is_escaping:
                is_escaping = False
                current_pos += 1
                continue
            
            if char == '\\' and (in_string or in_char):
                is_escaping = True
                current_pos += 1
                continue

            # Update state
            if in_single_line_comment:
                if char == '\n':
                    in_single_line_comment = False
            elif in_multi_line_comment:
                if char == '*' and current_pos + 1 < len(code_content) and code_content[current_pos+1] == '/':
                    in_multi_line_comment = False
                    current_pos += 1 # Skip '*'
            elif in_string:
                if char == '"':
                    in_string = False
            elif in_char:
                if char == "'":
                    in_char = False
            else:
                # Potential start of something
                if char == '/' and current_pos + 1 < len(code_content):
                    if code_content[current_pos+1] == '/':
                        in_single_line_comment = True
                        current_pos += 1
                    elif code_content[current_pos+1] == '*':
                        in_multi_line_comment = True
                        current_pos += 1
                elif char == '"':
                    in_string = True
                elif char == "'":
                    in_char = True
                elif char == '{':
                    open_braces += 1
                elif char == '}':
                    open_braces -= 1
                    if open_braces == 0:
                        # Found the matching closing brace
                        chunk_text = code_content[start_index : current_pos + 1].strip()
                        if chunk_text:
                            chunks.append(chunk_text)
                        break
            
            current_pos += 1
            
    # Fallback to the whole file if no chunks were extracted
    if not chunks and code_content.strip():
        return [code_content.strip()]

    return chunks

def _chunk_python_code(code_content):
    """
    Splits Python code into chunks based on function and class definitions.
    Uses AST (Abstract Syntax Tree) when available, falls back to regex.
    """
    try:
        import ast
        tree = ast.parse(code_content)
        chunks = []

        # Extract top-level functions and classes
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Get the source code for this node
                try:
                    lines = code_content.split('\n')
                    start = node.lineno - 1
                    end = node.end_lineno if hasattr(node, 'end_lineno') else node.lineno
                    chunk = '\n'.join(lines[start:end])
                    if chunk.strip():
                        chunks.append(chunk.strip())
                except:
                    pass

        if chunks:
            return chunks
    except SyntaxError:
        pass

    # Fallback: regex-based extraction
    # Match function and class definitions
    pattern = r"^(def|class)\s+\w+.*?(?=^(def|class|\Z))"
    matches = re.findall(pattern, code_content, re.MULTILINE | re.DOTALL)

    chunks = []
    for match in re.finditer(pattern, code_content, re.MULTILINE | re.DOTALL):
        chunk = match.group(0).strip()
        if chunk:
            chunks.append(chunk)

    if not chunks and code_content:
        return [code_content.strip()]

    return chunks

def _chunk_javascript_code(code_content):
    """
    Splits JavaScript code into chunks based on function and class definitions.
    Handles both arrow functions and regular function declarations.
    """
    chunks = []

    # Pattern to match various function/class definitions
    # Matches: function foo() {}, const foo = () => {}, class Foo {}, async function foo() {}
    pattern = r"(?:async\s+)?(?:function\s+\w+|const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=|class\s+\w+)\s*(?:\(.*?\))?\s*(?:=>)?\s*\{(?:[^{}]|\{[^{}]*\})*\}"

    for match in re.finditer(pattern, code_content, re.DOTALL):
        chunk = match.group(0).strip()
        if chunk:
            chunks.append(chunk)

    # If no chunks found, try simpler function extraction
    if not chunks:
        simple_pattern = r"(?:function|const|let|var|class)\s+\w+[^{]*\{[^{}]*\}"
        for match in re.finditer(simple_pattern, code_content, re.DOTALL):
            chunk = match.group(0).strip()
            if chunk:
                chunks.append(chunk)

    if not chunks and code_content:
        return [code_content.strip()]

    return chunks