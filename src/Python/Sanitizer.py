import re
import sys
import magic
from urllib.parse import urlparse

def detect_injection(input_string):
    patterns = [
        r"(\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|\bDROP\b|\bUNION\b|\bOR\b|\bAND\b)",  
        r"[\';\"]",  
        r"(--|#|\/*)",  
        r"(\bexec\b|\bexecute\b|\bsp_configure\b)",  
        r"\b(?:chr|char|ascii|substring|substring_index|concat|concat_ws|position|mid|length|repeat)\b",  
        r"(eval|base64_decode|gzinflate|preg_replace|shell_exec|system|exec)",  
        r"(\b\w+@[\w\.]+)",  
        r"(\bscript\b|\balert\b|\bonerror\b|\bwindow\b)",  
    ]

    for pattern in patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True

    return False

def is_executable_file(file_path):
    file_type = magic.from_file(file_path, mime=True)
    executable_types = [
        'application/x-executable',
        'application/x-msdownload',
        'application/x-sh',
        'application/x-python',
        'application/x-perl',
        'application/x-httpd-php',
        'application/x-php',
        'application/x-ruby',
        'application/x-shar',
        'text/x-shellscript',
        'text/x-perl',
        'text/x-python',
    ]

    return file_type in executable_types

def is_url_safe(url):
    parsed_url = urlparse(url)
    if detect_injection(parsed_url.path) or detect_injection(parsed_url.query):
        return False
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python security_detector.py <input_string_or_url>")
        sys.exit(1)

    input_string = sys.argv[1]
    
    if input_string.startswith("http://") or input_string.startswith("https://"):
        if not is_url_safe(input_string):
            print("Potential injection detected in the URL!")
        else:
            print("URL is safe.")
    else:
        if detect_injection(input_string):
            print("Potential injection detected in input!")
        else:
            print("Input is safe.")
