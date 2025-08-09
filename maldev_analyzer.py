"""
MalDev Analyzer MCP
Copyright (c) 2025 Maor Tal (RootInj3c)

This software is licensed under the MIT License.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all  
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  
SOFTWARE.
"""

from typing import Any
from mcp.server.fastmcp import FastMCP
import hashlib
import os
import re
import json
import pefile
import math

mcp = FastMCP("OPSEC")

def find_suspicious_apis(strings: list[str]) -> list:
    suspicious = [
        # Process and memory manipulation
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
        'WriteProcessMemory', 'ReadProcessMemory', 'NtWriteVirtualMemory', 'NtReadVirtualMemory',
        'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx', 'RtlCreateUserThread',
        'QueueUserAPC', 'SetThreadContext', 'GetThreadContext', 'ResumeThread', 'SuspendThread',
        'OpenProcess', 'OpenThread', 'MapViewOfFile', 'UnmapViewOfFile', 'FlushInstructionCache',
        'NtCreateSection', 'ZwMapViewOfSection', 'NtMapViewOfSection',

        # DLL injection / loader
        'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
        'GetProcAddress', 'GetModuleHandleA', 'GetModuleHandleW', 'GetModuleFileNameA', 'GetModuleFileNameW',
        'FreeLibrary', 'LdrLoadDll', 'LdrGetProcedureAddress',

        # Shell / command execution
        'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'CreateProcessA', 'CreateProcessW',
        'NtCreateUserProcess', 'system', 'popen',

        # API unhooking and evasion
        'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'NtOpenSection',
        'NtProtectVirtualMemory', 'NtAllocateVirtualMemory', 'NtFreeVirtualMemory',
        'NtQueryInformationProcess', 'NtQuerySystemInformation', 'NtClose', 'NtCreateFile',
        'NtSetContextThread', 'NtGetContextThread', 'NtContinue',

        # Anti-debugging / sandbox evasion
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationThread',
        'OutputDebugStringA', 'OutputDebugStringW', 'GetTickCount', 'GetTickCount64',
        'QueryPerformanceCounter', 'NtSetInformationThread', 'NtYieldExecution',
        'GetLastInputInfo', 'GetCursorPos', 'FindWindowA', 'GetForegroundWindow',
        'GetSystemMetrics', 'QueryDosDeviceA', 'NtQueryObject', 'GlobalMemoryStatusEx',
        'GetSystemInfo', 'IsWow64Process', 'IsWow64Process2',

        # AMSI / ETW bypass
        'AmsiScanBuffer', 'AmsiScanString', 'AmsiInitialize',
        'EtwEventWrite', 'EtwRegister', 'EtwUnregister',

        # Network / C2
        'InternetOpenA', 'InternetConnectA', 'InternetOpenUrlA', 'HttpOpenRequestA',
        'HttpSendRequestA', 'InternetReadFile', 'InternetCloseHandle',
        'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest', 'WinHttpReceiveResponse',
        'WSASocketA', 'WSAStartup', 'send', 'recv', 'connect', 'socket', 'bind',

        # Persistence
        'RegOpenKeyExA', 'RegSetValueExA', 'RegCreateKeyExA', 'RegCloseKey',
        'RegQueryValueExA', 'RegDeleteKeyA',
        'SetWindowsHookExA', 'SetWindowsHookExW', 'CreateServiceA', 'StartServiceA',
        'CoCreateInstance', 'IPersistFile', 'ITaskService', 'ITaskDefinition',

        # Token / privilege manipulation
        'OpenProcessToken', 'AdjustTokenPrivileges', 'SetThreadToken',
        'DuplicateTokenEx', 'LookupPrivilegeValueA', 'GetTokenInformation',

        # IPC & named pipes
        'CreateNamedPipeA', 'ConnectNamedPipe', 'CallNamedPipeA',
        'CreateFileMappingA', 'MapViewOfFile',

        # WMI execution
        'IWbemLocator::ConnectServer', 'IWbemServices::ExecQuery', 'IWbemServices::GetObject',

        # CLR hosting
        'CorBindToRuntime', 'ICLRMetaHost', 'ICLRRuntimeInfo', 'ICLRRuntimeHost',
        'LoadLibraryShim',

        # Driver loading / BYOVD
        'NtLoadDriver', 'ZwSetSystemInformation',

        # Sleep masking / obfuscation
        'NtDelayExecution', 'NtSetTimerResolution', 'SetWaitableTimer', 'CreateWaitableTimer', 'WaitForSingleObject',

        # Other enumeration
        'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
        'EnumProcesses', 'EnumProcessModules', 'GetStartupInfoA',
        'Sleep', 'SleepEx'
    ]
    found = set()

    for s in strings:
        for api in suspicious:
            if api.lower() in s.lower():
                found.add(api)

    return list(found)
    
def score_entropy_label(entropy: float) -> str:
    if entropy < 1.5:
        return "🔴 Very Low (null-padded or malformed)"
    elif entropy < 5.0:
        return "🟠 Low (structured/textual)"
    elif entropy < 6.5:
        return "🟡 Medium (typical binary)"
    elif entropy < 7.4:
        return "🟢 High (normal PE/mixed content)"
    else:
        return "🔴 Suspicious (encrypted, packed, or shellcode)"

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1

    entropy = 0.0
    data_len = len(data)
    for count in frequency:
        if count == 0:
            continue
        p_x = count / data_len
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)

# Common C2 / post-ex frameworks (expand anytime)
C2_TERMS = {
    "cobalt", "cobaltstrike", "bruteratel", "brc4",
    "sliver", "mythic", "empire", "powershell-empire", "poshc2",
    "havoc", "covenant", "metasploit", "msf", "merlin", "nimplant",
    "koadic", "apfell", "nighthawk", "arkime", "quasar", "pupy",
    "basilisk", "venom", "hive", "deimos", "poseidon", "adversary",
    "grunt", "beacon", "agent", "implant"
}
# Benign exports to ignore
BENIGN_EXPORT_WHITELIST = {
    "dllmain", "dllregisterserver", "dllunregisterserver",
    "dllgetclassobject", "dllcanunloadnow",
    "main", "winmain", "wwinmain"
}

# Object terms you already track
OBJECT_TERMS = (
    "payload", "shell", "module", "beacon", "agent", "sliver",
    "implant", "stager", "stage", "shellcode", "dll", "service",
    "task", "command", "cmd", "bootstrap", "entry", "entrypoint",
    "inject", "injector"
)

# Focused regexes; we’ll inject C2 terms dynamically below
BASE_PATTERNS = [
    (re.compile(r"reflective(main|loader)?", re.I), 3),
    (re.compile(r"loader", re.I), 2),
    (re.compile(r"inject|injector", re.I), 3),
    (re.compile(r"shellcode", re.I), 3),
    (re.compile(r"^(?:exec|execute)(?:_)?(?:payload|shell|module)?$", re.I), 2),
    (re.compile(r"^start(?:_)?(?:beacon|agent|service)?$", re.I), 3),
    (re.compile(r"stager|stage\d+", re.I), 2),
    (re.compile(r"entrypoint|entry$", re.I), 1),
    (re.compile(r"bootstrap|boot", re.I), 1),
]

def find_c2_terms_in_strings(strings: list[str]) -> list[str]:
    hits = set()
    for s in strings:
        low = s.lower()
        for term in C2_TERMS:
            if term in low:
                hits.add(term)
    return sorted(hits)

# Heuristic: Run/Load followed by CamelCase token (e.g., RunSliver, LoadBeacon)
CAMEL_AFTER_VERB = re.compile(r"^(?:run|load)[A-Z][A-Za-z0-9]{2,}$")

def _compiled_c2_patterns():
    """
    Build precise patterns that match:
      - ^(run|load|start|exec)C2TERM$
      - ^(run|load|start|exec)_(c2term|objectterm)$
      - anywhere occurrence of c2term in export (lower weight)
    """
    # anchor verbs + C2/object terms
    joint = "|".join(map(re.escape, sorted(set(C2_TERMS) | set(OBJECT_TERMS))))
    verb_block = r"(?:run|load|start|exec|execute)"
    patterns = [
        (re.compile(rf"^{verb_block}(?:_)?(?:{joint})(\d+)?$", re.I), 3), 
        (re.compile(rf"(?:^|_)(?:{joint})(?:_|$)", re.I), 2),               
    ]
    return patterns

@mcp.tool()
def analyze_exports_table(file: str) -> dict:
    """Check any suspicous section names in the Export table.

    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    pe = pefile.PE(file)

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return {"export_count": 0, "exports": [], "suspicious_exports": [], "score": 0}

    export_names, flagged, score = [], [], 0
    patterns = BASE_PATTERNS + _compiled_c2_patterns()

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        name = exp.name.decode(errors='ignore')
        export_names.append(name)

        lname = name.lower()
        if lname in BENIGN_EXPORT_WHITELIST:
            continue

        matched = False
        # Precise patterns (incl. C2)
        for rx, weight in patterns:
            if rx.search(name):
                flagged.append(name)
                score += weight
                matched = True
                break

        # If still not matched, apply CamelCase heuristic for Run*/Load*
        if not matched and CAMEL_AFTER_VERB.match(name):
            w = 2 if any(term in lname for term in C2_TERMS | set(OBJECT_TERMS)) else 1
            flagged.append(name)
            score += w

    # Dedup while preserving order
    seen = set()
    suspicious_unique = [x for x in flagged if not (x in seen or seen.add(x))]

    return {
        "export_count": len(export_names),
        "exports": export_names[:50],
        "suspicious_exports": suspicious_unique,
        "score": min(score, 10)
    }
    
@mcp.tool()
def entropy_check(file: str) -> dict:
    """Calculate Shannon entropy of a file.
    
    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    if not os.path.isabs(file):
        file = os.path.join(os.getcwd(), file)

    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}

    with open(file, "rb") as f:
        data = f.read()
        entropy = shannon_entropy(data)

    return {
        "filename": os.path.basename(file),
        "entropy": entropy,
        "rank": score_entropy_label(entropy)
    }

@mcp.tool()
def check_digital_signature(file) -> str:
    """Check presence of signature on the PE file.
    
    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    pe = pefile.PE(file)
    # 0x80 = IMAGE_DIRECTORY_ENTRY_SECURITY
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]

    if security_dir.VirtualAddress != 0:
        return "Present (may be signed)"
    else:
        return "Not present"

@mcp.tool()
def analyze_sections_and_score(file) -> dict:
    """Check any suspicous section names in the PE.
    
    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    pe = pefile.PE(file)

    baseline_sections = {
        '.text', '.rdata', '.data', '.rsrc', '.reloc',
        '.idata', '.pdata', '.bss', '.edata', '.crt', '.tls'
    }

    known_packer_prefixes = ['.upx', '.vmp', '.aspack', '.petite', '.mpress', '.wwpack']

    section_data = []
    red_flags = 0

    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode(errors='ignore').lower()
        data = section.get_data()
        entropy = shannon_entropy(data)
        rva = hex(section.VirtualAddress)
        size = section.SizeOfRawData

        # Classification
        if name in baseline_sections:
            category = 'baseline'
        elif any(name.startswith(p) for p in known_packer_prefixes):
            category = 'packer_like'
            if entropy > 7.4:
                red_flags += 2  # more weight
        elif name.startswith('.') and name[1:].isalnum():
            category = 'suspicious'
            if entropy > 7.4:
                red_flags += 1
        else:
            category = 'unknown'
            if entropy > 7.4:
                red_flags += 1

        section_data.append({
            "name": name,
            "rva": rva,
            "size": size,
            "entropy": entropy,
            "classification": category
        })

    # Final score (0–10 scale)
    score = min(10, red_flags * 2)  # scale up to 10 max

    return {
        "sections": section_data,
        "mal_score": score,
        "verdict": (
            "🔴 High Risk" if score >= 8 else
            "🟠 Suspicious" if score >= 5 else
            "🟢 Clean"
        )
    }

@mcp.tool()
def entropy_sections_check(file) -> list:
    """Calculate Shannon entropy of each PE sections.
    
    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    try:
        pe = pefile.PE(file)
    except Exception as e:
        return {"error": f"Not a valid PE file: {str(e)}"}

    results = []

    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode(errors='ignore')
        data = section.get_data()
        entropy = shannon_entropy(data)

        results.append({
            "name": name,
            "virtual_address": hex(section.VirtualAddress),
            "size": section.SizeOfRawData,
            "entropy": round(entropy, 4)
        })

    return results

@mcp.tool()
def parse_iat(file: str) -> dict:
    """Parsing the Import Address Table (IAT) from a PE file.
    
    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    try:
        pe = pefile.PE(file)
    except Exception as e:
        return {"error": f"Not a valid PE file: {str(e)}"}

    results = []

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return {"info": "No import table found (possible shellcode or packed binary)"}

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8', errors='ignore')
        functions = []
        for imp in entry.imports:
            func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
            functions.append({
                "name": func_name,
                "iat_rva": hex(imp.address - pe.OPTIONAL_HEADER.ImageBase)
            })
        results.append({
            "dll": dll_name,
            "functions": functions
        })

    return {
        "imports": results
    }

@mcp.tool()
def file_hashes(file: str) -> dict:
    """Get hashes for a file provided by the user.

    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    # If path is not absolute, try common locations
    possible_paths = [
        file,
        os.path.join(os.getcwd(), file),
        os.path.join(os.environ.get("TEMP", "/tmp"), "claude", "files", file)
    ]

    for path in possible_paths:
        if os.path.exists(path):
            file = path
            break
    else:
        return {"error": f"File not found in known locations: {file}"}

    result = {
        "filename": os.path.basename(file),
        "size_bytes": os.path.getsize(file)
    }

    # Compute hashes
    with open(file, "rb") as f:
        data = f.read()
        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["md5"] = hashlib.md5(data).hexdigest()

    return result

def _utf16le_bytes(s: str) -> bytes:
    return b"".join(ch.encode("ascii", "ignore") + b"\x00" for ch in s)

def _find_terms_fast(data: bytes, terms: list[str] | set[str]) -> list[str]:
    """Fast whole-file scan for ASCII & UTF-16LE encodings of given terms."""
    hits = set()
    for t in terms:
        if not t: 
            continue
        ascii_pat = re.compile(re.escape(t).encode("ascii", "ignore"), re.IGNORECASE)
        u16_pat   = re.compile(re.escape(_utf16le_bytes(t)), re.IGNORECASE)
        if ascii_pat.search(data) or u16_pat.search(data):
            hits.add(t.lower())
    return sorted(hits)

@mcp.tool()
def extract_strings(file: str, min_length: int = 4, max_total: int = 20, deep_scan: bool = False) -> dict:
    """Get top-N strings and flag suspicious APIs & C2 terms.
    If deep_scan=True, scan the whole file bytes for API/C2 terms without extracting all strings.
    No need to explain how it can be useful for. Just display the data.

    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}

    with open(file, "rb") as f:
        data = f.read()

    # --- FAST top-N strings (display) ---
    ascii_strings   = re.findall(rb'[\x20-\x7E]{%d,}' % min_length, data)
    unicode_strings = re.findall(rb'(?:[\x20-\x7E]\x00){%d,}' % min_length, data)

    ascii_decoded   = [s.decode('ascii', errors='ignore') for s in ascii_strings]
    utf16le_decoded = [s.decode('utf-16le', errors='ignore') for s in unicode_strings]

    combined = ascii_decoded + utf16le_decoded
    # sort by length desc, then dedup while preserving order
    combined.sort(key=len, reverse=True)
    seen = set()
    top_strings = []
    for s in combined:
        if s not in seen:
            seen.add(s)
            top_strings.append(s)
            if len(top_strings) >= max_total:
                break

    # --- Detection paths ---
    if deep_scan:
        # Fast whole-file pattern scan (no full string extraction)
        api_hits = _find_terms_fast(data, suspicious)
        c2_hits  = _find_terms_fast(data, C2_TERMS)
    else:
        # Light: only check the displayed strings
        api_hits = find_suspicious_apis(top_strings)
        c2_hits  = find_c2_terms_in_strings(top_strings)

    return {
        "top_strings": top_strings,
        "suspicious_apis": api_hits,
        "c2_terms": c2_hits,
        "mode": "deep_scan" if deep_scan else "fast"
    }

@mcp.tool()
def extract_and_flag_apis(file: str) -> dict:
    """Extract strings and flag suspicious API calls.
    No need to explain how it can be useful for. Just display the strings that may be suspicous.

    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}

    strings_result = extract_strings(file)
    strings = strings_result.get("top_strings", [])

    found_apis = find_suspicious_apis(strings)

    return {
        "suspicious_apis": found_apis
    }

def extract_and_flag_apis(file: str) -> dict:
    """Extract strings and flag APIs that appear in strings but are NOT in the IAT.
    Inteded to detect IAT hiding and dynamic API resolution (e.g via GetModuleHandle or GetProcAddress)

    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}

    try:
        pe = pefile.PE(file)
    except Exception as e:
        return {"error": f"Failed to parse PE file: {str(e)}"}

    # Extract suspicious strings from binary
    strings_result = extract_strings(file)
    strings = strings_result.get("top_strings", [])

    # Extract IAT imports (just API names)
    imported_apis = set()
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imported_apis.add(imp.name.decode('utf-8', errors='ignore'))

    # Find suspicious APIs from strings
    all_api_hits = find_suspicious_apis(strings)

    # Flag only APIs found in strings but NOT present in IAT
    dynamic_only = [api for api in all_api_hits if api not in imported_apis]

    return {
        "suspicious_apis_not_in_iat": dynamic_only
    }

if __name__ == "__main__":
    # Run with stdio transport for Claude compatibility
    mcp.run(transport='stdio')
