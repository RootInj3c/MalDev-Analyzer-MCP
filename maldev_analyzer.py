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

def _sec_name(sec) -> str:
    return sec.Name.rstrip(b"\x00").decode(errors="ignore")

def _overlaps(a0, a1, b0, b1) -> bool:
    return max(a0, b0) < min(a1, b1)

# PE characteristics flags
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ    = 0x40000000
IMAGE_SCN_MEM_WRITE   = 0x80000000

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
   Just display the data.

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
def pe_metadata(file: str) -> dict:
    """Extract basic PE metadata.
    
    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}
    try:
        pe = pefile.PE(file, fast_load=True)
        pe.parse_data_directories()
    except Exception as e:
        return {"error": f"PE parse failed: {e}"}

    from datetime import datetime
    compile_ts = pe.FILE_HEADER.TimeDateStamp
    metadata = {
        "path": os.path.basename(file),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "compile_time_utc": datetime.utcfromtimestamp(compile_ts).strftime('%Y-%m-%d %H:%M:%S'),
        "machine": hex(pe.FILE_HEADER.Machine),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
    }

    # lightweight compiler/runtime hints
    blob = pe.__data__
    hints = []
    if b"go.buildid" in blob: hints.append("Go")
    if b"mscoree.dll" in blob or b"Microsoft.CSharp" in blob: hints.append(".NET")
    if b"rust_eh_personality" in blob: hints.append("Rust")
    if b"UPX!" in blob: hints.append("Pack:UPX")
    if hints: metadata["compiler_guess"] = ", ".join(hints)

    return metadata

@mcp.tool()
def detect_etw_artifacts(file: str, strict_mode: bool = False) -> dict:
    """Detect ETW usage and common inline patch patterns (e.g., EtwEventWrite -> ret 0)."""
    
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}

    try:
        pe = pefile.PE(file, fast_load=True)
        pe.parse_data_directories()
    except Exception as e:
        return {"error": f"PE parse failed: {e}"}

    etw_imports = []
    has_advapi = False
    imported_etw_rvas = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = (entry.dll or b"").decode(errors="ignore").lower()
            if "advapi32.dll" in dll:
                has_advapi = True
            for imp in entry.imports:
                if not imp.name:
                    continue
                name = imp.name.decode(errors="ignore")
                if name.startswith("Etw"):
                    etw_imports.append(f"{dll}:{name}" if dll else name)
                if name == "EtwEventWrite" and imp.address:
                    try:
                        rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                        imported_etw_rvas.append(rva)
                    except Exception:
                        pass

    with open(file, "rb") as f:
        data = f.read()

    etw_strings = []
    for m in (b"EtwEventWrite", b"EtwRegister", b"EtwUnregister"):
        if m in data:
            etw_strings.append(m.decode("latin1"))

    # patch signatures (same as AMSI, return-success stubs)
    sigs = {
        "x64_xor_rax_ret": b"\x48\x31\xC0\xC3",
        "x64_mov_eax0_ret": b"\xB8\x00\x00\x00\x00\xC3",
        "x86_xor_eax_ret":  b"\x33\xC0\xC3",
        "x86_mov_eax0_ret": b"\xB8\x00\x00\x00\x00\xC3",
    }

    patch_hits = []
    try:
        for s in pe.sections:
            if not (s.Characteristics & IMAGE_SCN_MEM_EXECUTE):
                continue
            sec = s.get_data()
            base_rva = s.VirtualAddress
            name = _sec_name(s)
            for label, sig in sigs.items():
                start = 0
                while True:
                    idx = sec.find(sig, start)
                    if idx == -1:
                        break
                    patch_hits.append({"section": name, "pattern": label, "rva": hex(base_rva + idx)})
                    start = idx + 1
    except Exception:
        pass

    # proximity scan near IAT thunk for EtwEventWrite
    near_hits = []
    try:
        mm = pe.get_memory_mapped_image()
        for rva in imported_etw_rvas:
            window = mm[max(0, rva - 64): rva + 64]
            for label, sig in sigs.items():
                k = window.find(sig)
                if k != -1:
                    near_hits.append({"around": "IAT:EtwEventWrite", "pattern": label, "rva_window_start": hex(max(0, rva - 64))})
    except Exception:
        pass

    have_markers = bool(etw_imports or etw_strings or has_advapi)
    have_patches = bool(patch_hits or near_hits)

    score = 0
    if has_advapi:  score += 1
    if etw_imports: score += 2
    if etw_strings: score += 2
    if have_patches: score += 4
    score = min(10, score)

    if strict_mode:
        verdict = ("🔴 Likely ETW patcher/bypass" if (have_markers and have_patches and score >= 8)
                   else "🟠 ETW usage / possible bypass" if have_markers or have_patches
                   else "🟢 Low")
    else:
        verdict = ("🔴 Likely ETW patcher/bypass" if score >= 8
                   else "🟠 ETW usage / possible bypass" if score >= 5
                   else "🟢 Low")

    return {
        "etw_imports": sorted(set(etw_imports)),
        "etw_strings": sorted(set(etw_strings)),
        "patch_signatures": patch_hits[:100],
        "proximity_hits": near_hits[:50],
        "strict_mode": bool(strict_mode),
        "score": score,
        "verdict": verdict
    }

@mcp.tool()
def detect_hashed_api_resolution(file: str) -> dict:
    """Heuristics for API hashing loops (ROR/XOR) and hashed tables in data sections."""
    
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}
    with open(file, "rb") as f:
        data = f.read()

    is_pe = data.startswith(b"MZ")
    flags = []
    ror_patterns = [
        b"\xC1\xC8\x0D",       # ror eax, 13 (x86)
        b"\x48\xC1\xC9\x0D",   # ror rcx, 13 (x64)
        b"\xC1\xCA\x0D",       # ror edx, 13
        b"\xD1\xC8",           # ror eax,1 (generic)
        b"\x4C\x8B\xD1"        # mov r10,rcx (often in syscall/hash stubs)
    ]
    for p in ror_patterns:
        if p in data:
            flags.append("ror_loop_bytes")

    # Look for xor/add/ror combinational loop bytes near each other
    if re.search(b"(?:\x33.|[\x80-\x83].{1}|\x05....).{0,24}(?:\xC1[\xC8-\xCF].)", data, re.DOTALL):
        flags.append("xor_add_ror_mix")

    # Scan .data/.rdata for sequences of many 4-byte non-zero constants (possible hash tables)
    table_hits = []
    if is_pe:
        try:
            pe = pefile.PE(data=data, fast_load=True)
            for s in pe.sections:
                name = _sec_name(s).lower()
                if not (name.startswith(".data") or name.startswith(".rdata")):
                    continue
                sec = s.get_data()
                # look for >= 8 consecutive dwords of non-zero values
                i = 0
                consec = 0
                start_off = None
                while i + 4 <= len(sec):
                    d = int.from_bytes(sec[i:i+4], "little")
                    if d not in (0, 0xFFFFFFFF):
                        consec += 1
                        if consec == 1:
                            start_off = i
                        if consec >= 8:
                            table_hits.append({"section": name, "rva": hex(s.VirtualAddress + start_off)})
                            break
                    else:
                        consec = 0
                        start_off = None
                    i += 4
        except Exception:
            pass

    score = min(10, (3 if "xor_add_ror_mix" in flags else 0) + (2 if "ror_loop_bytes" in flags else 0) + (3 if table_hits else 0))
    return {
        "flags": list(sorted(set(flags))),
        "hash_table_candidates": table_hits[:20],
        "score": score,
        "verdict": "🟠 Possible API hashing" if score >= 5 else "🟢 Low"
    }

@mcp.tool()
def detect_syscall_stubs(file: str) -> dict:
    """Detect common x64 syscall stubs and markers (mov r10, rcx; syscall; ret)."""
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}
    with open(file, "rb") as f:
        data = f.read()

    is_pe = data.startswith(b"MZ")
    hits_global = []
    # Classic x64 stub: 4C 8B D1  B8 ?? ?? ?? ??  0F 05  C3
    stub_re = re.compile(b"\x4C\x8B\xD1.{5}\x0F\x05\xC3", re.DOTALL)
    for m in stub_re.finditer(data):
        hits_global.append({"offset": hex(m.start()), "pattern": "mov r10,rcx; syscall; ret"})

    # Count raw syscall opcodes
    syscall_count = data.count(b"\x0F\x05")

    section_hits = []
    if is_pe:
        try:
            pe = pefile.PE(data=data, fast_load=True)
            for s in pe.sections:
                sec = s.get_data()
                count = sec.count(b"\x0F\x05")
                if count >= 1:
                    section_hits.append({
                        "section": _sec_name(s),
                        "syscall_count": count
                    })
        except Exception:
            pass

    score = min(10, (len(hits_global) * 3) + (2 if syscall_count >= 2 else 0) + (3 if section_hits else 0))
    return {
        "global_stub_hits": hits_global[:50],
        "syscall_opcode_count": syscall_count,
        "section_syscall_hits": section_hits,
        "score": score,
        "verdict": "🔴 Likely manual syscalls" if score >= 8 else ("🟠 Suspicious" if score >= 5 else "🟢 Low")
    }

@mcp.tool()
def tls_callbacks(file: str) -> dict:
    """Enumerate TLS callbacks (often used for stealthy loader execution)."""
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}
    try:
        pe = pefile.PE(file, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']])
    except Exception as e:
        return {"error": f"PE parse failed: {e}"}

    if not hasattr(pe, "DIRECTORY_ENTRY_TLS") or not pe.DIRECTORY_ENTRY_TLS:
        return {"count": 0, "callbacks": []}

    cbs = []
    for tls in pe.DIRECTORY_ENTRY_TLS:
        try:
            addrs = tls.struct.AddressOfCallBacks
            if not addrs:
                continue
            # Read callback array until NULL
            ptr_size = 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
            offset = pe.get_offset_from_rva(addrs - pe.OPTIONAL_HEADER.ImageBase)
            while True:
                raw = pe.__data__[offset:offset+ptr_size]
                if len(raw) < ptr_size:
                    break
                val = int.from_bytes(raw, "little")
                if val == 0:
                    break
                cbs.append(hex(val))
                offset += ptr_size
        except Exception:
            pass

    return {"count": len(cbs), "callbacks": cbs[:32]}
    
@mcp.tool()
def inspect_resources(file: str, max_items: int = 20) -> dict:
    """Parse .rsrc and flag high-entropy or suspicious-looking resource blobs."""
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}
    try:
        pe = pefile.PE(file, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    except Exception as e:
        return {"error": f"PE parse failed: {e}"}

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return {"items": []}

    suspicious = []
    markers = [
        (b"MZ", "pe_header"),
        (b"PK\x03\x04", "zip"),
        (b"%PDF", "pdf"),
        (b"<script", "html_js"),
        (b"powershell", "powershell"),
        (b"cmd.exe", "cmd"),
        (b"encrypted", "keyword_encrypted")
    ]

    for entry in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", []):
        for res_type in entry.directory.entries:
            for res_id in getattr(res_type.directory, "entries", []):
                for lang in getattr(res_id.directory, "entries", []):
                    data_rva = lang.data.struct.OffsetToData
                    size = lang.data.struct.Size
                    try:
                        raw = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                    except Exception:
                        continue
                    ent = shannon_entropy(raw)
                    flags = []
                    for sig, name in markers:
                        if sig.lower() in raw.lower():
                            flags.append(name)
                    if ent >= 7.4 or flags or raw.startswith(b"MZ"):
                        suspicious.append({
                            "type": getattr(res_type, "id", None),
                            "id": getattr(res_id, "id", None),
                            "lang": getattr(lang, "id", None),
                            "size": size,
                            "entropy": round(ent, 4),
                            "flags": flags[:5]
                        })

    # sort by entropy desc and size
    suspicious.sort(key=lambda x: (x["entropy"], x["size"]), reverse=True)
    return {"items": suspicious[:max_items]}
    
@mcp.tool()
def detect_shellcode(file: str) -> dict:
    """Heuristic shellcode detection for raw blobs or embedded PE sections.
    
    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}

    with open(file, "rb") as f:
        data = f.read()

    result = {"path": os.path.basename(file), "size": len(data)}
    flags = []

    # Heuristic A: PE header presence
    is_pe = data.startswith(b"MZ")
    result["has_pe_header"] = bool(is_pe)

    # Heuristic B: entropy of whole file (raw blobs)
    ent = shannon_entropy(data[: min(len(data), 2_000_000)])  # cap to 2MB for speed
    result["entropy"] = ent
    if not is_pe and ent >= 7.4:
        flags.append("raw_high_entropy")

    # Heuristic C: syscall stub bytes (x64 common sequence: mov r10, rcx; syscall)
    # 4C 8B D1  B8 xx xx xx xx  0F 05  C3
    if re.search(b"\x4C\x8B\xD1.{5}\x0F\x05\xC3", data, re.DOTALL):
        flags.append("syscall_stub_pattern")

    # Heuristic D: 0x0F 0x05 occurrences
    if data.count(b"\x0F\x05") >= 2:
        flags.append("multiple_syscall_markers")

    # Heuristic E: CALL-POP/JMP-CALL (typical shellcode)
    if re.search(b"\xE8....\x5B", data, re.DOTALL) or re.search(b"\xEB.\xE8...", data, re.DOTALL):
        flags.append("call_pop_or_jmp_call")

    # Heuristic F: long NOP sleds
    if b"\x90"*64 in data:
        flags.append("nop_sled_64+")

    # If PE, inspect sections for embedded shellcode traits
    embedded = []
    if is_pe:
        try:
            pe = pefile.PE(data=data, fast_load=True)
            for s in pe.sections:
                name = _sec_name(s)
                sec = s.get_data()
                e = shannon_entropy(sec)
                rwx = bool(s.Characteristics & IMAGE_SCN_MEM_WRITE) and bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                rx_in_data = (name.startswith(".data") and bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                hit = {
                    "section": name,
                    "entropy": e,
                    "rwx": rwx,
                    "rx_in_data": rx_in_data
                }
                if e >= 7.4 and (name in (".text", ".data") or rwx or rx_in_data):
                    hit["flag"] = "suspicious_embedded_payload"
                    embedded.append(hit)
        except Exception:
            pass

    # Score (0–10)
    score = 0
    weight = {
        "raw_high_entropy": 3,
        "syscall_stub_pattern": 3,
        "multiple_syscall_markers": 2,
        "call_pop_or_jmp_call": 1,
        "nop_sled_64+": 1,
    }
    for f in flags:
        score += weight.get(f, 1)
    if embedded:
        score += 3
    score = min(score, 10)

    result.update({
        "flags": flags,
        "embedded_suspicious_sections": embedded,
        "score": score,
        "verdict": "🔴 Likely shellcode/packed" if score >= 8 else ("🟠 Suspicious" if score >= 5 else "🟢 Low")
    })
    return result

@mcp.tool()
def section_rwx_analysis(file: str) -> dict:
    """Check for RWX/overlap and suspicious executable placement.
    
    Args:
        file: The file name or path provided. (i.e., local / absolute path)
    """
    if not os.path.exists(file):
        return {"error": f"File not found: {file}"}
    try:
        pe = pefile.PE(file, fast_load=True)
        pe.parse_data_directories()
    except Exception as e:
        return {"error": f"PE parse failed: {e}"}

    secs = []
    problems = {
        "rwx_sections": [],
        "rx_in_data": [],
        "writable_text": [],
        "overlaps": [],
        "high_entropy_text": []
    }

    # collect VA ranges and attributes
    ranges = []
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        name = _sec_name(s)
        va   = s.VirtualAddress
        vsz  = max(s.Misc_VirtualSize, s.SizeOfRawData) or s.SizeOfRawData
        start = image_base + va
        end   = start + vsz
        ch    = s.Characteristics
        ent   = shannon_entropy(s.get_data())

        info = {
            "name": name,
            "va_start": hex(start),
            "va_end": hex(end),
            "raw_size": s.SizeOfRawData,
            "virt_size": s.Misc_VirtualSize,
            "entropy": ent,
            "R": bool(ch & IMAGE_SCN_MEM_READ),
            "W": bool(ch & IMAGE_SCN_MEM_WRITE),
            "X": bool(ch & IMAGE_SCN_MEM_EXECUTE),
        }
        secs.append(info)
        ranges.append((name, start, end))

        if info["W"] and info["X"]:
            problems["rwx_sections"].append(name)
        if name.startswith(".data") and info["X"]:
            problems["rx_in_data"].append(name)
        if name == ".text" and info["W"]:
            problems["writable_text"].append(name)
        if name == ".text" and ent >= 7.6:
            problems["high_entropy_text"].append({"name": name, "entropy": ent})

    # overlaps
    for i in range(len(ranges)):
        for j in range(i+1, len(ranges)):
            n1,a0,a1 = ranges[i]
            n2,b0,b1 = ranges[j]
            if _overlaps(a0,a1,b0,b1):
                problems["overlaps"].append(f"{n1} <-> {n2}")

    # overall risk
    score = 0
    if problems["rwx_sections"]: score += 4
    if problems["rx_in_data"]:   score += 3
    if problems["writable_text"]:score += 2
    if problems["overlaps"]:     score += 2
    if problems["high_entropy_text"]: score += 2
    score = min(score, 10)

    return {
        "sections": secs,
        "problems": problems,
        "score": score,
        "verdict": "🔴 Risky layout" if score >= 8 else ("🟠 Suspicious" if score >= 5 else "🟢 OK")
    }
    
@mcp.tool()
def extract_and_flag_apis(file: str) -> dict:
    """Extract strings and flag suspicious API calls.

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
