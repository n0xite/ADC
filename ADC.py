import pefile
import argparse
import pyfiglet


ANTI_DEBUG_APIS = [
    # Debugger detection
    'IsDebuggerPresent',
    'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess',
    'NtSetInformationThread',
    'NtGetContextThread',
    'NtSetContextThread',
    'GetThreadContext',
    'SetThreadContext',

    # Exception manipulation
    'SetUnhandledExceptionFilter',
    'RaiseException',
    'NtContinue',

    # Handle manipulation & stealth tricks
    'CloseHandle',
    'NtClose',

    # Timing checks / Anti-tracing
    'QueryPerformanceCounter',
    'GetTickCount',
    'GetTickCount64',
    'NtYieldExecution',
    'RDTSC',  # RDTSC is an instruction, not an import, but can sometimes be wrapped

    # Debug object checks
    'NtQueryObject',

    # Debug output
    'OutputDebugStringA',
    'OutputDebugStringW',
    
    # Termination for self-exit
    'NtTerminateProcess',
    'ExitProcess',

    # Process manipulation
    'NtQuerySystemInformation',

    # Self-debugging tricks
    'DebugActiveProcess',
    'NtCreateThreadEx',
    'NtOpenProcess',
    'CreateProcessA',
    'CreateProcessW',
]

def analyze_pe(file_path):
    pe = pefile.PE(file_path)

    suspicious_imports = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    dll_name = entry.dll.decode('utf-8', errors='ignore')

                    if func_name in ANTI_DEBUG_APIS:
                        suspicious_imports.append((dll_name, func_name, hex(imp.address)))

    return suspicious_imports


def main():
    print("\n")
    print("\n")
    print("\n")
    print(pyfiglet.figlet_format("Anti-Debug Check",  font = "doom", width = 100))
    print("\n")
    print("\n")
    print("\n")
    parser = argparse.ArgumentParser(description="Detect Anti-Debugging APIs in PE Files")
    parser.add_argument("file", help="Path to the PE file (e.g., EXE/DLL)")
    args = parser.parse_args()

    suspicious_imports = analyze_pe(args.file)

    if suspicious_imports:
        print("\nSuspicious Anti-Debugging APIs Found:\n")
        print(f"{'DLL':<20}{'Function':<35}{'Address'}")
        print("-" * 65)
        for dll, func, addr in suspicious_imports:
            print(f"{dll:<20}{func:<35}{addr}")
    else:
        print("No suspicious anti-debugging APIs detected.")

if __name__ == "__main__":
    main()
