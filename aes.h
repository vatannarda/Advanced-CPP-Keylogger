/*
 * AES-256 Encryption/Decryption Header
 * Windows CryptoAPI Implementation
 * 
 * Advanced Crypter Project
 */

#ifndef AES_H
#define AES_H

#include <windows.h>
#include <wincrypt.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")

// AES-256 Key Size (32 bytes)
#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16

// ==================== KEY BLOB STRUCTURE ====================
// CryptoAPI requires a specific structure for AES keys
typedef struct {
    BLOBHEADER hdr;
    DWORD keySize;
    BYTE keyData[AES_KEY_SIZE];
} AES_KEY_BLOB;

// ==================== RANDOM KEY GENERATION ====================
inline void GenerateRandomBytes(BYTE* buffer, DWORD size) {
    HCRYPTPROV hProv = 0;
    
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, size, buffer);
        CryptReleaseContext(hProv, 0);
    } else {
        // Fallback: Use system time + performance counter
        srand((unsigned)(GetTickCount() ^ GetCurrentProcessId()));
        LARGE_INTEGER pc;
        QueryPerformanceCounter(&pc);
        srand((unsigned)(pc.LowPart ^ pc.HighPart));
        
        for (DWORD i = 0; i < size; i++) {
            buffer[i] = (BYTE)(rand() % 256);
        }
    }
}

inline void GenerateRandomKey(BYTE* key) {
    GenerateRandomBytes(key, AES_KEY_SIZE);
}

inline void GenerateRandomIV(BYTE* iv) {
    GenerateRandomBytes(iv, AES_IV_SIZE);
}

// ==================== AES ENCRYPTION ====================
inline bool AES_Encrypt(const BYTE* plaintext, DWORD plaintextLen, 
                        const BYTE* key, const BYTE* iv,
                        std::vector<BYTE>& ciphertext) {
    
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    bool result = false;
    
    // Acquire crypto context
    if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }
    
    // Create key blob
    AES_KEY_BLOB keyBlob;
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.keySize = AES_KEY_SIZE;
    memcpy(keyBlob.keyData, key, AES_KEY_SIZE);
    
    // Import key
    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }
    
    // Set CBC mode and IV
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0);
    
    // Calculate padded size (PKCS7 padding)
    DWORD paddedLen = plaintextLen;
    DWORD blockPadding = AES_BLOCK_SIZE - (plaintextLen % AES_BLOCK_SIZE);
    paddedLen += blockPadding;
    
    // Allocate buffer
    ciphertext.resize(paddedLen);
    memcpy(ciphertext.data(), plaintext, plaintextLen);
    
    // Apply PKCS7 padding
    for (DWORD i = 0; i < blockPadding; i++) {
        ciphertext[plaintextLen + i] = (BYTE)blockPadding;
    }
    
    // Encrypt
    DWORD encryptLen = paddedLen;
    if (CryptEncrypt(hKey, 0, TRUE, 0, ciphertext.data(), &encryptLen, paddedLen)) {
        ciphertext.resize(encryptLen);
        result = true;
    }
    
    // Cleanup
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    
    // Secure cleanup of key blob
    SecureZeroMemory(&keyBlob, sizeof(keyBlob));
    
    return result;
}

// ==================== AES DECRYPTION ====================
inline bool AES_Decrypt(const BYTE* ciphertext, DWORD ciphertextLen,
                        const BYTE* key, const BYTE* iv,
                        std::vector<BYTE>& plaintext) {
    
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    bool result = false;
    
    // Acquire crypto context
    if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }
    
    // Create key blob
    AES_KEY_BLOB keyBlob;
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.keySize = AES_KEY_SIZE;
    memcpy(keyBlob.keyData, key, AES_KEY_SIZE);
    
    // Import key
    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }
    
    // Set CBC mode and IV
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0);
    
    // Allocate buffer
    plaintext.resize(ciphertextLen);
    memcpy(plaintext.data(), ciphertext, ciphertextLen);
    
    // Decrypt
    DWORD decryptLen = ciphertextLen;
    if (CryptDecrypt(hKey, 0, TRUE, 0, plaintext.data(), &decryptLen)) {
        // Remove PKCS7 padding
        if (decryptLen > 0) {
            BYTE paddingLen = plaintext[decryptLen - 1];
            if (paddingLen <= AES_BLOCK_SIZE && paddingLen <= decryptLen) {
                decryptLen -= paddingLen;
            }
        }
        plaintext.resize(decryptLen);
        result = true;
    }
    
    // Cleanup
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    SecureZeroMemory(&keyBlob, sizeof(keyBlob));
    
    return result;
}

// ==================== RC4 FALLBACK ====================
inline void RC4_Crypt(BYTE* data, DWORD dataLen, const BYTE* key, DWORD keyLen) {
    BYTE S[256];
    BYTE T[256];
    
    // KSA (Key Scheduling Algorithm)
    for (int i = 0; i < 256; i++) {
        S[i] = (BYTE)i;
        T[i] = key[i % keyLen];
    }
    
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;
        BYTE temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    
    // PRGA (Pseudo-Random Generation Algorithm)
    int i = 0;
    j = 0;
    for (DWORD n = 0; n < dataLen; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        
        BYTE temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        
        int k = (S[i] + S[j]) % 256;
        data[n] ^= S[k];
    }
    
    // Secure cleanup
    SecureZeroMemory(S, sizeof(S));
    SecureZeroMemory(T, sizeof(T));
}

// ==================== XOR OBFUSCATION FOR KEY/IV ====================
inline void XOR_Obfuscate(BYTE* data, DWORD dataLen, const char* xorKey) {
    size_t keyLen = strlen(xorKey);
    for (DWORD i = 0; i < dataLen; i++) {
        data[i] ^= xorKey[i % keyLen];
    }
}

#endif // AES_H
