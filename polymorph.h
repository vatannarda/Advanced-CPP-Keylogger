/*
 * Polymorphic Engine Header
 * Generates random junk code and mutates stub
 * 
 * Advanced Crypter Project
 */

#ifndef POLYMORPH_H
#define POLYMORPH_H

#include <windows.h>
#include <vector>
#include <cstdlib>
#include <ctime>

// ==================== JUNK CODE TEMPLATES ====================
// These are harmless instructions that confuse disassemblers

// x86 NOP-equivalent instructions
const unsigned char JUNK_TEMPLATES[][8] = {
    { 0x90 },                                       // NOP
    { 0x87, 0xC0 },                                 // XCHG EAX, EAX
    { 0x87, 0xDB },                                 // XCHG EBX, EBX
    { 0x87, 0xC9 },                                 // XCHG ECX, ECX
    { 0x87, 0xD2 },                                 // XCHG EDX, EDX
    { 0x8D, 0x40, 0x00 },                           // LEA EAX, [EAX+0]
    { 0x8D, 0x49, 0x00 },                           // LEA ECX, [ECX+0]
    { 0x8D, 0x52, 0x00 },                           // LEA EDX, [EDX+0]
    { 0x8D, 0x5B, 0x00 },                           // LEA EBX, [EBX+0]
    { 0x50, 0x58 },                                 // PUSH EAX; POP EAX
    { 0x51, 0x59 },                                 // PUSH ECX; POP ECX
    { 0x52, 0x5A },                                 // PUSH EDX; POP EDX
    { 0x53, 0x5B },                                 // PUSH EBX; POP EBX
    { 0x83, 0xC0, 0x00 },                           // ADD EAX, 0
    { 0x83, 0xC1, 0x00 },                           // ADD ECX, 0
    { 0x83, 0xE8, 0x00 },                           // SUB EAX, 0
    { 0x31, 0xC0, 0x31, 0xC0 },                     // XOR EAX,EAX; XOR EAX,EAX
    { 0x0F, 0x1F, 0x00 },                           // NOP DWORD [EAX] (multi-byte NOP)
    { 0x0F, 0x1F, 0x40, 0x00 },                     // NOP DWORD [EAX+0]
    { 0x0F, 0x1F, 0x44, 0x00, 0x00 },               // NOP DWORD [EAX+EAX*1+0]
};

const int JUNK_SIZES[] = { 1, 2, 2, 2, 2, 3, 3, 3, 3, 2, 2, 2, 2, 3, 3, 3, 4, 3, 4, 5 };
const int JUNK_COUNT = sizeof(JUNK_SIZES) / sizeof(JUNK_SIZES[0]);

// ==================== POLYMORPHIC ENGINE CLASS ====================
class PolymorphicEngine {
private:
    std::vector<BYTE> m_junkCode;
    
    void InitRandom() {
        static bool initialized = false;
        if (!initialized) {
            LARGE_INTEGER pc;
            QueryPerformanceCounter(&pc);
            srand((unsigned)(time(NULL) ^ GetTickCount() ^ pc.LowPart ^ GetCurrentProcessId()));
            initialized = true;
        }
    }
    
public:
    PolymorphicEngine() {
        InitRandom();
    }
    
    // Generate random junk code block
    std::vector<BYTE> GenerateJunkCode(int minSize, int maxSize) {
        InitRandom();
        std::vector<BYTE> junk;
        
        int targetSize = minSize + (rand() % (maxSize - minSize + 1));
        
        while ((int)junk.size() < targetSize) {
            int idx = rand() % JUNK_COUNT;
            int size = JUNK_SIZES[idx];
            
            if ((int)junk.size() + size <= targetSize) {
                for (int i = 0; i < size; i++) {
                    junk.push_back(JUNK_TEMPLATES[idx][i]);
                }
            }
        }
        
        return junk;
    }
    
    // Generate random data block (for padding)
    std::vector<BYTE> GenerateRandomData(int size) {
        InitRandom();
        std::vector<BYTE> data(size);
        
        for (int i = 0; i < size; i++) {
            data[i] = (BYTE)(rand() % 256);
        }
        
        return data;
    }
    
    // Generate polymorphic marker (unique per build)
    std::vector<BYTE> GenerateMarker() {
        InitRandom();
        std::vector<BYTE> marker(16);
        
        // Start with timestamp-based seed
        DWORD tick = GetTickCount();
        LARGE_INTEGER pc;
        QueryPerformanceCounter(&pc);
        
        DWORD seed = tick ^ pc.LowPart ^ GetCurrentProcessId();
        
        for (int i = 0; i < 16; i++) {
            seed = seed * 1103515245 + 12345;
            marker[i] = (BYTE)((seed >> 16) & 0xFF);
        }
        
        return marker;
    }
    
    // Instruction substitution: XOR EAX,EAX -> SUB EAX,EAX (etc.)
    void SubstituteInstructions(std::vector<BYTE>& code) {
        for (size_t i = 0; i < code.size() - 1; i++) {
            // XOR reg,reg -> SUB reg,reg
            if (code[i] == 0x31 || code[i] == 0x33) {
                if (rand() % 2) {
                    code[i] = 0x29; // SUB
                }
            }
            // MOV reg,0 -> XOR reg,reg (if safe)
            else if (code[i] == 0xB8 && i + 4 < code.size()) {
                if (code[i+1] == 0 && code[i+2] == 0 && code[i+3] == 0 && code[i+4] == 0) {
                    if (rand() % 2) {
                        code[i] = 0x31;
                        code[i+1] = 0xC0; // XOR EAX,EAX
                        // Fill rest with NOPs
                        code[i+2] = 0x90;
                        code[i+3] = 0x90;
                        code[i+4] = 0x90;
                    }
                }
            }
        }
    }
    
    // Insert junk code at random positions in code vector
    std::vector<BYTE> InsertJunkAtPositions(const std::vector<BYTE>& original, 
                                             const std::vector<int>& positions,
                                             int junkSize) {
        std::vector<BYTE> result;
        int origIdx = 0;
        int posIdx = 0;
        
        while (origIdx < (int)original.size()) {
            if (posIdx < (int)positions.size() && origIdx == positions[posIdx]) {
                // Insert junk here
                auto junk = GenerateJunkCode(junkSize / 2, junkSize);
                result.insert(result.end(), junk.begin(), junk.end());
                posIdx++;
            }
            result.push_back(original[origIdx++]);
        }
        
        return result;
    }
    
    // Generate random variable name hash (for import obfuscation)
    DWORD GenerateHash(const char* str) {
        DWORD hash = 0;
        while (*str) {
            hash = ((hash << 5) + hash) + (*str++);
            hash ^= (rand() & 0xFF);
        }
        return hash;
    }
    
    // Create opaque predicate (always true/false but hard to analyze)
    std::vector<BYTE> GenerateOpaquePredicate(bool alwaysTrue) {
        InitRandom();
        std::vector<BYTE> code;
        
        // Example: (x*x) >= 0 is always true
        // MOV EAX, random
        // IMUL EAX, EAX
        // TEST EAX, EAX
        // JNS target (or JS for false)
        
        int randomVal = rand();
        
        code.push_back(0xB8); // MOV EAX, imm32
        code.push_back((BYTE)(randomVal & 0xFF));
        code.push_back((BYTE)((randomVal >> 8) & 0xFF));
        code.push_back((BYTE)((randomVal >> 16) & 0xFF));
        code.push_back((BYTE)((randomVal >> 24) & 0xFF));
        
        code.push_back(0x0F); // IMUL EAX, EAX
        code.push_back(0xAF);
        code.push_back(0xC0);
        
        code.push_back(0x85); // TEST EAX, EAX
        code.push_back(0xC0);
        
        if (alwaysTrue) {
            code.push_back(0x79); // JNS (always taken for x^2)
        } else {
            code.push_back(0x78); // JS (never taken for x^2)
        }
        code.push_back(0x02); // Jump offset
        
        // Dead code (never executed if alwaysTrue)
        code.push_back(0xEB); // JMP
        code.push_back(0x00); // +0 (will be patched)
        
        return code;
    }
};

// ==================== GLOBAL INSTANCE ====================
inline PolymorphicEngine& GetPolyEngine() {
    static PolymorphicEngine engine;
    return engine;
}

#endif // POLYMORPH_H
