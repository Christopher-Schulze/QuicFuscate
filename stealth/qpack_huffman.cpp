#include "qpack.hpp"
#include <bitset>
#include <queue>
#include <algorithm>

namespace quicsand {

// Huffman-Kodierungstabelle gemäß RFC 7541 Appendix B
// https://datatracker.ietf.org/doc/html/rfc7541#appendix-B
struct HuffmanEntry {
    uint32_t code;      // Huffman-Code
    uint8_t bit_length; // Länge des Codes in Bits
};

static const HuffmanEntry huffman_table[257] = {
    {0x1ff8, 13},    // 0
    {0x7fffd8, 23},  // 1
    {0xfffffe2, 28}, // 2
    {0xfffffe3, 28}, // 3
    {0xfffffe4, 28}, // 4
    {0xfffffe5, 28}, // 5
    {0xfffffe6, 28}, // 6
    {0xfffffe7, 28}, // 7
    {0xfffffe8, 28}, // 8
    {0xffffea, 24},  // 9
    {0x3ffffffc, 30},// 10
    {0xfffffe9, 28}, // 11
    {0xfffffea, 28}, // 12
    {0x3ffffffd, 30},// 13
    {0xfffffeb, 28}, // 14
    {0xfffffec, 28}, // 15
    {0xfffffed, 28}, // 16
    {0xfffffee, 28}, // 17
    {0xfffffef, 28}, // 18
    {0xffffff0, 28}, // 19
    {0xffffff1, 28}, // 20
    {0xffffff2, 28}, // 21
    {0x3ffffffe, 30},// 22
    {0xffffff3, 28}, // 23
    {0xffffff4, 28}, // 24
    {0xffffff5, 28}, // 25
    {0xffffff6, 28}, // 26
    {0xffffff7, 28}, // 27
    {0xffffff8, 28}, // 28
    {0xffffff9, 28}, // 29
    {0xffffffa, 28}, // 30
    {0xffffffb, 28}, // 31
    {0x14, 6},       // 32 - ' '
    {0x3f8, 10},     // 33 - '!'
    {0x3f9, 10},     // 34 - '"'
    {0xffa, 12},     // 35 - '#'
    {0x1ff9, 13},    // 36 - '$'
    {0x15, 6},       // 37 - '%'
    {0xf8, 8},       // 38 - '&'
    {0x7fa, 11},     // 39 - '''
    {0x3fa, 10},     // 40 - '('
    {0x3fb, 10},     // 41 - ')'
    {0xf9, 8},       // 42 - '*'
    {0x7fb, 11},     // 43 - '+'
    {0xfa, 8},       // 44 - ','
    {0x16, 6},       // 45 - '-'
    {0x17, 6},       // 46 - '.'
    {0x18, 6},       // 47 - '/'
    {0x0, 5},        // 48 - '0'
    {0x1, 5},        // 49 - '1'
    {0x2, 5},        // 50 - '2'
    {0x19, 6},       // 51 - '3'
    {0x1a, 6},       // 52 - '4'
    {0x1b, 6},       // 53 - '5'
    {0x1c, 6},       // 54 - '6'
    {0x1d, 6},       // 55 - '7'
    {0x1e, 6},       // 56 - '8'
    {0x1f, 6},       // 57 - '9'
    {0x5c, 7},       // 58 - ':'
    {0xfb, 8},       // 59 - ';'
    {0x7ffc, 15},    // 60 - '<'
    {0x20, 6},       // 61 - '='
    {0xffb, 12},     // 62 - '>'
    {0x3fc, 10},     // 63 - '?'
    {0x1ffa, 13},    // 64 - '@'
    {0x21, 6},       // 65 - 'A'
    {0x5d, 7},       // 66 - 'B'
    {0x5e, 7},       // 67 - 'C'
    {0x5f, 7},       // 68 - 'D'
    {0x60, 7},       // 69 - 'E'
    {0x61, 7},       // 70 - 'F'
    {0x62, 7},       // 71 - 'G'
    {0x63, 7},       // 72 - 'H'
    {0x64, 7},       // 73 - 'I'
    {0x65, 7},       // 74 - 'J'
    {0x66, 7},       // 75 - 'K'
    {0x67, 7},       // 76 - 'L'
    {0x68, 7},       // 77 - 'M'
    {0x69, 7},       // 78 - 'N'
    {0x6a, 7},       // 79 - 'O'
    {0x6b, 7},       // 80 - 'P'
    {0x6c, 7},       // 81 - 'Q'
    {0x6d, 7},       // 82 - 'R'
    {0x6e, 7},       // 83 - 'S'
    {0x6f, 7},       // 84 - 'T'
    {0x70, 7},       // 85 - 'U'
    {0x71, 7},       // 86 - 'V'
    {0x72, 7},       // 87 - 'W'
    {0xfc, 8},       // 88 - 'X'
    {0x73, 7},       // 89 - 'Y'
    {0xfd, 8},       // 90 - 'Z'
    {0x1ffb, 13},    // 91 - '['
    {0x7fff0, 19},   // 92 - '\'
    {0x1ffc, 13},    // 93 - ']'
    {0x3ffc, 14},    // 94 - '^'
    {0x22, 6},       // 95 - '_'
    {0x7ffd, 15},    // 96 - '`'
    {0x3, 5},        // 97 - 'a'
    {0x23, 6},       // 98 - 'b'
    {0x4, 5},        // 99 - 'c'
    {0x24, 6},       // 100 - 'd'
    {0x5, 5},        // 101 - 'e'
    {0x25, 6},       // 102 - 'f'
    {0x26, 6},       // 103 - 'g'
    {0x27, 6},       // 104 - 'h'
    {0x6, 5},        // 105 - 'i'
    {0x74, 7},       // 106 - 'j'
    {0x75, 7},       // 107 - 'k'
    {0x28, 6},       // 108 - 'l'
    {0x29, 6},       // 109 - 'm'
    {0x2a, 6},       // 110 - 'n'
    {0x7, 5},        // 111 - 'o'
    {0x2b, 6},       // 112 - 'p'
    {0x76, 7},       // 113 - 'q'
    {0x2c, 6},       // 114 - 'r'
    {0x8, 5},        // 115 - 's'
    {0x9, 5},        // 116 - 't'
    {0x2d, 6},       // 117 - 'u'
    {0x77, 7},       // 118 - 'v'
    {0x78, 7},       // 119 - 'w'
    {0x79, 7},       // 120 - 'x'
    {0x7a, 7},       // 121 - 'y'
    {0x7b, 7},       // 122 - 'z'
    {0x7ffe, 15},    // 123 - '{'
    {0x7fc, 11},     // 124 - '|'
    {0x3ffd, 14},    // 125 - '}'
    {0x1ffd, 13},    // 126 - '~'
    {0xffffffc, 28}, // 127
    {0xfffe6, 20},   // 128
    {0x3fffd2, 22},  // 129
    {0xfffe7, 20},   // 130
    {0xfffe8, 20},   // 131
    {0x3fffd3, 22},  // 132
    {0x3fffd4, 22},  // 133
    {0x3fffd5, 22},  // 134
    {0x7fffd9, 23},  // 135
    {0x3fffd6, 22},  // 136
    {0x7fffda, 23},  // 137
    {0x7fffdb, 23},  // 138
    {0x7fffdc, 23},  // 139
    {0x7fffdd, 23},  // 140
    {0x7fffde, 23},  // 141
    {0xffffeb, 24},  // 142
    {0x7fffdf, 23},  // 143
    {0xffffec, 24},  // 144
    {0xffffed, 24},  // 145
    {0x3fffd7, 22},  // 146
    {0x7fffe0, 23},  // 147
    {0xffffee, 24},  // 148
    {0x7fffe1, 23},  // 149
    {0x7fffe2, 23},  // 150
    {0x7fffe3, 23},  // 151
    {0x7fffe4, 23},  // 152
    {0x1fffdc, 21},  // 153
    {0x3fffd8, 22},  // 154
    {0x7fffe5, 23},  // 155
    {0x3fffd9, 22},  // 156
    {0x7fffe6, 23},  // 157
    {0x7fffe7, 23},  // 158
    {0xffffef, 24},  // 159
    {0x3fffda, 22},  // 160
    {0x1fffdd, 21},  // 161
    {0xfffe9, 20},   // 162
    {0x3fffdb, 22},  // 163
    {0x3fffdc, 22},  // 164
    {0x7fffe8, 23},  // 165
    {0x7fffe9, 23},  // 166
    {0x1fffde, 21},  // 167
    {0x7fffea, 23},  // 168
    {0x3fffdd, 22},  // 169
    {0x3fffde, 22},  // 170
    {0xfffff0, 24},  // 171
    {0x1fffdf, 21},  // 172
    {0x3fffdf, 22},  // 173
    {0x7fffeb, 23},  // 174
    {0x7fffec, 23},  // 175
    {0x1fffe0, 21},  // 176
    {0x1fffe1, 21},  // 177
    {0x3fffe0, 22},  // 178
    {0x1fffe2, 21},  // 179
    {0x7fffed, 23},  // 180
    {0x3fffe1, 22},  // 181
    {0x7fffee, 23},  // 182
    {0x7fffef, 23},  // 183
    {0xfffea, 20},   // 184
    {0x3fffe2, 22},  // 185
    {0x3fffe3, 22},  // 186
    {0x3fffe4, 22},  // 187
    {0x7ffff0, 23},  // 188
    {0x3fffe5, 22},  // 189
    {0x3fffe6, 22},  // 190
    {0x7ffff1, 23},  // 191
    {0x3ffffe0, 26}, // 192
    {0x3ffffe1, 26}, // 193
    {0xfffeb, 20},   // 194
    {0x7fff1, 19},   // 195
    {0x3fffe7, 22},  // 196
    {0x7ffff2, 23},  // 197
    {0x3fffe8, 22},  // 198
    {0x1ffffec, 25}, // 199
    {0x3ffffe2, 26}, // 200
    {0x3ffffe3, 26}, // 201
    {0x3ffffe4, 26}, // 202
    {0x7ffffde, 27}, // 203
    {0x7ffffdf, 27}, // 204
    {0x3ffffe5, 26}, // 205
    {0xfffff1, 24},  // 206
    {0x1ffffed, 25}, // 207
    {0x7fff2, 19},   // 208
    {0x1fffe3, 21},  // 209
    {0x3ffffe6, 26}, // 210
    {0x7ffffe0, 27}, // 211
    {0x7ffffe1, 27}, // 212
    {0x3ffffe7, 26}, // 213
    {0x7ffffe2, 27}, // 214
    {0xfffff2, 24},  // 215
    {0x1fffe4, 21},  // 216
    {0x1fffe5, 21},  // 217
    {0x3ffffe8, 26}, // 218
    {0x3ffffe9, 26}, // 219
    {0xffffffd, 28}, // 220
    {0x7ffffe3, 27}, // 221
    {0x7ffffe4, 27}, // 222
    {0x7ffffe5, 27}, // 223
    {0xfffec, 20},   // 224
    {0xfffff3, 24},  // 225
    {0xfffed, 20},   // 226
    {0x1fffe6, 21},  // 227
    {0x3fffe9, 22},  // 228
    {0x1fffe7, 21},  // 229
    {0x1fffe8, 21},  // 230
    {0x7ffff3, 23},  // 231
    {0x3fffea, 22},  // 232
    {0x3fffeb, 22},  // 233
    {0x1ffffee, 25}, // 234
    {0x1ffffef, 25}, // 235
    {0xfffff4, 24},  // 236
    {0xfffff5, 24},  // 237
    {0x3ffffea, 26}, // 238
    {0x7ffff4, 23},  // 239
    {0x3ffffeb, 26}, // 240
    {0x7ffffe6, 27}, // 241
    {0x3ffffec, 26}, // 242
    {0x3ffffed, 26}, // 243
    {0x7ffffe7, 27}, // 244
    {0x7ffffe8, 27}, // 245
    {0x7ffffe9, 27}, // 246
    {0x7ffffea, 27}, // 247
    {0x7ffffeb, 27}, // 248
    {0xffffffe, 28}, // 249
    {0x7ffffec, 27}, // 250
    {0x7ffffed, 27}, // 251
    {0x7ffffee, 27}, // 252
    {0x7ffffef, 27}, // 253
    {0x7fffff0, 27}, // 254
    {0x3ffffee, 26}, // 255
    {0x3fffffff, 30}  // 256 - (EOS)
};

// Huffman-Dekodierungsbaum-Knoten
struct HuffmanNode {
    int symbol;
    std::shared_ptr<HuffmanNode> children[2];
    
    HuffmanNode() : symbol(-1) {
        children[0] = nullptr;
        children[1] = nullptr;
    }
};

// Baut den Huffman-Dekodierungsbaum auf (wird einmalig beim Programmstart aufgebaut)
static std::shared_ptr<HuffmanNode> build_huffman_tree() {
    auto root = std::make_shared<HuffmanNode>();
    
    for (int i = 0; i < 257; i++) {
        const HuffmanEntry& entry = huffman_table[i];
        
        auto current = root;
        for (int j = entry.bit_length - 1; j >= 0; j--) {
            int bit = (entry.code >> j) & 1;
            
            if (!current->children[bit]) {
                current->children[bit] = std::make_shared<HuffmanNode>();
            }
            
            current = current->children[bit];
        }
        
        current->symbol = i;
    }
    
    return root;
}

// Statischer Huffman-Dekodierungsbaum (wird einmalig erstellt)
static std::shared_ptr<HuffmanNode> huffman_tree = build_huffman_tree();

// Huffman-Kodierung
std::vector<uint8_t> QpackCodec::huffman_encode(const std::string& input) {
    std::vector<uint8_t> result;
    if (input.empty()) {
        return result;
    }
    
    // Bitstream für die Kodierung
    std::vector<bool> bits;
    
    // Für jedes Zeichen im Eingabestring
    for (unsigned char c : input) {
        const HuffmanEntry& entry = huffman_table[c];
        
        // Füge die Bits des Huffman-Codes hinzu
        for (int i = entry.bit_length - 1; i >= 0; i--) {
            bits.push_back((entry.code >> i) & 1);
        }
    }
    
    // Padding mit EOS (1-Bits) hinzufügen, um auf Byte-Grenze zu kommen
    while (bits.size() % 8 != 0) {
        bits.push_back(1);
    }
    
    // Bits in Bytes konvertieren
    for (size_t i = 0; i < bits.size(); i += 8) {
        uint8_t byte = 0;
        for (size_t j = 0; j < 8; j++) {
            if (i + j < bits.size() && bits[i + j]) {
                byte |= (1 << (7 - j));
            }
        }
        result.push_back(byte);
    }
    
    return result;
}

// Huffman-Dekodierung
std::string QpackCodec::huffman_decode(const std::vector<uint8_t>& input) {
    std::string result;
    if (input.empty()) {
        return result;
    }
    
    auto current = huffman_tree;
    
    // Für jedes Byte in der Eingabe
    for (size_t i = 0; i < input.size(); i++) {
        uint8_t byte = input[i];
        
        // Für jedes Bit im Byte
        for (int j = 7; j >= 0; j--) {
            int bit = (byte >> j) & 1;
            
            if (!current->children[bit]) {
                // Ungültiger Huffman-Code
                return "";
            }
            
            current = current->children[bit];
            
            if (current->symbol != -1) {
                if (current->symbol < 256) {  // Kein EOS
                    result.push_back(static_cast<char>(current->symbol));
                }
                
                current = huffman_tree;  // Zurück zur Wurzel für den nächsten Code
            }
        }
    }
    
    return result;
}

} // namespace quicsand
