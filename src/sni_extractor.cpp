#include "../include/sni_extractor.h"

static uint16_t read2Bytes(const uint8_t* p) {
    return (p[0] << 8) | p[1];
}

OptionalString SNIExtractor::extract(
    const uint8_t* data,
    size_t len
) {
    OptionalString result;

    if (len < 10) return result;
    if (data[0] != 0x16) return result;
    if (data[5] != 0x01) return result;

    size_t pos = 9;
    pos += 2;   // skip version
    pos += 32;  // skip random

    if (pos >= len) return result;
    uint8_t session_len = data[pos];
    pos += 1 + session_len;

    if (pos + 2 > len) return result;
    uint16_t cipher_len = read2Bytes(data + pos);
    pos += 2 + cipher_len;

    if (pos >= len) return result;
    uint8_t comp_len = data[pos];
    pos += 1 + comp_len;

    if (pos + 2 > len) return result;
    uint16_t extensions_len = read2Bytes(data + pos);
    pos += 2;

    size_t extensions_end = pos + extensions_len;

    while (pos + 4 <= extensions_end && pos + 4 <= len) {
        uint16_t ext_type = read2Bytes(data + pos);
        uint16_t ext_len  = read2Bytes(data + pos + 2);
        pos += 4;

        if (ext_type == 0x0000) {
            if (pos + 5 > len) return result;
            pos += 3;
            uint16_t name_len = read2Bytes(data + pos);
            pos += 2;
            if (pos + name_len > len) return result;

            result.value = std::string((char*)(data + pos), name_len);
            result.found = true;
            return result;
        }

        pos += ext_len;
    }

    return result;
}