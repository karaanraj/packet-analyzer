#pragma once
#include <string>
#include <cstdint>

// We use a simple wrapper instead of std::optional
// to avoid version issues
struct OptionalString {
    std::string value;
    bool found = false;
};

class SNIExtractor {
public:
    static OptionalString extract(
        const uint8_t* payload,
        size_t length
    );
};