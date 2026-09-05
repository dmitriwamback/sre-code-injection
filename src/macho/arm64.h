//
// Created by Dmitri on 2026-09-05.
//

#ifndef SRE_CODE_INJECTION_ARM64_H
#define SRE_CODE_INJECTION_ARM64_H
#include <cstdint>
#include <string>


namespace arm64 {
    struct Instruction {
        uint64_t address;
        uint32_t encoding;
        std::string mnemonic;
    };

    Instruction Decode(uint64_t address, uint32_t encoding);
};


#endif //SRE_CODE_INJECTION_ARM64_H
