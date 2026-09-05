//
// Created by Dmitri on 2026-09-05.
//

#ifndef SRE_CODE_INJECTION_MACHO_H
#define SRE_CODE_INJECTION_MACHO_H

#include <cstdint>
#include <string>
#include <vector>

enum class Architecture {
    ARM64, X86_64, Unknown
};

struct CodeSection {
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
};

class MachO {
public:
    MachO(const std::string& path);
    void Inspect();
    CodeSection FindCodeSection() const;
    Architecture GetArchitecture() const;

private:
    std::string filepath;
    std::vector<uint8_t> data;
};


#endif //SRE_CODE_INJECTION_MACHO_H
