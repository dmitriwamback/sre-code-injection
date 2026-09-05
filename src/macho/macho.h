//
// Created by Dmitri on 2026-09-05.
//

#ifndef SRE_CODE_INJECTION_MACHO_H
#define SRE_CODE_INJECTION_MACHO_H

#include <cstdint>
#include <string>
#include <vector>

// Represents the architecture of a Mach-O file
enum class Architecture {
    ARM64, X86_64, Unknown
};

// Represents a section in a Mach-O file
struct CodeSection {
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
};

// Represents a Mach-O file
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
