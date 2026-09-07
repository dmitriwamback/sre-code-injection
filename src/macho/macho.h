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

struct MachOSegment {
    std::string name;

    uint64_t vmAddress;
    uint64_t vmSize;
    uint64_t fileOffset;
    uint64_t fileSize;
    uint64_t maxProtection;
    uint64_t initialProtection;
};

// Represents a Mach-O file
class MachO {
public:
    MachO(const std::string& path);
    void Inspect();
    void AppendData(const std::vector<uint8_t>& data);
    void Save(const std::string& path);

    [[nodiscard]] CodeSection FindCodeSection() const;
    [[nodiscard]] Architecture GetArchitecture() const;
    [[nodiscard]] std::vector<MachOSegment> GetSegments() const;
    [[nodiscard]] size_t GetSize() const;

    void AddPayloadSection(const std::vector<uint8_t>& payload, const std::string& symbolName);
    void AddDefinedSymbol(const std::string& symbolName, uint64_t address, uint8_t sectionIndex);

private:
    std::string filepath;
    std::vector<uint8_t> data;
};


#endif //SRE_CODE_INJECTION_MACHO_H
