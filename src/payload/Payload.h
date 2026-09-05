//
// Created by Dmitri on 2026-09-05.
//

#ifndef SRE_CODE_INJECTION_PAYLOAD_H
#define SRE_CODE_INJECTION_PAYLOAD_H
#include <cstdint>
#include <vector>

// Represents the architecture of the payload
enum class PayloadArchitecture {
    ARM64, X86_64, Unknown
};

// Represents a section in the payload
// Sections meaning the code and data segments of the payload
struct PayloadSection {
    std::string name;
    uint64_t address;
    uint64_t size;
    uint64_t offset;
    uint64_t alignment;
    uint32_t relocationOffset;
    uint32_t relocationCount;
};

// Represents a symbol in the payload
// Symbols are functions or variables that can be referenced by other code
struct PayloadSymbol {
    std::string name;

    uint64_t value;
    uint64_t size;

    uint8_t type;
    uint8_t section;
    uint16_t desc;

    bool defined;
    bool external;
};

struct PayloadRelocation {
    uint64_t offset;
    std::string symbol;
    bool external;
    bool pcRelative;
    uint8_t length;
    uint8_t type;
};

class Payload {
public:
    Payload(const std::string& path);

    [[nodiscard]] PayloadArchitecture Architecture() const;
    [[nodiscard]] const std::string& Path() const;
    [[nodiscard]] const std::vector<uint8_t>& Code() const;
    [[nodiscard]] const PayloadSection& CodeSection() const;
    [[nodiscard]] const PayloadSymbol& EntryPoint() const;
    [[nodiscard]] const std::vector<PayloadSymbol>& Symbols() const;
    [[nodiscard]] const std::vector<PayloadRelocation>& Relocations() const;

private:
    void Load();
    void ParseHeader();
    void ParseSections();
    void ParseSymbols();
    void ParseRelocations();
    void LocateCodeSections();
    void LocateEntryPoint();

    std::vector<uint8_t> code, data;
    std::string filepath;
    PayloadArchitecture architecture;
    PayloadSection codeSection;
    PayloadSymbol entryPoint;
    std::vector<PayloadSymbol> symbols;
    std::vector<PayloadRelocation> relocations;
    std::vector<PayloadSection> sections;
};


#endif //SRE_CODE_INJECTION_PAYLOAD_H
