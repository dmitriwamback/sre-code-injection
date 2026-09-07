//
// Created by Dmitri on 2026-09-05.
//

#include "Payload.h"

#include <fstream>
#include <iostream>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/reloc.h>

// Helper function to check if a pointer is within the bounds of the data vector
namespace {
    template <typename T>
    const T* CheckedPointer(const std::vector<uint8_t>& data, size_t offset) {

        if (offset > data.size() || sizeof(T) > data.size() - offset) {
            throw std::runtime_error("Payload contains out-of-bounds structure");
        }
        return reinterpret_cast<const T*>(data.data() + offset);
    }
}

// Payload class implementation
Payload::Payload(const std::string& path) {

    // Initialize the Payload object with the given file path and load the payload data
    filepath = path;
    architecture = PayloadArchitecture::Unknown;

    // Load the payload data from the file
    Load();
    ParseHeader();
    ParseSections();
    ParseSymbols();
    ParseRelocations();
    LocateCodeSections();
    LocateEntryPoint();
}

void Payload::Load() {

    // Open the payload file in binary mode
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file");
    }

    // Determine the size of the file and read its contents into the data vector
    file.seekg(0, std::ios::end);
    const auto size = file.tellg();

    // Check if the file is empty and throw an error if it is
    if (size <= 0) {
        throw std::runtime_error("Payload is empty");
    }

    // Read the entire file into the data vector
    file.seekg(0, std::ios::beg);
    data.resize(size);
    file.read(reinterpret_cast<char*>(data.data()), size);

    // Check if the file was read successfully and throw an error if it wasn't
    if (!file) {
        throw std::runtime_error("Failed to read payload file");
    }
}

// Parse the Mach-O header of the payload to determine its architecture
void Payload::ParseHeader() {

    // Check if the payload is a valid Mach-O file and determine its architecture
    const auto* header = CheckedPointer<mach_header_64>(data, 0);

    // Check if the magic number in the header matches the expected value for a Mach-O file
    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("Payload not Mach-O");
    }

    // Determine the architecture of the payload based on the CPU type in the header
    switch (header->cputype) {
        case CPU_TYPE_ARM64:
            architecture = PayloadArchitecture::ARM64;
            break;
        case CPU_TYPE_X86_64:
            architecture = PayloadArchitecture::X86_64;
            break;
        default:
            architecture = PayloadArchitecture::Unknown;
            break;
    }
}

// Getters for the Payload class to access its properties
PayloadArchitecture Payload::Architecture() const {
    return architecture;
}

// Get the file path of the payload
const std::string& Payload::Path() const {
    return filepath;
}

// Get the code section of the payload as a vector of bytes
const std::vector<uint8_t>& Payload::Code() const {
    return code;
}

// Get the code section metadata of the payload
const PayloadSection &Payload::CodeSection() const {
    return codeSection;
}

// Get the entry point symbol of the payload
const PayloadSymbol &Payload::EntryPoint() const {
    return entryPoint;
}

// Get the symbols defined in the payload
const std::vector<PayloadSymbol>& Payload::Symbols() const {
    return symbols;
}

// Get the relocations defined in the payload
const std::vector<PayloadRelocation>& Payload::Relocations() const {
    return relocations;
}

// Parse the sections of the payload to extract information about each section
void Payload::ParseSections() {

    // Get a pointer to the Mach-O header and set up a cursor to iterate through the load commands
    const auto* header = CheckedPointer<mach_header_64>(data, 0);

    // Set up a cursor to iterate through the load commands in the Mach-O header
    const uint8_t* cursor = data.data() + sizeof(mach_header_64);
    const uint8_t* end = data.data() + data.size();

    // Iterate through the load commands to find and parse the sections of the payload
    for (uint32_t i = 0; i < header->ncmds; i++) {

        // Check if the cursor is within the bounds of the data vector and throw an error if it isn't
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Invalid payload load command");
        }

        // Get a pointer to the current load command and check its size to ensure it's valid
        const auto* command = reinterpret_cast<const load_command*>(cursor);
        if (command->cmdsize < sizeof(load_command) || cursor + command->cmdsize > end) {
            throw std::runtime_error("Invalid payload load command size");
        }

        // If the load command is a segment command, parse its sections and store their information in the sections vector
        if (command->cmd == LC_SEGMENT_64) {
            
            // Get pointers to the segment command and its first section, and iterate through all sections in the segment
            const auto* segment = reinterpret_cast<const segment_command_64*>(cursor);
            const auto* section = reinterpret_cast<const section_64*>(cursor + sizeof(segment_command_64));

            // Iterate through all sections in the segment and extract their information into PayloadSection objects
            for (uint32_t s = 0; s < segment->nsects; s++) {

                // Check if the section pointer is within the bounds of the data vector and throw an error if it isn't
                if (reinterpret_cast<const uint8_t*>(section) + sizeof(section_64) > end) {
                    throw std::runtime_error("Invalid payload section");
                }

                // Create a PayloadSection object and populate it with information from the section, then add it to the sections vector
                PayloadSection result;
                result.name             = section->sectname;
                result.address          = section->addr;
                result.size             = section->size;
                result.offset           = section->offset;
                result.alignment        = section->align;
                result.relocationCount  = section->nreloc;
                result.relocationOffset = section->reloff;

                // Add the parsed section to the sections vector
                sections.push_back(result);

                // If the section is the __text section, store its information in the codeSection member variable
                if (result.name == "__text") {
                    codeSection = result;
                }

                // Move the section pointer to the next section in the segment
                section++;
            }
        }

        // Move the cursor to the next load command in the Mach-O header
        cursor += command->cmdsize;
    }
}

void Payload::LocateCodeSections() {

    // Check if the code section was found during section parsing and throw an error if it wasn't
    if (codeSection.size == 0) {
        throw std::runtime_error("Payload does not contain a __text section");
    }

    // Check if the code section's offset and size are within the bounds of the data vector and throw an error if they aren't
    if (codeSection.offset > data.size() || codeSection.size > data.size() - codeSection.offset) {
        throw std::runtime_error("Payload __text exceeds file");
    }

    // Extract the code section from the data vector and store it in the code member variable
    const auto begin = data.begin() + static_cast<ptrdiff_t>(codeSection.offset);
    const auto end = begin + static_cast<ptrdiff_t>(codeSection.size);

    // Assign the extracted code section to the code member variable
    code.assign(begin, end);
}

void Payload::ParseSymbols() {

    // Get a pointer to the Mach-O header and set up a cursor to iterate through the load commands
    const auto* header = CheckedPointer<mach_header_64>(data, 0);

    // Set up a cursor to iterate through the load commands in the Mach-O header and initialize a pointer for the symtab command
    const uint8_t* cursor = data.data() + sizeof(mach_header_64);
    const uint8_t* end = data.data() + data.size();

    // Initialize a pointer to the symtab_command structure, which will be used to locate the symbol table in the payload
    const symtab_command* symtab = nullptr;

    // Iterate through the load commands to find the LC_SYMTAB command, which contains information about the symbol table
    for (uint32_t i = 0; i < header->ncmds; i++) {

        // Check if the cursor is within the bounds of the data vector and throw an error if it isn't
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Invalid payload load command");
        }

        // Get a pointer to the current load command and check its size to ensure it's valid
        const auto* command = reinterpret_cast<const load_command*>(cursor);

        // Check if the command size is valid and throw an error if it isn't
        if (command->cmdsize < sizeof(load_command) || cursor + command->cmdsize > end) {
            throw std::runtime_error("Invalid payload load command size");
        }

        // If the load command is LC_SYMTAB, store a pointer to the symtab_command structure and break out of the loop
        if (command->cmd == LC_SYMTAB) {
            if (command->cmdsize < sizeof(symtab_command)) {
                throw std::runtime_error("Invalid LC_SYMTAB");
            }

            symtab = reinterpret_cast<const symtab_command*>(cursor);
            break;
        }

        // Move the cursor to the next load command in the Mach-O header
        cursor += command->cmdsize;
    }

    // Check if the symtab command was found and throw an error if it wasn't
    if (!symtab) {
        throw std::runtime_error("Symtab not found");
    }

    // Calculate the offsets and sizes of the string table and symbol table, and check if they are within the bounds of the data vector
    const size_t stringTableOffset = symtab->stroff;
    const size_t stringTableSize = symtab->strsize;

    // Check if the string table offset and size are within the bounds of the data vector and throw an error if they aren't
    if (stringTableOffset > data.size() || stringTableSize > data.size() - stringTableOffset) {
        throw std::runtime_error("Payload string table exceeds file");
    }

    // Calculate the offset and size of the symbol table, and check if they are within the bounds of the data vector
    const size_t symbolTableOffset = symtab->symoff;
    const size_t symbolTableSize = static_cast<size_t>(symtab->nsyms) * sizeof(nlist_64);

    // Check if the symbol table offset and size are within the bounds of the data vector and throw an error if they aren't
    if (symbolTableOffset > data.size() || symbolTableSize > data.size() - symbolTableOffset) {
        throw std::runtime_error("Payload symbol table exceeds file");
    }

    // Get pointers to the symbol table and string table, and iterate through the symbols to extract their information into PayloadSymbol objects
    const auto* _symbols = reinterpret_cast<const nlist_64*>(data.data() + symbolTableOffset);
    const char* stringTable = reinterpret_cast<const char*>(data.data() + stringTableOffset);


    // Iterate through the symbols in the symbol table and extract their information into PayloadSymbol objects
    for (uint32_t i = 0; i < symtab->nsyms; i++) {

        // Check if the symbol's string index is within the bounds of the string table and throw an error if it isn't
        const nlist_64& symbol = _symbols[i];
        if (symbol.n_un.n_strx >= stringTableSize) {
            throw std::runtime_error("Symbol contains invalid string index");
        }

        // Get the name of the symbol from the string table using its string index
        const char* name = stringTable + symbol.n_un.n_strx;

        // Create a PayloadSymbol object and populate it with information from the symbol, then add it to the symbols vector
        PayloadSymbol result;
        result.name = name;
        result.value = symbol.n_value;
        result.type = symbol.n_type;
        result.section = symbol.n_sect;
        result.desc = symbol.n_desc;
        result.defined = (symbol.n_type & N_TYPE) == N_SECT;
        result.external = (symbol.n_type & N_EXT) != 0;
        symbols.push_back(result);
    }
}

// Locate the entry point of the payload by searching for a specific symbol in the symbols vector
void Payload::LocateEntryPoint() {

    // Define the name of the entry point symbol to search for in the symbols vector
    constexpr const char* entryName = "_testFunction";

    // Iterate through the symbols vector to find the entry point symbol and store its information in the entryPoint member variable
    for (const auto& symbol : symbols) {

        // Check if the current symbol's name matches the entry point symbol name and continue to the next symbol if it doesn't
        if (symbol.name != entryName) {
            continue;
        }

        // Check if the entry point symbol is defined and throw an error if it isn't
        if (!symbol.defined) {
            throw std::runtime_error("Payload entry point is undefined");
        }

        // Store the entry point symbol information in the entryPoint member variable and return from the function
        entryPoint = symbol;
        return;
    }

    throw std::runtime_error("Could not find payload entry point");
}

// Parse the relocations of the payload to extract information about each relocation entry
void Payload::ParseRelocations() {

    // Get a pointer to the Mach-O header and set up a cursor to iterate through the load commands
    const auto* header = CheckedPointer<mach_header_64>(data, 0);
    const uint8_t* cursor = data.data() + sizeof(mach_header_64);
    const uint8_t* end = data.data() + data.size();
    const symtab_command* symtab = nullptr;

    // Iterate through the load commands to find the LC_SYMTAB command, which contains information about the symbol table
    for (uint32_t i = 0; i < header->ncmds; i++) {

        // Check if the cursor is within the bounds of the data vector and throw an error if it isn't
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Invalid payload load command");
        }

        // Get a pointer to the current load command and check its size to ensure it's valid
        const auto* command = reinterpret_cast<const load_command*>(cursor);
        if (command->cmdsize < sizeof(load_command) || cursor + command->cmdsize > end) {
            throw std::runtime_error("Payload load command exceeds file");
        }

        // If the load command is LC_SYMTAB, store a pointer to the symtab_command structure and break out of the loop
        if (command->cmd == LC_SYMTAB) {
            if (command->cmdsize < sizeof(symtab_command)) {
                throw std::runtime_error("Invalid LC_SYMTAB");
            }
            symtab = reinterpret_cast<const symtab_command*>(cursor);
            break;
        }

        // Move the cursor to the next load command in the Mach-O header
        cursor += command->cmdsize;
    }

    // Check if the symtab command was found and throw an error if it wasn't
    if (!symtab) {
        throw std::runtime_error("Symtab not found");
    }

    // Calculate the offset and size of the symbol table, and check if they are within the bounds of the data vector
    const size_t symbolTableOffset = symtab->symoff;
    const size_t symbolTableSize = static_cast<size_t>(symtab->nsyms) * sizeof(nlist_64);

    // Check if the symbol table offset and size are within the bounds of the data vector and throw an error if they aren't
    if (symbolTableOffset > data.size() || symbolTableSize > data.size() - symbolTableOffset) {
        throw std::runtime_error("Payload symbol table exceeds file");
    }

    // Get a pointer to the symbol table and calculate the offset and size of the string table, checking if they are within the bounds of the data vector
    const auto* rawSymbols = reinterpret_cast<const nlist_64*>(data.data() + symbolTableOffset);
    const size_t stringTableOffset = symtab->stroff;
    const size_t stringTableSize = symtab->strsize;

    // Check if the string table offset and size are within the bounds of the data vector and throw an error if they aren't
    if (stringTableOffset > data.size() || stringTableSize > data.size() - stringTableOffset) {
        throw std::runtime_error("Payload string table exceeds file");
    }

    // Get a pointer to the string table, which contains the names of the symbols referenced by the relocations
    const char* stringTable = reinterpret_cast<const char*>(data.data() + stringTableOffset);


    // Iterate through the sections of the payload to find and parse the relocations for each section
    for (const auto& section : sections) {
        if (section.relocationCount == 0) continue;

        // Calculate the offset and size of the relocation table for the current section, and check if they are within the bounds of the data vector
        const size_t relocationOffset = section.relocationOffset;
        const size_t relocationSize = static_cast<size_t>(section.relocationCount) * sizeof(relocation_info);

        // Check if the relocation table offset and size are within the bounds of the data vector and throw an error if they aren't
        if (relocationOffset > data.size() || relocationSize > data.size() - relocationOffset) {
            throw std::runtime_error("Payload relocation table exceeds file");
        }

        // Get a pointer to the relocation table for the current section and iterate through its entries to extract their information into PayloadRelocation objects
        const auto* rawRelocations = reinterpret_cast<const relocation_info*>(data.data() + relocationOffset);

        // Iterate through the relocation entries for the current section and extract their information into PayloadRelocation objects
        for (uint32_t i = 0; i < section.relocationCount; i++) {
            const relocation_info& raw = rawRelocations[i];
            PayloadRelocation relocation;
            relocation.offset = static_cast<uint64_t>(raw.r_address);
            relocation.external = raw.r_extern != 0;
            relocation.type = static_cast<uint8_t>(raw.r_type);
            relocation.pcRelative = raw.r_pcrel != 0;
            relocation.length = static_cast<uint8_t>(raw.r_length);

            // If the relocation is external, look up the symbol name in the symbol table and store it in the PayloadRelocation object
            if (raw.r_extern) {
                const uint32_t symbolIndex = raw.r_symbolnum;

                // Check if the symbol index is within the bounds of the symbol table and throw an error if it isn't
                if (symbolIndex >= symtab->nsyms) {
                    throw std::runtime_error("Relocation contains invalid symbol table");
                }

                // Get the symbol from the symbol table and check if its string index is within the bounds of the string table, throwing an error if it isn't
                const nlist_64& symbol = rawSymbols[symbolIndex];
                if (symbol.n_un.n_strx >= stringTableSize) {
                    throw std::runtime_error("Symbol contains invalid string index");
                }
                relocation.symbol = stringTable + symbol.n_un.n_strx;
            }

            relocations.push_back(std::move(relocation));
        }
    }
}
