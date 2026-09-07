//
// Created by Dmitri on 2026-09-05.
//

#include "macho.h"
#include <mach-o/loader.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <limits>
#include <mach-o/nlist.h>

// MachO class implementation
MachO::MachO(const std::string& path) {
    this->filepath = path;

    // Load the Mach-O file into memory
    std::ifstream file(this->filepath, std::ios::binary);

    // Check if the file was opened successfully and throw an error if it wasn't
    if (!file) {
        throw std::runtime_error("Could not open file");
    }

    // Determine the size of the file and read its contents into the data vector
    file.seekg(0, std::ios::end);
    const auto size = file.tellg();

    // Check if the file is empty and throw an error if it is
    if (size <= 0) {
        throw std::runtime_error("File is empty");
    }

    // Read the entire file into the data vector
    file.seekg(0, std::ios::beg);
    data.resize(size);

    // Check if the file was read successfully and throw an error if it wasn't
    file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

    // Check if the file was read successfully and throw an error if it wasn't
    if (!file) {
        throw std::runtime_error("Could not read file");
    }
}

void MachO::Inspect() {

    // Check if the file is large enough to contain a Mach-O header and throw an error if it isn't
    if (data.size() < sizeof(mach_header_64)) {
        throw std::runtime_error("File is too small");
    }

    // Get a pointer to the Mach-O header and check if it has the correct magic number, throwing an error if it doesn't
    const auto* header = reinterpret_cast<const mach_header_64*>(data.data());

    // Check if the magic number in the header matches the expected value for a Mach-O file and throw an error if it doesn't
    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("File is not a Mach-O file");
    }

    // Print information about the Mach-O file, including its file path, size, architecture, and load commands
    std::cout << "File: " << this->filepath << std::endl;
    std::cout << "Size: " << data.size() << " bytes" << std::endl;

    // Determine the architecture of the Mach-O file based on the cputype field in the header and print it to the console
    if (header->cputype == CPU_TYPE_ARM64) {
        std::cout << "ARM64" << std::endl;
    }
    else {
        std::cout << "Architecture 0x" << std::hex << header->cputype << std::dec << std::endl;
    }

    // Print information about the load commands in the Mach-O file, including their command type and size
    std::cout << "Load Commands: " << header->ncmds << std::endl;
    const uint8_t* cursor = data.data() + sizeof(mach_header_64);
    const uint8_t* end = data.data() + data.size();

    // Iterate through the load commands in the Mach-O file and print information about each one to the console
    for (uint32_t i = 0; i < header->ncmds; i++) {

        // Check if the cursor is within the bounds of the data vector and throw an error if it isn't
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        // Get a pointer to the current load command and check its size to ensure it's valid, throwing an error if it isn't
        const auto* command = reinterpret_cast<const load_command*>(cursor);

        // Check if the command size is valid and throw an error if it isn't
        if (command->cmdsize < sizeof(load_command)) {
            throw std::runtime_error("Invalid command size");
        }

        // Check if the command size is within the bounds of the data vector and throw an error if it isn't
        if (cursor + command->cmdsize > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        // Print information about the current load command to the console, including its command type and size
        std::cout << "\nLoad Command " << i << std::endl;
        std::cout << "  cmd:    0x" << std::hex << command->cmd << std::endl;
        std::cout << "  cmdsize: 0x" << command->cmdsize << std::dec << std::endl;

        if (command->cmd == LC_SEGMENT_64) {

            // If the load command is a segment command, print information about its sections to the console
            const auto* segment = reinterpret_cast<const segment_command_64*>(cursor);
            std::cout << "Segment: " << segment->segname << std::endl;
            std::cout << "  vmaddr:  0x" << std::hex << segment->vmaddr << std::endl;
            std::cout << "  vmsize:  0x" << segment->vmsize << std::endl;
            std::cout << "  fileoff:  0x" << segment->fileoff << std::endl;
            std::cout << "  filesize:  0x" << segment->filesize << std::endl;
            std::cout << "  sections:  " << segment->nsects << std::endl;
            
            const auto* section = reinterpret_cast<const section_64*>(cursor + sizeof(segment_command_64));

            // Iterate through the sections of the segment and print information about each one to the console
            for (uint32_t s = 0; s < segment->nsects; s++) {

                // Check if the section pointer is within the bounds of the data vector and throw an error if it isn't
                const auto* section_end = reinterpret_cast<const uint8_t*>(section) + sizeof(section_64);
                if (section_end > end) {
                    throw std::runtime_error("Section exceeds beyond file");
                }

                // Print information about the current section to the console, including its name, address, size, and file offset
                std::cout << "Section: " << section->sectname << std::endl;
                std::cout << "  addr:    0x" << std::hex << section->addr << std::endl;
                std::cout << "  size:    0x" << std::hex << section->size << std::endl;
                std::cout << "  fileoff:  0x" << std::hex << section->offset << std::dec << std::endl;

                section++;
            }
        }
        // Move the cursor to the next load command in the Mach-O file
        cursor += command->cmdsize;
    }
}

// Find the __TEXT, __text section in the Mach-O file and return its address, size, and file offset
CodeSection MachO::FindCodeSection() const {

    // Check if the file is large enough to contain a Mach-O header and throw an error if it isn't
    if (data.size() < sizeof(mach_header_64)) {
        throw std::runtime_error("File is too small");
    }

    // Get a pointer to the Mach-O header and check if it has the correct magic number, throwing an error if it doesn't
    const auto* header = reinterpret_cast<const mach_header_64*>(data.data());

    // Check if the magic number in the header matches the expected value for a Mach-O file and throw an error if it doesn't
    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("File is not a Mach-O file");
    }

    // Set up a cursor to iterate through the load commands in the Mach-O file and determine the end of the data vector
    const uint8_t* cursor = data.data() + sizeof(mach_header_64);
    const uint8_t* end = data.data() + data.size();

    // Iterate through the load commands in the Mach-O file to find the __TEXT, __text section and return its information
    for (uint32_t i = 0; i < header->ncmds; i++) {

        // Check if the cursor is within the bounds of the data vector and throw an error if it isn't
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        // Get a pointer to the current load command and check its size to ensure it's valid, throwing an error if it isn't
        const auto* command = reinterpret_cast<const load_command*>(cursor);
        if (command->cmdsize < sizeof(load_command) || cursor + command->cmdsize > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        // If the load command is a segment command, iterate through its sections to find the __TEXT, __text section and return its information
        if (command->cmd == LC_SEGMENT_64) {

            // Get pointers to the segment command and its first section, and iterate through all sections in the segment
            const auto* segment = reinterpret_cast<const segment_command_64*>(cursor);
            const auto* section = reinterpret_cast<const section_64*>(cursor + sizeof(segment_command_64));

            // Iterate through all sections in the segment to find the __TEXT, __text section and return its information
            for (uint32_t s = 0; s < segment->nsects; s++) {

                // Check if the section pointer is within the bounds of the data vector and throw an error if it isn't
                const auto* section_bytes = reinterpret_cast<const uint8_t*>(section);

                // Check if the section pointer is within the bounds of the data vector and throw an error if it isn't
                if (section_bytes + sizeof(section_64) > end) {
                    throw std::runtime_error("Section exceeds beyond file");
                }

                // Check if the current section is the __TEXT, __text section and return its information if it is
                if (std::string(section->sectname) == "__text" && std::string(section->segname) == "__TEXT") {
                    CodeSection code_section{};
                    code_section.address    = section->addr;
                    code_section.size       = section->size;
                    code_section.fileOffset = section->offset;

                    return code_section;
                }

                // Move to the next section in the segment
                section++;
            }
        }

        // Move the cursor to the next load command in the Mach-O file
        cursor += command->cmdsize;
    }

    throw std::runtime_error("Could not find __TEXT, __text");
}

// Get the architecture of the Mach-O file based on the cputype field in the header
Architecture MachO::GetArchitecture() const {

    // Check if the file is large enough to contain a Mach-O header and throw an error if it isn't
    if (data.size() < sizeof(mach_header_64)) {
        throw std::runtime_error("File is too small");
    }

    // Get a pointer to the Mach-O header and check if it has the correct magic number, throwing an error if it doesn't
    const auto* header = reinterpret_cast<const mach_header_64*>(data.data());
    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("File is not a Mach-O file");
    }

    // Determine the architecture of the Mach-O file based on the cputype field in the header and return it
    switch (header->cputype) {
        case CPU_TYPE_X86_64:
            return Architecture::X86_64;
        case CPU_TYPE_ARM64:
            return Architecture::ARM64;
        default:
            return Architecture::Unknown;
    }
}

std::vector<MachOSegment> MachO::GetSegments() const {
    if (data.size() < sizeof(mach_header_64)) {
        throw std::runtime_error("File is too small");
    }
    const auto* header = reinterpret_cast<const mach_header_64*>(data.data());

    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("File is not a Mach-O file");
    }

    const uint8_t* cursor = data.data() + sizeof(mach_header_64);
    const uint8_t* end = data.data() + data.size();

    std::vector<MachOSegment> segments;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        const auto* command = reinterpret_cast<const load_command*>(cursor);

        if (command->cmdsize < sizeof(load_command)) {
            throw std::runtime_error("Invalid load command size");
        }

        if (cursor + command->cmdsize > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        if (command->cmd == LC_SEGMENT_64) {

            if (command->cmdsize < sizeof(segment_command_64)) {
                throw std::runtime_error("Invalid LC_SEGMENT_64");
            }

            const auto* segment = reinterpret_cast<const segment_command_64*>(cursor);
            MachOSegment seg{};
            seg.name                = segment->segname;
            seg.vmAddress           = segment->vmaddr;
            seg.vmSize              = segment->vmsize;
            seg.fileOffset          = segment->fileoff;
            seg.fileSize            = segment->filesize;
            seg.maxProtection       = segment->maxprot;
            seg.initialProtection   = segment->initprot;

            segments.push_back(seg);
        }
        cursor += command->cmdsize;
    }
    return segments;
}

void MachO::AppendData(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        throw std::runtime_error("File is empty");
    }

    data.insert(data.end(), bytes.begin(), bytes.end());
}

void MachO::AddPayloadSection(const std::vector<uint8_t> &payload, const std::string& symbolName) {
    if (payload.empty()) {
        throw std::runtime_error("Payload is empty");
    }

    if (data.size() < sizeof(mach_header_64)) {
        throw std::runtime_error("File is too small");
    }

    if (symbolName.empty()) {
        throw std::runtime_error("Symbol name is empty");
    }

    auto* header = reinterpret_cast<const mach_header_64*>(data.data());
    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("File is not a Mach-O file");
    }

    section_64 *textSection = nullptr;
    segment_command_64 *textSegment = nullptr;
    uint32_t textSectionIndex = 0;
    uint32_t currentSectionIndex = 1;

    uint8_t* cursor = data.data() + sizeof(mach_header_64);
    uint8_t* end = data.data() + data.size();

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        auto* command = reinterpret_cast<const load_command*>(cursor);
        if (command->cmdsize < sizeof(load_command) || cursor + command->cmdsize > end) {
            throw std::runtime_error("Invalid load command size");
        }

        if (command->cmd == LC_SEGMENT_64) {
            auto* segment = reinterpret_cast<segment_command_64*>(cursor);
            const uint64_t requiredSize = sizeof(segment_command_64) + static_cast<uint64_t>(segment->nsects) * sizeof(section_64);

            if (requiredSize > command->cmdsize) {
                throw std::runtime_error("LC_SEGMENT_64 section table exceeds command");
            }

            auto* sections = reinterpret_cast<section_64*>(cursor + sizeof(segment_command_64));

            for (uint32_t s = 0; s < segment->nsects; s++) {
                auto* section = &sections[s];

                if (std::strncmp(section->segname, "__TEXT", sizeof(section->segname)) == 0 && std::strncmp(section->sectname, "__text", sizeof(section->sectname)) == 0) {
                    textSection = section;
                    textSegment = segment;
                    textSectionIndex = currentSectionIndex + s;
                    break;
                }
            }

            if (textSection) {
                break;
            }

            currentSectionIndex += segment->nsects;
        }
        cursor += command->cmdsize;
    }

    if (!textSection || !textSegment) {
        throw std::runtime_error("Could not find __TEXT, __text");
    }

    const uint64_t textOffset = textSection->offset;
    const uint64_t oldTextSize = textSection->size;
    const uint64_t textEnd = textOffset + oldTextSize;

    if (textEnd > data.size()) {
        throw std::runtime_error("__text extends beyond file");
    }

    uint64_t nextSectionOffset = UINT64_MAX;
    cursor = data.data() + sizeof(mach_header_64);
    currentSectionIndex = 1;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        auto* command = reinterpret_cast<const load_command*>(cursor);
        if (command->cmdsize < sizeof(load_command) || cursor + command->cmdsize > end) {
            throw std::runtime_error("Invalid load command size");
        }

        if (command->cmd == LC_SEGMENT_64) {
            auto* segment = reinterpret_cast<const segment_command_64*>(cursor);
            const uint64_t requiredSize = static_cast<uint64_t>(segment->nsects) * sizeof(section_64) + sizeof(segment_command_64);

            if (requiredSize > command->cmdsize) {
                throw std::runtime_error("LC_SEGMENT_64 section table exceeds command");
            }

            auto* sections = reinterpret_cast<section_64*>(cursor + sizeof(segment_command_64));

            for (uint32_t s = 0; s < segment->nsects; s++) {
                auto* section = &sections[s];

                if (section->size != 0 && section->offset > textEnd) {
                    nextSectionOffset = std::min(nextSectionOffset, static_cast<uint64_t>(section->offset));
                }
            }

            currentSectionIndex += segment->nsects;
        }

        cursor += command->cmdsize;
    }

    if (nextSectionOffset == UINT64_MAX) {
        throw std::runtime_error("Could not find space after __text");
    }

    if (nextSectionOffset < textEnd) {
        throw std::runtime_error("Mach-O section overlap");
    }

    const uint64_t alignment = 1ULL << textSection->align;
    const uint64_t functionOffset = (textEnd + alignment - 1) & ~(alignment - 1);
    const uint64_t padding = functionOffset - textEnd;
    const uint64_t requiredSpace = padding + payload.size();
    const uint64_t available = nextSectionOffset - textEnd;

    if (requiredSpace > available) {
        std::cerr
        << "Payload does not fit:\n"
        << "  payload size:   " << payload.size() << "\n"
        << "  text offset:    0x" << std::hex << textOffset << "\n"
        << "  old text size:  0x" << oldTextSize << "\n"
        << "  text end:       0x" << textEnd << "\n"
        << "  next section:   0x" << nextSectionOffset << "\n"
        << "  available:      0x" << available << "\n"
        << "  alignment:      0x" << alignment << "\n"
        << "  function offset:0x" << functionOffset << "\n"
        << "  padding:         0x" << padding << "\n"
        << "  required space:  0x" << requiredSpace << std::dec << "\n";

        throw std::runtime_error("payload does not fit in __text slack");
    }

    const uint64_t segmentFileEnd = static_cast<uint64_t>(textSegment->fileoff) + textSegment->filesize;
    const uint64_t newFileEnd = functionOffset + payload.size();

    if (newFileEnd > segmentFileEnd) {
        throw std::runtime_error("payload would extend __TEXT segment");
    }

    const uint64_t functionAddress = textSection->addr + (functionOffset - textSection->offset);
    std::copy(payload.begin(), payload.end(), data.begin() + functionOffset);

    const uint64_t newTextSize = functionOffset - textSection->offset + payload.size();
    textSection->size = newTextSize;

    AddDefinedSymbol(symbolName, functionAddress, textSectionIndex);
}

void MachO::AddDefinedSymbol(const std::string &symbolName, uint64_t address, uint8_t sectionIndex) {
    if (symbolName.empty()) {
        throw std::runtime_error("Symbol name is empty");
    }

    mach_header_64* header = reinterpret_cast<mach_header_64*>(data.data());
    symtab_command* symtab = nullptr;
    dysymtab_command* dysymtab = nullptr;
    uint64_t symtabOffset = 0;

    uint8_t* cursor = data.data() + sizeof(mach_header_64);
    uint8_t* end = data.data() + data.size();

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }
        auto* command = reinterpret_cast<const load_command*>(cursor);

        if (command->cmdsize < sizeof(load_command) || cursor + command->cmdsize > end) {
            throw std::runtime_error("Invalid load command size");
        }

        if (command->cmd == LC_SYMTAB) {
            symtab = reinterpret_cast<symtab_command*>(cursor);
            symtabOffset = static_cast<uint64_t>(cursor - data.data());
        }
        else if (command->cmd == LC_DYSYMTAB) {
            dysymtab = reinterpret_cast<dysymtab_command*>(cursor);
        }

        cursor += command->cmdsize;
    }

    if (!symtab) {
        throw std::runtime_error("Could not find symtab");
    }

    const uint64_t oldSymBytes = static_cast<uint64_t>(symtab->nsyms) * sizeof(nlist_64);
    if (static_cast<uint64_t>(symtab->symoff) + oldSymBytes > data.size()) {
        throw std::runtime_error("Symbol table exceeds file");
    }

    if (static_cast<uint64_t>(symtab->stroff) + symtab->strsize > data.size()) {
        throw std::runtime_error("Symbol table exceeds file");
    }

    auto* oldSymbols = reinterpret_cast<const nlist_64*>(data.data() + symtab->symoff);
    const char* oldStrings = reinterpret_cast<const char*>(data.data() + symtab->stroff);

    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        const nlist_64& symbol = oldSymbols[i];
        if (symbol.n_un.n_strx >= symtab->strsize) {
            throw std::runtime_error("Invalid symbol string index");
        }

        const char* existingName = oldStrings + symbol.n_un.n_strx;
        if (symbolName == existingName) {
            throw std::runtime_error("symbol already exists");
        }
    }

    std::vector<uint8_t> strings(data.begin() + symtab->stroff, data.begin() + symtab->stroff + symtab->strsize);
    if (strings.empty() || strings[0] == '\0') {
        throw std::runtime_error("Invalid string table");
    }

    const uint32_t newStringIndex = static_cast<uint32_t>(strings.size());
    strings.insert(strings.end(), symbolName.begin(), symbolName.end());
    strings.push_back('\0');

    std::vector<nlist_64> symbols(oldSymbols, oldSymbols + symtab->nsyms);
    nlist_64 newSymbol{};
    newSymbol.n_un.n_strx = newStringIndex;
    newSymbol.n_type = N_SECT | N_EXT;
    newSymbol.n_sect = sectionIndex;
    newSymbol.n_desc = 0;
    newSymbol.n_value = address;

    uint32_t newSymbolIndex = 0;
    if (dysymtab) {
        const uint64_t localEnd = static_cast<uint64_t>(dysymtab->ilocalsym) + dysymtab->nlocalsym;
        const uint64_t undefEnd = static_cast<uint64_t>(dysymtab->iundefsym) + dysymtab->nundefsym;
        const uint64_t extEnd = static_cast<uint64_t>(dysymtab->iextdefsym) + dysymtab->nextdefsym;

        if (localEnd > symbols.size() || extEnd > symbols.size() || undefEnd > symbols.size()) {
            throw std::runtime_error("Invalid LC_DYSYMTAB");
        }

        newSymbolIndex = dysymtab->iextdefsym + dysymtab->nextdefsym;
        symbols.insert(symbols.begin() + newSymbolIndex, newSymbol);
        dysymtab->nextdefsym++;
        dysymtab->iundefsym++;
    }
    else {
        newSymbolIndex = static_cast<uint32_t>(symbols.size());
        symbols.push_back(newSymbol);
        //++symtab->nsyms;
    }

    const uint64_t symbolOffset = (data.size() + 7) & ~uint64_t(7);
    if (symbolOffset > data.size()) {
        data.resize(symbolOffset, 0);
    }

    const uint64_t symbolBytes = static_cast<uint64_t>(symbols.size()) * sizeof(nlist_64);
    const uint64_t stringOffset = symbolOffset + symbolBytes;
    const uint64_t newFileSize = stringOffset + strings.size();

    data.resize(newFileSize);

    auto newSymtab = reinterpret_cast<symtab_command*>(data.data() + symtabOffset);
    newSymtab->symoff = static_cast<uint32_t>(symbolOffset);
    newSymtab->nsyms = static_cast<uint32_t>(symbols.size());
    newSymtab->stroff = static_cast<uint32_t>(stringOffset);
    newSymtab->strsize = static_cast<uint32_t>(strings.size());

    std::memcpy(data.data() + symbolOffset, symbols.data(), symbolBytes);
    std::memcpy(data.data() + stringOffset, strings.data(), strings.size());
}

size_t MachO::GetSize() const {
    return data.size();
}

void MachO::Save(const std::string &path) {
    std::ofstream out(path, std::ios::binary);

    if (!out) {
        throw std::runtime_error("Could not open file for writing");
    }

    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!out) {
        throw std::runtime_error("Could not write to file");
    }
}
