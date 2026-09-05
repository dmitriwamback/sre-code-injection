//
// Created by Dmitri on 2026-09-05.
//

#include "macho.h"
#include <mach-o/loader.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

MachO::MachO(const std::string& path) {
    this->filepath = path;

    std::ifstream file(this->filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open file");
    }

    file.seekg(0, std::ios::end);
    const auto size = file.tellg();

    if (size <= 0) {
        throw std::runtime_error("File is empty");
    }

    file.seekg(0, std::ios::beg);
    data.resize(size);

    file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

    if (!file) {
        throw std::runtime_error("Could not read file");
    }
}

void MachO::Inspect() {

    if (data.size() < sizeof(mach_header_64)) {
        throw std::runtime_error("File is too small");
    }
    const auto* header = reinterpret_cast<const mach_header_64*>(data.data());

    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("File is not a Mach-O file");
    }

    std::cout << "File: " << this->filepath << std::endl;
    std::cout << "Size: " << data.size() << " bytes" << std::endl;

    if (header->cputype == CPU_TYPE_ARM64) {
        std::cout << "ARM64" << std::endl;
    }
    else {
        std::cout << "Architecture 0x" << std::hex << header->cputype << std::dec << std::endl;
    }

    std::cout << "Load Commands: " << header->ncmds << std::endl;
    const uint8_t* cursor = data.data() + sizeof(mach_header_64);
    const uint8_t* end = data.data() + data.size();

    for (uint32_t i = 0; i < header->ncmds; i++) {

        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        const auto* command = reinterpret_cast<const load_command*>(cursor);

        if (command->cmdsize < sizeof(load_command)) {
            throw std::runtime_error("Invalid command size");
        }

        if (cursor + command->cmdsize > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        std::cout << "\nLoad Command " << i << std::endl;
        std::cout << "  cmd:    0x" << std::hex << command->cmd << std::endl;
        std::cout << "  cmdsize: 0x" << command->cmdsize << std::dec << std::endl;

        if (command->cmd == LC_SEGMENT_64) {
            const auto* segment = reinterpret_cast<const segment_command_64*>(cursor);
            std::cout << "Segment: " << segment->segname << std::endl;
            std::cout << "  vmaddr:  0x" << std::hex << segment->vmaddr << std::endl;
            std::cout << "  vmsize:  0x" << segment->vmsize << std::endl;
            std::cout << "  fileoff:  0x" << segment->fileoff << std::endl;
            std::cout << "  filesize:  0x" << segment->filesize << std::endl;
            std::cout << "  sections:  " << segment->nsects << std::endl;

            const auto* section = reinterpret_cast<const section_64*>(cursor + sizeof(segment_command_64));

            for (uint32_t s = 0; s < segment->nsects; s++) {
                const auto* section_end = reinterpret_cast<const uint8_t*>(section + sizeof(section_64));
                if (section_end > end) {
                    throw std::runtime_error("Section exceeds beyond file");
                }

                std::cout << "Section: " << section->sectname << std::endl;
                std::cout << "  addr:    0x" << std::hex << section->addr << std::endl;
                std::cout << "  size:    0x" << std::hex << section->size << std::endl;
                std::cout << "  fileoff:  0x" << std::hex << section->offset << std::dec << std::endl;

                section++;
            }
        }
        cursor += command->cmdsize;
    }
}

CodeSection MachO::FindCodeSection() const {

    if (data.size() < sizeof(mach_header_64)) {
        throw std::runtime_error("File is too small");
    }

    const auto* header = reinterpret_cast<const mach_header_64*>(data.data());

    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("File is not a Mach-O file");
    }

    const uint8_t* cursor = data.data() + sizeof(mach_header_64);
    const uint8_t* end = data.data() + data.size();

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cursor + sizeof(load_command) > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        const auto* command = reinterpret_cast<const load_command*>(cursor);
        if (command->cmdsize < sizeof(load_command) || cursor + command->cmdsize > end) {
            throw std::runtime_error("Load command exceeds beyond file");
        }

        if (command->cmd == LC_SEGMENT_64) {
            const auto* segment = reinterpret_cast<const segment_command_64*>(cursor);
            const auto* section = reinterpret_cast<const section_64*>(cursor + sizeof(segment_command_64));

            for (uint32_t s = 0; s < segment->nsects; s++) {
                const auto* section_bytes = reinterpret_cast<const uint8_t*>(section);

                if (section_bytes + sizeof(section_64) > end) {
                    throw std::runtime_error("Section exceeds beyond file");
                }

                if (std::string(section->sectname) == "__text" && std::string(section->segname) == "__TEXT") {
                    CodeSection code_section;
                    code_section.address    = section->addr;
                    code_section.size       = section->size;
                    code_section.fileOffset = section->offset;

                    return code_section;
                }

                section++;
            }
        }

        cursor += command->cmdsize;
    }

    throw std::runtime_error("Could not find __TEXT, __text");
}

Architecture MachO::GetArchitecture() const {
    if (data.size() < sizeof(mach_header_64)) {
        throw std::runtime_error("File is too small");
    }
    const auto* header = reinterpret_cast<const mach_header_64*>(data.data());
    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("File is not a Mach-O file");
    }

    switch (header->cputype) {
        case CPU_TYPE_X86_64:
            return Architecture::X86_64;
        case CPU_TYPE_ARM64:
            return Architecture::ARM64;
        default:
            return Architecture::Unknown;
    }
}