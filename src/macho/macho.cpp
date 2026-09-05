//
// Created by Dmitri on 2026-09-05.
//

#include "macho.h"
#include <mach-o/loader.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

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
                const auto* section_end = reinterpret_cast<const uint8_t*>(section + sizeof(section_64));
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
                    CodeSection code_section;
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