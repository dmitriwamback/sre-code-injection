#include <iostream>
#include "src/macho/macho.h"
#include "src/payload/Payload.h"

int main() {
    // Create a MachO object for the sample binary and inspect it to find the __TEXT, __text section
    MachO macho = MachO("/Users/dmitri/Documents/working/sre-code-injection/src/sample/sample");

    // Inspect the Mach-O file to find the __TEXT, __text section and print its address, size, and file offset
    macho.Inspect();
    CodeSection textSection = macho.FindCodeSection();

    std::cout << std::hex << textSection.address << std::endl;
    std::cout << textSection.size << std::endl;
    std::cout << textSection.fileOffset << std::endl;

    // Create a Payload object for the sample payload and print its code size and offset
    Payload payload = Payload("/Users/dmitri/Documents/working/sre-code-injection/src/sample/payload/payload.o");

    // Print the code size and offset of the payload to the console
    std::cout << "Code size: " << payload.Code().size() << " bytes\n";
    std::cout << "Code offset: 0x" << std::hex <<  payload.CodeSection().offset << std::endl;
}
