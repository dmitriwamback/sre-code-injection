#include <iostream>
#include "src/macho/macho.h"

int main() {
    MachO macho = MachO("/Users/dmitri/Documents/working/sre-code-injection/src/sample/sample");
    macho.Inspect();
    CodeSection textSection = macho.FindCodeSection();

    std::cout << std::hex << textSection.address << std::endl;
    std::cout << textSection.size << std::endl;
    std::cout << textSection.fileOffset << std::endl;
}