//
// Created by Dmitri on 2026-09-05.
//

#ifndef SRE_CODE_INJECTION_INJECTOR_H
#define SRE_CODE_INJECTION_INJECTOR_H
#include <string>

#include "macho.h"
#include "../payload/Payload.h"

struct InjectionResult {
    uint64_t payloadAddress;
    uint64_t payloadFileOffset;
    uint64_t payloadSize;
};

class Injector {
public:
    Injector(const std::string& targetPath, const std::string& payloadPath);
    InjectionResult Inject();
    void Save(const std::string& outputPath);

private:
    void ValidateCompatibility();
    MachO target;
    Payload payload;
    InjectionResult result;
};


#endif //SRE_CODE_INJECTION_INJECTOR_H
