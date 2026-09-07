//
// Created by Dmitri on 2026-09-05.
//

#include "injector.h"

Injector::Injector(const std::string &targetPath, const std::string &payloadPath) : target(targetPath), payload(payloadPath) {}

void Injector::ValidateCompatibility() {
    const Architecture targetArchitecture = target.GetArchitecture();
    const Architecture payloadArchitecture = target.GetArchitecture();

    if (targetArchitecture == Architecture::Unknown || payloadArchitecture == Architecture::Unknown) {
        throw std::runtime_error("Unknown architecture");
    }

    if (targetArchitecture != payloadArchitecture) {
        throw std::runtime_error("Both payload architecture and target architecture must be the same");
    }
}

InjectionResult Injector::Inject() {

    ValidateCompatibility();

    target.Inspect();

    const auto& payloadCode = payload.Code();

    if (payloadCode.empty()) {
        throw std::runtime_error("Payload is empty");
    }

    const auto segments = target.GetSegments();
    if (segments.empty()) {
        throw std::runtime_error("No segments");
    }

    target.AddPayloadSection(payloadCode, "_testFunction");

    result.payloadAddress = 0;
    result.payloadSize = payloadCode.size();

    return result;
}

void Injector::Save(const std::string &outputPath) {
    target.Save(outputPath);

    std::string cmd1 = "xattr -d com.apple.quarantine \"" + outputPath + "\"";
    std::string cmd2 = "codesign --remove-signature \"" + outputPath + "\"";
    std::string cmd3 = "codesign --force --sign - \"" + outputPath + "\"";
    std::string cmd4 = "chmod +x \"" + outputPath + "\"";

    system(cmd1.c_str());
    system(cmd2.c_str());
    system(cmd3.c_str());
    system(cmd4.c_str());
}
