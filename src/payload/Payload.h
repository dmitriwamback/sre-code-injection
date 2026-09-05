//
// Created by Dmitri on 2026-09-05.
//

#ifndef SRE_CODE_INJECTION_PAYLOAD_H
#define SRE_CODE_INJECTION_PAYLOAD_H
#include <cstdint>
#include <vector>


class Payload {
public:
    Payload(const std::string& path);
    const std::vector<uint8_t>& Bytes() const;

private:
    std::vector<uint8_t> data;
};


#endif //SRE_CODE_INJECTION_PAYLOAD_H
