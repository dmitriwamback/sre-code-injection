cmake_minimum_required(VERSION 4.3)
project(sre_code_injection)

set(CMAKE_CXX_STANDARD 20)

add_executable(sre_code_injection main.cpp
        src/macho/macho.cpp
        src/macho/macho.h
        src/macho/arm64.cpp
        src/macho/arm64.h
        src/macho/injector.cpp
        src/macho/injector.h
        src/payload/Payload.cpp
        src/payload/Payload.h)
