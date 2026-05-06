ThyrnAnalyzer
Building robust systems in C++, breaking them down in Assembly.

A lightweight, zero-dependency binary analysis tool written in pure C++17. ThyrnAnalyzer parses and extracts the core memory architecture of both Windows (PE) and Linux (ELF) executables. No <windows.h>, no heavy external libraries, no bloat. Just raw memory mapping and byte-level header reconstruction.

Features
Zero Dependencies: Pure C++17.

Cross-Platform: Analyzes PE (.exe, .dll) and ELF binaries dynamically.

Raw Parsing: Safe memory loading and manual byte-offset calculations instead of high-level OS wrappers.

Deep Memory Mapping: Extracts virtual addresses, raw sizes, and hidden section names (including .shstrtab parsing for Linux binaries).

Crash-Resistant: Built to handle malformed, packed, or obfuscated binaries without segfaulting.

Build
Linux / WSL

Bash
git clone https://github.com/thyrn90/ThyrnAnalyzer.git
cd ThyrnAnalyzer
cmake -B build
cmake --build build
./build/ThyrnAnalyzer /bin/ls

Windows

PowerShell
git clone https://github.com/thyrn90/ThyrnAnalyzer.git
cd ThyrnAnalyzer
cmake -B build
cmake --build build
.\build\Debug\ThyrnAnalyzer.exe C:\Windows\System32\calc.exe
