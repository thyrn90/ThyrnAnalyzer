#pragma once
#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <string>

namespace Thyrn {
    namespace ELF {
        inline void Analyze(const std::vector<uint8_t>& buffer) {
            if (buffer.size() < 64) {
                std::cerr << "[-] Error: Buffer too small to be a valid ELF binary.\n";
                return;
            }

            if (buffer[0] != 0x7F || buffer[1] != 'E' || buffer[2] != 'L' || buffer[3] != 'F') {
                std::cerr << "[-] Error: Invalid ELF magic. Not a Linux executable.\n";
                return;
            }

            std::cout << "\n[--- LINUX ELF HEADER ANALYSIS ---]\n";
            std::cout << "[+] ELF Magic Signature verified.\n";

            uint8_t elf_class = buffer[0x04];
            std::cout << "[*] Class        : " << (elf_class == 2 ? "ELF64 (64-bit)" : "ELF32 (32-bit)") << "\n";

            uint8_t endianness = buffer[0x05];
            if (endianness == 2) {
                std::cerr << "[!] WARNING: Big-Endian ELF detected! Offsets will read incorrectly on Little-Endian host.\n";
            }

            uint16_t machine = *reinterpret_cast<const uint16_t*>(&buffer[0x12]);
            std::cout << "[*] Architecture : 0x" << std::hex << machine;
            if (machine == 0x3E) std::cout << " (x86_64 - AMD64)\n";
            else if (machine == 0x03) std::cout << " (x86 - i386)\n";
            else if (machine == 0xB7) std::cout << " (AArch64 - ARM64)\n";
            else std::cout << " (Unknown/Other)\n";

            std::cout << "[*] Entry Point  : 0x" << std::hex;
            if (elf_class == 2) {
                uint64_t entry_point = *reinterpret_cast<const uint64_t*>(&buffer[0x18]);
                std::cout << entry_point << " (OEP)\n";
            } else {
                uint32_t entry_point = *reinterpret_cast<const uint32_t*>(&buffer[0x18]);
                std::cout << entry_point << " (OEP)\n";
            }

            std::cout << "[+] ELF core structure validated. Ready to dump memory sections.\n\n";
            std::cout << std::dec;
            std::cout << "[--- ELF SECTIONS (MEMORY MAP) ---]\n";
            if (elf_class == 2) {
                uint64_t shoff = *reinterpret_cast<const uint64_t*>(&buffer[0x28]);
                uint16_t shentsize = *reinterpret_cast<const uint16_t*>(&buffer[0x3A]);
                uint16_t shnum = *reinterpret_cast<const uint16_t*>(&buffer[0x3C]);
                uint16_t shstrndx = *reinterpret_cast<const uint16_t*>(&buffer[0x3E]);

                uint64_t strtab_hdr_offset = shoff + (shstrndx * shentsize);
                uint64_t strtab_offset = 0;
                
                if (strtab_hdr_offset + 0x20 <= buffer.size()) {
                    strtab_offset = *reinterpret_cast<const uint64_t*>(&buffer[strtab_hdr_offset + 0x18]);
                }

                std::cout << std::left << std::setw(20) << "Name"
                          << std::setw(16) << "Raw Offset" 
                          << std::setw(12) << "Size" 
                          << "Virtual Addr\n";
                std::cout << "----------------------------------------------------------------\n";

                for (int i = 0; i < shnum; ++i) {
                    uint64_t current_sec = shoff + (i * shentsize);
                    if (current_sec + shentsize > buffer.size()) break;

                    uint32_t name_idx = *reinterpret_cast<const uint32_t*>(&buffer[current_sec]);
                    
                    uint64_t addr = *reinterpret_cast<const uint64_t*>(&buffer[current_sec + 0x10]);
                    uint64_t offset = *reinterpret_cast<const uint64_t*>(&buffer[current_sec + 0x18]);
                    uint64_t size = *reinterpret_cast<const uint64_t*>(&buffer[current_sec + 0x20]);

                    std::string sec_name = "";
                    if (name_idx != 0 && (strtab_offset + name_idx < buffer.size())) {
                        size_t max_len = buffer.size() - (strtab_offset + name_idx);
                        const char* str_ptr = reinterpret_cast<const char*>(&buffer[strtab_offset + name_idx]);
                        size_t actual_len = 0;
                        while (actual_len < max_len && str_ptr[actual_len] != '\0') {
                            actual_len++;
                        }
                        sec_name = std::string(str_ptr, actual_len);
                    } else if (i == 0) {
                        sec_name = "NULL";
                    }

                    if (size > 0 || !sec_name.empty()) {
                        std::cout << std::left << std::setw(20) << sec_name
                                  << "0x" << std::hex << std::setw(14) << offset 
                                  << "0x" << std::setw(10) << size 
                                  << "0x" << addr << "\n";
                    }
                }
            } else {
                std::cout << "[!] Deep section scanning for ELF32 is currently bypassed.\n";
            }
            std::cout << std::dec << "\n";
        }
    }
}