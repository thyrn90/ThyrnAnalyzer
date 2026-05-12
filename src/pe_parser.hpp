#pragma once
#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <cstring>

namespace Thyrn {
    namespace PE {
        inline void Analyze(const std::vector<uint8_t>& buffer) {
            if (buffer.size() < 64) {
                std::cerr << "[-] Error: Buffer too small to be a valid executable.\n";
                return;
            }

            if (buffer[0] != 0x4D || buffer[1] != 0x5A) {
                std::cerr << "[-] Error: Missing 'MZ' signature. Not a Windows executable.\n";
                return;
            }

            uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(&buffer[0x3C]);
            
            if (e_lfanew >= buffer.size() || e_lfanew + 24 > buffer.size()) {
                std::cerr << "[!] Warning: Malformed PE offset (0x" << std::hex << e_lfanew << "). Possible malware or packed binary!\n";
                return;
            }

            if (buffer[e_lfanew] != 0x50 || buffer[e_lfanew + 1] != 0x45) {
                std::cerr << "[-] Error: Invalid PE signature at offset 0x" << std::hex << e_lfanew << "\n";
                return;
            }

            std::cout << "\n[--- WINDOWS PE HEADER ANALYSIS ---]\n";
            std::cout << "[+] PE Signature found at 0x" << std::hex << std::uppercase << e_lfanew << "\n";

            uint16_t machine = *reinterpret_cast<const uint16_t*>(&buffer[e_lfanew + 4]);
            
            uint16_t sections = *reinterpret_cast<const uint16_t*>(&buffer[e_lfanew + 6]);
            
            uint32_t entry_point = *reinterpret_cast<const uint32_t*>(&buffer[e_lfanew + 40]);

            std::cout << "[*] Architecture : 0x" << machine;
            if (machine == 0x8664) std::cout << " (x64 - AMD64)\n";
            else if (machine == 0x014C) std::cout << " (x86 - i386)\n";
            else std::cout << " (Unknown/Exotic)\n";

            std::cout << "[*] Sections     : " << std::dec << sections << "\n";
            std::cout << "[*] Entry Point  : 0x" << std::hex << entry_point << " (OEP)\n";
            
            std::cout << "[+] PE structure is intact. Ready for deep section dumping.\n\n";
            std::cout << std::dec;

            uint16_t opt_header_size = *reinterpret_cast<const uint16_t*>(&buffer[e_lfanew + 20]);
            size_t first_section_offset = static_cast<size_t>(e_lfanew) + 24 + opt_header_size;

            std::cout << "[--- PE SECTIONS (MEMORY MAP) ---]\n";
            std::cout << std::left << std::setw(10) << "Name" 
                      << std::setw(12) << "V.Size" 
                      << std::setw(12) << "V.Addr" 
                      << std::setw(12) << "RawSize" 
                      << "RawAddr\n";
            std::cout << "---------------------------------------------------------\n";

            for (int i = 0; i < sections; ++i) {
                size_t current_sec = first_section_offset + (i * 40);
                if (current_sec + 40 > buffer.size()) break;

                char name[9] = {0};
                std::memcpy(name, &buffer[current_sec], 8);

                uint32_t v_size = *reinterpret_cast<const uint32_t*>(&buffer[current_sec + 8]);
                uint32_t v_addr = *reinterpret_cast<const uint32_t*>(&buffer[current_sec + 12]);
                uint32_t raw_size = *reinterpret_cast<const uint32_t*>(&buffer[current_sec + 16]);
                uint32_t raw_addr = *reinterpret_cast<const uint32_t*>(&buffer[current_sec + 20]);

                std::cout << std::left << std::setw(10) << name 
                          << "0x" << std::hex << std::setw(10) << v_size 
                          << "0x" << std::setw(10) << v_addr 
                          << "0x" << std::setw(10) << raw_size 
                          << "0x" << raw_addr << "\n";
            }
            std::cout << std::dec << "\n";
        }
    }
}