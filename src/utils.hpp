#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>

namespace Thyrn {
    namespace Utils {
        inline std::vector<uint8_t> ReadFileToMemory(const std::filesystem::path& filePath) {
            if (!std::filesystem::exists(filePath)) {
                std::cerr << "[X] Error: File does not exist -> " << filePath.string() << "\n";
                return {};
            }

            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                std::cerr << "[X] Error: Permission denied or locked file.\n";
                return {};
            }

            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(size);
            if (size > 0 && file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                return buffer;
            }
            
            return {};
        }

        inline void PrintBanner() {
            std::cout << R"(
  _____ _                     ___   ___  
 |_   _| |__  _   _ _ __ _ __/ _ \ / _ \ 
   | | | '_ \| | | | '__| '_ \ (_) | | | |
   | | | | | | |_| | |  | | | \__, | |_| |
   |_| |_| |_|\__, |_|  |_| |_| /_/ \___/ 
              |___/                       
    Binary Architecture Analyzer v0.1
    No dependencies. Just raw memory parsing.
)" << '\n';
        }
    }
}