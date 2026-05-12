#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <exception>

namespace Thyrn {
    namespace Utils {
        constexpr std::streamsize MAX_FILE_SIZE = 256 * 1024 * 1024; 

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
            
            if (size > MAX_FILE_SIZE) {
                std::cerr << "[X] Error: File is too large (" << (size / 1024 / 1024) 
                          << " MB). Max supported size is 256 MB to prevent memory exhaustion.\n";
                return {};
            }

            if (size == 0) {
                std::cerr << "[X] Error: File is empty.\n";
                return {};
            }

            file.seekg(0, std::ios::beg);

            try {
                std::vector<uint8_t> buffer(static_cast<size_t>(size));
                
                if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                    return buffer;
                } else {
                    std::cerr << "[X] Error: Failed to read the entire file into memory.\n";
                    return {};
                }
            } 
            catch (const std::bad_alloc& e) {
                std::cerr << "[X] Fatal Error: Memory allocation failed. System out of RAM!\n";
                return {};
            }
        }

        inline void PrintBanner() {
            std::cout << R"(
 _____ _                    ___   ___  
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