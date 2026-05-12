#include <iostream>
#include <filesystem>
#include <exception>
#include <iomanip>
#include "utils.hpp"
#include "pe_parser.hpp"
#include "elf_parser.hpp"

using namespace std;
namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    try {
        Thyrn::Utils::PrintBanner();

        if (argc < 2) {
            cerr << "[!] Usage: " << argv[0] << " <path_to_binary>\n";
            return 1;
        }

        fs::path targetFile = fs::path(argv[1]);

        cout << "[*] Target Path : " << targetFile.string() << "\n";
        cout << "[*] Filename    : " << targetFile.filename().string() << "\n";

        if (!fs::exists(targetFile) || !fs::is_regular_file(targetFile)) {
            cerr << "[-] Error: Target does not exist or is not a regular file.\n";
            return 1;
        }

        vector<uint8_t> memoryBuffer = Thyrn::Utils::ReadFileToMemory(targetFile);

        if (memoryBuffer.empty()) {
            cerr << "[X] Operation aborted. Could not read file or file is empty.\n";
            return 1;
        }

        cout << "[+] File successfully loaded into memory.\n";
        cout << "[+] Total Size: " << dec << memoryBuffer.size() << " bytes.\n\n";

        if (memoryBuffer.size() >= 4) {
            if (memoryBuffer[0] == 0x4D && memoryBuffer[1] == 0x5A) {
                Thyrn::PE::Analyze(memoryBuffer);
            }
            else if (memoryBuffer[0] == 0x7F && memoryBuffer[1] == 'E' && memoryBuffer[2] == 'L' && memoryBuffer[3] == 'F') {
                Thyrn::ELF::Analyze(memoryBuffer);
            }
            else {
                cerr << "\n[-] Unknown binary format. Magic bytes: ";
                cerr << hex << uppercase << setfill('0')
                     << "0x" << setw(2) << (int)memoryBuffer[0] << " "
                     << "0x" << setw(2) << (int)memoryBuffer[1] << " "
                     << "0x" << setw(2) << (int)memoryBuffer[2] << " "
                     << "0x" << setw(2) << (int)memoryBuffer[3] << "\n";
                cerr << "[-] Not a standard PE or ELF executable.\n";
            }
        } else {
            cerr << "[-] Error: File is too small to contain a valid magic header.\n";
        }
    } 
    catch (const fs::filesystem_error& e) {
        cerr << "\n[!] Filesystem Error: " << e.what() << "\n";
        cerr << "[!] Tip: Check file permissions or run as Administrator. The file might be locked.\n";
        return 1;
    }
    catch (const std::exception& e) {
        cerr << "\n[!] Fatal Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}