#include <iostream>
#include <filesystem>
#include "utils.hpp"
#include "pe_parser.hpp"
#include "elf_parser.hpp"

using namespace std;
namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    Thyrn::Utils::PrintBanner();

    if (argc < 2) {
        cerr << "[!] Usage: " << argv[0] << " <path_to_binary>\n";
        return 1;
    }

    fs::path targetFile = fs::path(argv[1]);

    cout << "[*] Target Path : " << targetFile.string() << "\n";
    cout << "[*] Filename    : " << targetFile.filename().string() << "\n";

    vector<uint8_t> memoryBuffer = Thyrn::Utils::ReadFileToMemory(targetFile);

    if (memoryBuffer.empty()) {
        cerr << "[X] Operation aborted. Could not read file.\n";
        return 1;
    }

    cout << "[+] File successfully loaded into memory.\n";
    cout << "[+] Total Size: " << memoryBuffer.size() << " bytes.\n\n";

    if (memoryBuffer.size() >= 4) {
        if (memoryBuffer[0] == 0x4D && memoryBuffer[1] == 0x5A) {
            Thyrn::PE::Analyze(memoryBuffer);
        }
        else if (memoryBuffer[0] == 0x7F && memoryBuffer[1] == 'E' && memoryBuffer[2] == 'L' && memoryBuffer[3] == 'F') {
            Thyrn::ELF::Analyze(memoryBuffer);
        }
        else {
            cerr << "\n[-] Unknown binary format. Not a standard PE or ELF.\n";
        }
    }

    return 0;
}