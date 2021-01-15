// Still in build :)

#include <iostream>
#include <windows.h>
#include "peparser.cpp"

void printDosHeader(PIMAGE_DOS_HEADER dos_header);
void printFileHeader(PIMAGE_FILE_HEADER file_header);
void printOptionalHeader(PIMAGE_OPTIONAL_HEADER optional_header);

int main(int argc, char **argv){
    if (argc < 2){
        std::cout << "USAGE: " << argv[0] << " <pefile>" << std::endl;
        return 1;
    }

    // Open PE file indicated by argv[1]

    PEFile64 pefile;
    pefile.openFileAsPE64(argv[1]);
    std::cout << "Pointer to PE Signature: " << std::hex << pefile.getDosHeader()->e_lfanew << std::endl;
    std::cout << "Machine: " << std::hex << pefile.getFileHeader()->Machine << std::endl << std::endl;
    
    std::cout << "Sections:" << std::endl;
    pefile.printSectionNames();
    //pefile.printDosHeader();
}