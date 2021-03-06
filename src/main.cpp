// Still in build :)

#include <iostream>
#include <windows.h>
#include "peparser.cpp"

int main(int argc, char **argv){
    if (argc < 2){
        std::cout << "USAGE: " << argv[0] << " <pefile>" << std::endl;
        return 1;
    }

    // Open PE file indicated by argv[1]

    PEFile64 pefile;
    if(int ret = pefile.openFileAsPE64(argv[1])){
        std::cout << "Error opening file " << argv[1] << ". Code: " << ret << std::endl;
        return 1;
    }
    //std::cout << "Pointer to PE Signature: " << std::hex << pefile.getDosHeader()->e_lfanew << std::endl;
    //std::cout << "Machine: " << std::hex << pefile.getFileHeader()->Machine << std::endl << std::endl;
    //pefile.printDosHeader();
    //pefile.printFileHeader();
    //pefile.printOptionalHeader();
    //pefile.printDirectories();
    pefile.printSectionNames();
    //std::cout << "Sections:" << std::endl;
    //pefile.printSectionNames();
    //pefile.printDosHeader();
}