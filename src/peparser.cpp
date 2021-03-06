// Still in build :)
// TODO: isPEFile, isPE64, isPE32

#include <windows.h>
#include <iostream>

class PEFile64 {
    private:
        HANDLE pefile;
        PIMAGE_DOS_HEADER dos_header;
        PIMAGE_FILE_HEADER file_header;
        PIMAGE_OPTIONAL_HEADER64 optional_header;
        PIMAGE_SECTION_HEADER section_header_table;
    
        // initiliaze/finalize: the beginning and the end of a mapped PE file :)
        void initializePEFile();
        void finalizePEFile();

        // General use
        // allocatedSpace is at least numBytes of size
        int dumpBytes(int offsetStart, int numBytes, char * allocatedSpace);

        // Parse methods are required to properly map the file into memory
        void parseDosHeader();
        void parseFileHeader();
        void parseOptionalHeader();
        void parseSectionHeader();

        // Prints a section information
        void printSectionInformation(PIMAGE_SECTION_HEADER section);

    public:
        // Constructor
        PEFile64();
        PEFile64(LPCSTR path_to_file);

        // Initializer
        int openFileAsPE64(LPCSTR path_to_file);

        // GETs
        PIMAGE_DOS_HEADER getDosHeader();
        PIMAGE_FILE_HEADER getFileHeader();
        PIMAGE_OPTIONAL_HEADER getOptionalHeader();

        // Section-related stuff. pointerToDumpedData doesn't need to be allocated previously
        int dumpSection(LPCSTR sectionName, char * pointerToDumpedData);
        PIMAGE_SECTION_HEADER getSection(LPCSTR sectionName);

        // Frontend: print
        void printDosHeader();
        void printFileHeader();
        void printOptionalHeader();
        void printSectionNames();
        void printDirectories();
};


void PEFile64::initializePEFile(){
    // Section table needs parseFileHeader
    this->dos_header = (PIMAGE_DOS_HEADER) ::VirtualAlloc(NULL, sizeof(IMAGE_DOS_HEADER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    this->file_header = (PIMAGE_FILE_HEADER) ::VirtualAlloc(NULL, sizeof(IMAGE_FILE_HEADER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    this->optional_header = (PIMAGE_OPTIONAL_HEADER64) ::VirtualAlloc(NULL, sizeof(IMAGE_OPTIONAL_HEADER64), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

void PEFile64::finalizePEFile(){
    ::VirtualFree(this->dos_header, sizeof(IMAGE_DOS_HEADER), MEM_DECOMMIT | MEM_RELEASE);
    ::VirtualFree(this->file_header, sizeof(IMAGE_FILE_HEADER), MEM_DECOMMIT | MEM_RELEASE);
    ::VirtualFree(this->optional_header, sizeof(IMAGE_OPTIONAL_HEADER), MEM_DECOMMIT | MEM_RELEASE);
    ::VirtualFree(this->section_header_table, sizeof(IMAGE_SECTION_HEADER), MEM_DECOMMIT | MEM_RELEASE);
    ::CloseHandle(this->pefile);
}

int PEFile64::dumpBytes(int offsetStart, int numBytes, char * allocatedSpace){
    DWORD lpNumberOfBytesRead;
    ::SetFilePointer(this->pefile, offsetStart, 0, FILE_BEGIN);
    return ::ReadFile(this->pefile, allocatedSpace, numBytes, &lpNumberOfBytesRead, NULL);
}

// Parse methods are required to properly map the file into memory
void PEFile64::parseDosHeader(){
    DWORD lpNumberOfBytesRead;
    ::SetFilePointer(this->pefile, 0, 0, FILE_BEGIN);
    ::ReadFile(this->pefile, this->dos_header, sizeof(IMAGE_DOS_HEADER), &lpNumberOfBytesRead, NULL);
}

void PEFile64::parseFileHeader(){
    DWORD lpNumberOfBytesRead;

    // e_lfanew brings us to PE signature; e_lfanew + 0x4 brings us to FileHeader
    ::SetFilePointer(this->pefile, dos_header->e_lfanew + 0x4, 0, FILE_BEGIN);
    ::ReadFile(this->pefile, this->file_header, sizeof(IMAGE_FILE_HEADER), &lpNumberOfBytesRead, NULL);
}

void PEFile64::parseOptionalHeader(){
    DWORD lpNumberOfBytesRead;

    // e_lfanew brings us to PE signature; e_lfanew + 0x4 brings us to FileHeader
    ::SetFilePointer(this->pefile, dos_header->e_lfanew + 0x4 + sizeof(IMAGE_FILE_HEADER), 0, FILE_BEGIN);
    ::ReadFile(this->pefile, this->optional_header, sizeof(IMAGE_OPTIONAL_HEADER), &lpNumberOfBytesRead, NULL);
}

void PEFile64::parseSectionHeader(){
    DWORD lpNumberOfBytesRead;
    
    // We need to initialize the table here because we need the value of FileHeader->NumberOfSections
    this->section_header_table = (PIMAGE_SECTION_HEADER) ::VirtualAlloc(NULL, sizeof(IMAGE_SECTION_HEADER) * this->file_header->NumberOfSections, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    ::SetFilePointer(this->pefile, this->dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64), 0, FILE_BEGIN);
    ::ReadFile(this->pefile, this->section_header_table, sizeof(IMAGE_SECTION_HEADER) * this->file_header->NumberOfSections, &lpNumberOfBytesRead, NULL);
}

// Prints a section information
void PEFile64::printSectionInformation(PIMAGE_SECTION_HEADER section){
    std::cout << "Name: " << section->Name << std::endl;
    std::cout << "PhysicalAddress: " << std::hex << section->Misc.PhysicalAddress << std::endl;
    std::cout << "VirtualSize: " << std::hex << section->Misc.VirtualSize << std::endl;
    std::cout << "Relative Virtual Address: " << std::hex << section->VirtualAddress << std::endl;
    std::cout << "Virtual Address: " << std::hex << section->VirtualAddress + this->optional_header->ImageBase << std::endl;
    std::cout << "SizeOfRawData: " << std::hex << section->SizeOfRawData << std::endl;
    std::cout << "PointerToRawData: " << std::hex << section->PointerToRawData << std::endl;
    std::cout << "PointerToRelocations: " << std::hex << section->PointerToRelocations << std::endl;
    std::cout << "PointerToLinenumbers: " << std::hex << section->PointerToLinenumbers << std::endl;
    std::cout << "NumberOfRelocations: " << std::hex << section->NumberOfRelocations << std::endl;
    std::cout << "NumberOfLinenumbers:" << std::hex << section->NumberOfLinenumbers << std::endl;
    std::cout << "Characteristics: " << std::hex << section->Characteristics << std::endl;
}


// public
PEFile64::PEFile64(){
    this->pefile = NULL;
    this->dos_header = NULL;
    this->file_header = NULL;
    this->optional_header = NULL;
    this->section_header_table = NULL;
}

PEFile64::PEFile64(LPCSTR path_to_file){
    this->openFileAsPE64(path_to_file);
}

int PEFile64::openFileAsPE64(LPCSTR path_to_file){
    this->pefile = ::CreateFileA(path_to_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    // If has an error in opening the file, then return error code 1
    if(pefile == INVALID_HANDLE_VALUE){
        return GetLastError();
    }

    // Load all the components here
    initializePEFile();
    parseDosHeader();
    parseFileHeader();
    parseOptionalHeader();
    parseSectionHeader();
    return 0;
}



// GETs
PIMAGE_DOS_HEADER PEFile64::getDosHeader(){
    return this->dos_header;
}

PIMAGE_FILE_HEADER PEFile64::getFileHeader(){
    return this->file_header;
}

PIMAGE_OPTIONAL_HEADER PEFile64::getOptionalHeader(){
    return this->optional_header;
}

int PEFile64::dumpSection(LPCSTR sectionName, char * pointerToDumpedData){
    PIMAGE_SECTION_HEADER section = getSection(sectionName);

    if(section == NULL)
        return 1;
    
    // alloc
    pointerToDumpedData = (char *) ::VirtualAlloc(NULL, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    dumpBytes(section->PointerToRawData, section->SizeOfRawData, pointerToDumpedData);
}

PIMAGE_SECTION_HEADER PEFile64::getSection(LPCSTR sectionName){
    PIMAGE_SECTION_HEADER section = this->section_header_table;

    for(int i = 0; i < this->file_header->NumberOfSections; i++, section++){
        if(!strcmp((const char *)(section->Name), sectionName)){
            return section;
        }   
    }
    return NULL;
}

// Frontend: print
void PEFile64::printDosHeader(){
    std::cout << "-=-=-=-=-=-=-=-=-=-=- IMAGE_DOS_HEADER -=-=-=-=-=-=-=-=-=-=-" << std::endl;
    std::cout << "e_magic: " << std::hex << this->dos_header->e_magic << std::endl;
    std::cout << "e_cblp: " << std::hex << this->dos_header->e_cblp << std::endl;
    std::cout << "e_cp: " << std::hex << this->dos_header->e_cp << std::endl;
    std::cout << "e_crlc: " << std::hex << this->dos_header->e_crlc << std::endl;
    std::cout << "e_cparhdr: " << std::hex << this->dos_header->e_cparhdr << std::endl;
    std::cout << "e_minalloc: " << std::hex << this->dos_header->e_minalloc << std::endl;
    std::cout << "e_maxalloc: " << std::hex << this->dos_header->e_maxalloc << std::endl;
    std::cout << "e_ss: " << std::hex << this->dos_header->e_ss << std::endl;
    std::cout << "e_sp: " << std::hex << this->dos_header->e_sp << std::endl;
    std::cout << "e_csum: " << std::hex << this->dos_header->e_csum << std::endl;
    std::cout << "e_ip: " << std::hex << this->dos_header->e_ip << std::endl;
    std::cout << "e_cs: " << std::hex << this->dos_header->e_cs << std::endl;
    std::cout << "e_lfarlc: " << std::hex << this->dos_header->e_lfarlc << std::endl;
    std::cout << "e_ovno: " << std::hex << this->dos_header->e_ovno << std::endl;
    std::cout << "e_res: " << std::hex << this->dos_header->e_res << std::endl; // e_res[4]
    std::cout << "e_oemid: " << std::hex << this->dos_header->e_oemid << std::endl;
    std::cout << "e_oeminfo: " << std::hex << this->dos_header->e_oeminfo << std::endl;
    std::cout << "e_res2: " << std::hex << this->dos_header->e_res2 << std::endl; // e_res2[10]
    std::cout << "e_lfanew: " << std::hex << this->dos_header->e_lfanew << std::endl;
    std::cout << "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-" << std::endl;

}

void PEFile64::printFileHeader(){
    std::cout << "-=-=-=-=-=-=-=-=-=-=- IMAGE_FILE_HEADER -=-=-=-=-=-=-=-=-=-=-" << std::endl;
    std::cout << "Machine: " << std::hex << this->file_header->Machine << std::endl;
    std::cout << "NumberOfSections: " << std::hex << this->file_header->NumberOfSections << std::endl;
    std::cout << "TimeDateStamp: " << std::hex << this->file_header->TimeDateStamp << std::endl;
    std::cout << "PointerToSymbolTable: " << std::hex << this->file_header->PointerToSymbolTable << std::endl;
    std::cout << "NumberOfSymbols: " << std::hex << this->file_header->NumberOfSymbols << std::endl;
    std::cout << "SizeOfOptionalHeader: " << std::hex << this->file_header->SizeOfOptionalHeader << std::endl;
    std::cout << "Characteristics: " << std::hex << this->file_header->Characteristics << std::endl;
    std::cout << "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-" << std::endl;
}

void PEFile64::printOptionalHeader(){
    std::cout << "-=-=-=-=-=-=-=-=-=-=- IMAGE_OPTIONAL_HEADER -=-=-=-=-=-=-=-=-=-=-" << std::endl;
    std::cout << "Magic: " << std::hex << this->optional_header->Magic << std::endl;
    std::cout << "MajorLinkerVersion: " << std::hex << this->optional_header->MajorLinkerVersion << std::endl;
    std::cout << "MinorLinkerVersion: " << std::hex << this->optional_header->MinorLinkerVersion << std::endl;
    std::cout << "SizeOfCode: " << std::hex << this->optional_header->SizeOfCode << std::endl;
    std::cout << "SizeOfInitializedData: " << std::hex << this->optional_header->SizeOfInitializedData << std::endl;
    std::cout << "SizeOfUninitializedData: " << std::hex << this->optional_header->SizeOfUninitializedData << std::endl;
    std::cout << "AddressOfEntryPoint: " << std::hex << this->optional_header->AddressOfEntryPoint << std::endl;
    std::cout << "BaseOfCode: " << std::hex << this->optional_header->BaseOfCode << std::endl;
    // std::cout << "BaseOfData: " << this->optional_header->BaseOfData << std::endl;
    std::cout << "ImageBase: " << std::hex << this->optional_header->ImageBase << std::endl;
    std::cout << "SectionAlignment: " << std::hex << this->optional_header->SectionAlignment << std::endl;
    std::cout << "FileAlignment: " << std::hex << this->optional_header->FileAlignment << std::endl;
    std::cout << "MajorOperatingSystemVersion: " << std::hex << this->optional_header->MajorOperatingSystemVersion << std::endl;
    std::cout << "MinorOperatingSystemVersion: " << std::hex << this->optional_header->MinorOperatingSystemVersion << std::endl;
    std::cout << "MajorImageVersion: " << std::hex << this->optional_header->MajorImageVersion << std::endl;
    std::cout << "MinorImageVersion: " << std::hex << this->optional_header->MinorImageVersion << std::endl;
    std::cout << "MajorSubsystemVersion: " << std::hex << this->optional_header->MajorSubsystemVersion << std::endl;
    std::cout << "MinorSubsystemVersion: " << std::hex << this->optional_header->MinorSubsystemVersion << std::endl;
    std::cout << "Win32VersionValue: " << std::hex << this->optional_header->Win32VersionValue << std::endl;
    std::cout << "SizeOfImage: " << std::hex << this->optional_header->SizeOfImage << std::endl;
    std::cout << "SizeOfHeaders: " << std::hex << this->optional_header->SizeOfHeaders << std::endl;
    std::cout << "CheckSum: " << std::hex << this->optional_header->CheckSum << std::endl;
    std::cout << "Subsystem: " << std::hex << this->optional_header->Subsystem << std::endl;
    std::cout << "DllCharacteristics: " << std::hex << this->optional_header->DllCharacteristics << std::endl;
    std::cout << "SizeOfStackReserve: " << std::hex << this->optional_header->SizeOfStackReserve << std::endl;
    std::cout << "SizeOfStackCommit: " << std::hex << this->optional_header->SizeOfStackCommit << std::endl;
    std::cout << "SizeOfHeapReserve: " << std::hex << this->optional_header->SizeOfHeapReserve << std::endl;
    std::cout << "SizeOfHeapCommit: " << std::hex << this->optional_header->SizeOfHeapCommit << std::endl;
    std::cout << "LoaderFlags: " << std::hex << this->optional_header->LoaderFlags << std::endl;
    std::cout << "NumberOfRvaAndSizes: " << std::hex << this->optional_header->NumberOfRvaAndSizes << std::endl;
    std::cout << "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-" << std::endl;
}

void PEFile64::printSectionNames(){
    PIMAGE_SECTION_HEADER section = this->section_header_table;

    for(int i = 0; i < this->file_header->NumberOfSections; i++, section++){
        std::cout << "=================================" << std::endl;
        printSectionInformation(section);
        std::cout << "=================================" << std::endl;
    }
    
}

void PEFile64::printDirectories(){
    std::string directory_names[16] = {"EXPORT TABLE", "IMPORT TABLE", "RESOURCE TABLE", "EXCEPTION TABLE", "CERTIFICATE TABLE", "BASE RELOCATION TABLE",
    "DEBUG", "ARCHITECTURE", "GLOBAL PTR", "TLS TABLE", "LOAD CONFIG TABLE", "BOUND IMPORT", "IAT", "DELAY IMPORT DESCRIPTOR",
    "CLR RUNTIME HEADER", "RESERVED"};
    PIMAGE_DATA_DIRECTORY data_directory = this->optional_header->DataDirectory;

    for(int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++){
        std::cout << "=================================" << std::endl;
        std::cout << "Data Directory " << directory_names[i] << std::endl;
        std::cout << "Virtual Address: " << std::hex << data_directory[i].VirtualAddress << std::endl;
        std::cout << "Size: " << std::hex << data_directory[i].Size << std::endl;
        std::cout << "=================================" << std::endl;
    }
}