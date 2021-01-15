// Still in build :)

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
        void initializePEFile(){
            // Section table needs parseFileHeader
            this->dos_header = (PIMAGE_DOS_HEADER) ::VirtualAlloc(NULL, sizeof(IMAGE_DOS_HEADER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            this->file_header = (PIMAGE_FILE_HEADER) ::VirtualAlloc(NULL, sizeof(IMAGE_FILE_HEADER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            this->optional_header = (PIMAGE_OPTIONAL_HEADER64) ::VirtualAlloc(NULL, sizeof(IMAGE_OPTIONAL_HEADER64), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }

        void finalizePEFile(){
            ::VirtualFree(this->dos_header, sizeof(IMAGE_DOS_HEADER), MEM_DECOMMIT | MEM_RELEASE);
            ::VirtualFree(this->file_header, sizeof(IMAGE_FILE_HEADER), MEM_DECOMMIT | MEM_RELEASE);
            ::VirtualFree(this->optional_header, sizeof(IMAGE_OPTIONAL_HEADER), MEM_DECOMMIT | MEM_RELEASE);
            ::VirtualFree(this->section_header_table, sizeof(IMAGE_SECTION_HEADER), MEM_DECOMMIT | MEM_RELEASE);
            ::CloseHandle(this->pefile);
        }

        // Parse methods are required to properly map the file into memory
        void parseDosHeader(){
            DWORD lpNumberOfBytesRead;
            ::SetFilePointer(this->pefile, 0, 0, FILE_BEGIN);
            ::ReadFile(this->pefile, this->dos_header, sizeof(IMAGE_DOS_HEADER), &lpNumberOfBytesRead, NULL);
        }

        void parseFileHeader(){
            DWORD lpNumberOfBytesRead;

            // e_lfanew brings us to PE signature; e_lfanew + 0x4 brings us to FileHeader
            ::SetFilePointer(this->pefile, dos_header->e_lfanew + 0x4, 0, FILE_BEGIN);
            ::ReadFile(this->pefile, this->file_header, sizeof(IMAGE_FILE_HEADER), &lpNumberOfBytesRead, NULL);
        }

        void parseOptionalHeader(){

        }

        void parseSectionHeader(){
            DWORD lpNumberOfBytesRead;
            
            // We need to initialize the table here because we need the value of FileHeader->NumberOfSections
            this->section_header_table = (PIMAGE_SECTION_HEADER) ::VirtualAlloc(NULL, sizeof(IMAGE_SECTION_HEADER) * this->file_header->NumberOfSections, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
            ::SetFilePointer(this->pefile, this->dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64), 0, FILE_BEGIN);
            ::ReadFile(this->pefile, this->section_header_table, sizeof(IMAGE_SECTION_HEADER) * this->file_header->NumberOfSections, &lpNumberOfBytesRead, NULL);
        }

        // Prints a section information
        void printSectionInformation(PIMAGE_SECTION_HEADER section){
            std::cout << "Name: " << section->Name << std::endl;
            std::cout << "PhysicalAddress: " << std::hex << section->Misc.PhysicalAddress << std::endl;
            std::cout << "VirtualSize: " << std::hex << section->Misc.VirtualSize << std::endl;
            std::cout << "VirtualAddress: " << std::hex << section->VirtualAddress << std::endl;
            std::cout << "SizeOfRawData: " << std::hex << section->SizeOfRawData << std::endl;
            std::cout << "PointerToRawData: " << std::hex << section->PointerToRawData << std::endl;
            std::cout << "PointerToRelocations: " << std::hex << section->PointerToRelocations << std::endl;
            std::cout << "PointerToLinenumbers: " << std::hex << section->PointerToLinenumbers << std::endl;
            std::cout << "NumberOfRelocations: " << std::hex << section->NumberOfRelocations << std::endl;
            std::cout << "NumberOfLinenumbers:" << std::hex << section->NumberOfLinenumbers << std::endl;
            std::cout << "Characteristics: " << std::hex << section->Characteristics << std::endl;
        }


    public:
        // Constructor
        PEFile64(){
            this->pefile = NULL;
            this->dos_header = NULL;
            this->file_header = NULL;
            this->optional_header = NULL;
            this->section_header_table = NULL;
        }

        BOOL openFileAsPE64(LPCSTR path_to_file){
            this->pefile = ::CreateFileA(path_to_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            
            // If has an error in opening the file, then return error code 1
            if(pefile == INVALID_HANDLE_VALUE){
                std::cout << "Error in opening file " << path_to_file << ". Code: " << ::GetLastError() << std::endl;
                return 1;
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
        PIMAGE_DOS_HEADER getDosHeader(){
            return this->dos_header;
        }

        PIMAGE_FILE_HEADER getFileHeader(){
            return this->file_header;
        }

        PIMAGE_OPTIONAL_HEADER getOptionalHeader(){
            return this->optional_header;
        }

        // Frontend: print
        void printDosHeader(){
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

        void printFileHeader(){
            std::cout << "-=-=-=-=-=-=-=-=-=-=- IMAGE_FILE_HEADER -=-=-=-=-=-=-=-=-=-=-" << std::endl;
            std::cout << "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-" << std::endl;
        }

        void printOptionalHeader(){
            std::cout << "-=-=-=-=-=-=-=-=-=-=- IMAGE_OPTIONAL_HEADER -=-=-=-=-=-=-=-=-=-=-" << std::endl;
            std::cout << "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-" << std::endl;
        }

        void printSectionNames(){
            PIMAGE_SECTION_HEADER section = this->section_header_table;

            for(int i = 0; i < this->file_header->NumberOfSections; i++, section++){
                std::cout << "=================================" << std::endl;
                printSectionInformation(section);
                std::cout << "=================================" << std::endl;
            }
            
        }
        
};

