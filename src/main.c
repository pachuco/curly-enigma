//#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "crypto.h"
#include "util.h"


















































//find what is possibly 64kb of encrypted blank space
/*int doBlankFind(uint32_t* outOff, uint32_t startOffset) {
    int nrSegments = (g_fileMemLen - startOffset - LEN_HEADER) / LEN_CRYPT;
    char* grandWinPtr = NULL;
    int grandWinNum = 1;
    
    printf("\n!Stage doBlankFind.\n");
    for (uint32_t i=0; i < nrSegments; i++) {
        char* ptr1 = g_fileMem + startOffset + LEN_HEADER + LEN_CRYPT*i;
        int winNum = 1;
        
        for (int j=i; j < nrSegments; j++) {
            char* ptr2 = g_fileMem + startOffset + LEN_HEADER + LEN_CRYPT*j;
            
            if (!memcmp(ptr1, ptr2, LEN_CRYPT)) winNum++;
        }
        
        if (winNum > grandWinNum) {
            grandWinNum = winNum;
            grandWinPtr = ptr1;
        }
    }
    
    if (grandWinPtr) {
        printf("Promising 64kb chunk at file offset of 0x%X, repeated a total of %d times.\n", grandWinPtr - g_fileMem, grandWinNum);
        *outOff = grandWinPtr - g_fileMem;
        return 1;
    } else {
        printf("No identical 64kb chunks or code failed.\n");
        return 0;
    }
}*/

//offset excludes header!
bool getKeyFromBytePlaintext(CryptKey* ck, FileThing* pFtFirm, uint32_t offset, uint8_t plainTextByte) {
    if (!openFileThing(pFtFirm, O_RDONLY)) return false;
    
    for (uint32_t i=0; i < LEN_CRYPT; i++) {
        uint8_t cipher = pFtFirm->firm.data[offset+i];
        uint8_t key    = cipher ^ plainTextByte;
        
        ck->data[(offset+i) & MASK_CRYPT] = key;
    }
    
    if (ck->usedHistory < MAX_HISTORY) {
        for (uint32_t i=0; i < LEN_CRYPT; i++) {
            SETBIT(ck->history[ck->usedHistory], (offset+i) & MASK_CRYPT);
        }
        ck->usedHistory++;
    }
    
    return true;
}

bool getKeyFromFilePlaintext(CryptKey* ck, FileThing* pFtFirm, uint32_t offset, FileThing* pFtPlain) {
    if (!openFileThing(pFtFirm,  O_RDONLY)) return false;
    if (!openFileThing(pFtPlain, O_RDONLY)) return false;
    
    for (uint32_t i=0; i < pFtPlain->size; i++) {
        uint8_t cipher = pFtFirm->firm.data[offset+i];
        uint8_t key    = cipher ^ pFtPlain->rawData[i];
        uint8_t oldKey = ck->data[(offset+i) & MASK_CRYPT];
        
        ck->data[(offset+i) & MASK_CRYPT] = key;
        if (ck->usedHistory < MAX_HISTORY && key != oldKey) {
            SETBIT(ck->history[ck->usedHistory], (offset+i) & MASK_CRYPT);
        }
    }
    if (ck->usedHistory < MAX_HISTORY) ck->usedHistory++;
    
    return true;
}

bool writeXoredFirmwareWithCryptkeyPair(CryptKey* ckOs, CryptKey* ckUser, FileThing* pFtFirm, char* outPath) {
    if (!openFileThing(pFtFirm, O_RDONLY)) return false;
    FileThing ftOut = FT_DEFINE(outPath);
    ftOut.size = pFtFirm->size;
    if (!openFileThing(&ftOut, O_WRONLY|O_CREAT)) return false;
    
    memcpy(ftOut.firm.header, pFtFirm->firm.header, sizeof(FirmwareHeader));
    
    CryptKey* keys[2]   = {ckOs, ckUser}; 
    uint32_t offsets[3] = {0, SWP24(pFtFirm->firm.header->osSize01), pFtFirm->size - LEN_HEADER};
    for (uint32_t i=0; i < 2; i++) {
        CryptKey* ck = keys[i];
        uint32_t startOff = offsets[i+0];
        uint32_t endOff   = offsets[i+1];
        
        if (!ck) {
            memcpy(ftOut.firm.data+startOff, pFtFirm->firm.data+startOff, endOff - startOff);
            continue;
        }
        
        for (uint32_t j=startOff; j < endOff; j++) {
           ftOut.firm.data[j] = pFtFirm->firm.data[j] ^ ck->data[j & MASK_CRYPT];
        }
    }
    
    closeFileThing(&ftOut);
    return true;
}

//t1 firmwares have one pair of keys, t2 another
static FileThing t1Firmwares[] = {
    FT_DEFINE("./../t1/myV-55_KB3,MC  010604 1043(22)_251538352_M2004_F153_04_N2_Vodafone_FID12.fls"),
    FT_DEFINE("./../t1/myC-5-2_KA3,RC 151004 1709(22)_251691245_F314_04_N1_Vodafone_FID12.fls"),
    FT_DEFINE("./../t1/myC-5-2_KA3,RC 151004 1709(22)_251691245_F314_04_N1_Vodafone_FID21.fls"),
    FT_DEFINE("./../t1/myC-5-2_KA3,RE 091104 1816(22)_251748432_F323_04_N1_Meteor_FID12.fls"),
    FT_DEFINE("./../t1/myC-5-2_KA3,RE 091104 1816(22)_251748432_F323_04_N1_Meteor_FID21.fls"),
    FT_DEFINE("./../t1/myC-5-2_KA3,RE  241104 1856(22)_251715582_F046_05_N1_FREE_FID21.fls"),
    FT_DEFINE("./../t1/myC-5-2_KA3,RE  241104 1856(22)_251748432_F323_04_N1_FREE_FID12.fls"),
    FT_DEFINE("./../t1/myX-4_KB3,NG 051004 1041(30)_251647776_FID12_FREE.fls"),
    FT_DEFINE("./../t1/myX-4_KB3,NG 051004 1041(30)_251658394_FID21_FREE.fls"),
    FT_DEFINE("./../t1/myX-4_KB3,NG 251004 1027(30)_251647776_FID12_FREE.fls"),
    FT_DEFINE("./../t1/myX-4_KB3,NG 251004 1027(30)_251658394_FID21_FREE.fls"),
    FT_DEFINE("./../t1/myX-4_KE3,ND 281004 1457(22)_251654437_FID12_ORANGE.fls"),
    FT_DEFINE("./../t1/myX-4_KE3,ND 281004 1457(22)_251658394_FID21_ORANGE.fls"),
};

static FileThing t2Firmwares[] = {
    FT_DEFINE("./../t2/myX-5-2_KB3,ME 210604 1654(22)_251545034_M2004_F138_04_N1_IDEA_FID12.fls"),
    FT_DEFINE("./../t2/myX-5-2_KB3,ME 210604 1654(22)_251545034_M2004_F138_04_N1_IDEA_FID21.fls"),
    FT_DEFINE("./../t2/myX-5-2_KB3,MF  180604 1736(2F)_251587491_M2004_F168_04_N1_FREE_FID12.fls"),
    FT_DEFINE("./../t2/myX-5-2_KB3,MF  180604 1736(2F)_251587491_M2004_F168_04_N1_FREE_FID21.fls"),
    FT_DEFINE("./../t2/myX-5-2_KB3,MJ  300704 1919(22)_251608112_M2004_F240_04_N1_T-Mobile_FID12.fls"),
};

//these files are known to exist in user FS part of firmwares
//at best, I can hope to get a full user FS key
static FileThing plaintexts[] = {
    FT_DEFINE("./../plaintexts/barthezz.mid"),
    FT_DEFINE("./../plaintexts/CultureBeat_-_MrVain__JD_20121217233537.mid"),
};

//OS image, followed by user FS
static CryptKey t1Keys[2] = {0};
static CryptKey t2Keys[2] = {0};

#define CHK(X) if (!(X)) return 1
int main(int argc, char* argv[]) {
    assert(LEN_HEADER == sizeof(FirmwareHeader));
    
    CHK(getKeyFromBytePlaintext(&t1Keys[1], &t1Firmwares[0], 0xDE0030, 0xFF));
    //CHK(getKeyFromBytePlaintext(&t1Keys[1], &t1Firmwares[1], 0xBA189A, 0xFF));
    
    CHK(getKeyFromFilePlaintext(&t1Keys[1], &t1Firmwares[0], 0xE5109A-LEN_HEADER, &plaintexts[0])); //myv55: barthezz
    CHK(getKeyFromFilePlaintext(&t1Keys[1], &t1Firmwares[0], 0xF0D38A-LEN_HEADER, &plaintexts[1])); //myv55: mrvain
    
    CHK(writeCryptkeyAndHistoryPixelmap(&t1Keys[1], "./t1user.bmp"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[0],  "./dec_myV55.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[1],  "./dec_myC52_001.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[2],  "./dec_myC52_002.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[3],  "./dec_myC52_003.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[4],  "./dec_myC52_004.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[5],  "./dec_myC52_005.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[6],  "./dec_myC52_006.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[7],  "./dec_myX4_001.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[8],  "./dec_myX4_002.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[9],  "./dec_myX4_003.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[10], "./dec_myX4_004.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[11], "./dec_myX4_005.bin"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[12], "./dec_myX4_006.bin"));
    
    return 0;
}