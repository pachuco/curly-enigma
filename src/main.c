//#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#ifdef __WIN32
#include "mman.h"
#else
#include <sys/mman.h>
#endif

#define COUNTOF(X) (sizeof(X) / sizeof(X[0]))

#define GETBIT(BMAP, IND)   !!((BMAP)[(IND)>>3] &   (0x80>>((IND)&0x7F)))
#define SETBIT(BMAP, IND)     ((BMAP)[(IND)>>3] |=  (0x80>>((IND)&0x7F)))
#define UNSETBIT(BMAP, IND)   ((BMAP)[(IND)>>3] &= ~(0x80>>((IND)&0x7F)))

#ifdef BIG_ENDIAN
    #define SWP16(X) (X)
    #define SWP24(X) (X)
    #define SWP32(X) (X)
#else
    #define SWP16(X) (((X)>>8)&0x00FF) | (((X)<<8)&0xFF00)
    #define SWP24(X) (((X)>>16)&0x0000FF) | ((X)&0x00FF00) | (((X)<<16)&0xFF0000) 
    #define SWP32(X) (((X)>>24)&0x000000FF) | (((X)>>8)&0x0000FF00) | (((X)<<8)&0x00FF0000) | (((X)<<24)&0xFF000000)
#endif

#define FT_DEFINE(PATH) {{0}, 0, PATH}

/*typedef struct {
    char* buf;
    int   len;
} MemFile;

int loadMemFile(char* path, MemFile* mf) {
    char* buf; int len;
	FILE* fin = fopen(path, "rb");
	if (!fin) return 0;

    fseek(fin, 0, SEEK_END);
    len = ftell( fin );
    fseek(fin, 0, SEEK_SET);

    buf = malloc(len);
    if(!buf) {
        fclose(fin);
        return 0;
    }

    fread(buf, 1, len, fin);
	fclose(fin);
    
    mf->buf = buf;
    mf->len = len;
    
    return 1;
}

void freeMemFile(MemFile* mf) {
    if (mf) {
        if (mf->buf) free(mf->buf);
        mf->buf = 0;
        mf->len = 0;
    }
}*/




































//some things we know:
//- encryption repeats every 64kb. It's XOR.
//- the firmware is split in two: OS image, user FS.
//- osSize01/02 is the place where OS splits from user FS, uint24_t.
//- the OS image is crypted separately from user FS.
//- the user FS contains lots of whitespace, easy to reverse rolling XOR.
//- the OS image is compact, not so easy to reverse rolling XOR. Crib dragging suggested.
//- files are 16777264 long, which is exactly 16 mb plus header.
//- endianess is BE
//- Firmware is for SCDR II.
//- The myv-55 phone has TI Calypso+ chipset, which is ARM9 probably.
//- The Calypso probably decodes firmware.


#define LEN_HEADER 0x30
#define LEN_CRYPT 0x10000

#pragma pack(push,1)
typedef struct { //len 48??
    char idString[19];      //not a 0t string
    uint8_t  UNK01;         //04
    uint32_t UNK02:24;      //00 00 00
    uint32_t UNK03:8;       //00
    uint32_t osSize01:24;   //B4 00 00
                            //B5 00 00
    uint32_t UNK04:8;       //FF
    uint32_t romsize01:24;  //FF FF FF
    uint32_t UNK05:8;       //FF
    uint32_t romsize02:24;  //FF FF FF
    uint32_t UNK06:8;       //04
    uint32_t osSize02:24;   //B4 00 00     //coincides
                            //B5 00 00
    uint32_t UNK07:8;       //FF
    uint32_t size01:24;     //52 21 A6
                            //52 21 EE
                            //52 25 7A
                            //53 38 06
                            //53 38 4A
                            //53 91 AA
                            //53 91 D2
                            //53 A6 9E
    uint32_t UNK08:8;       //04
    uint32_t size02;        //00 FF 02 22
                            //00 FF 02 2F
                            //00 FF 02 30
} FirmwareHeader;
#pragma pack(pop)

#define MAX_HISTORY 8
typedef struct {
    uint8_t  data[LEN_CRYPT];
    //shows which bytes were changed each round
    uint32_t usedHistory;
    uint8_t  history[MAX_HISTORY][LEN_CRYPT>>3];
} CryptKey;

typedef struct {
  FirmwareHeader* header;
  uint8_t* data; //rawData + LEN_HEADER
} Firmware;

typedef struct {
    union {
        uint8_t* rawData;
        Firmware firm;
    };
    uint32_t size;
    char* path;
} FileThing;


bool armFileThing(FileThing* ft, int wantedAccess) {
    FILE* fin;
    uint8_t* map;
    uint32_t size;
    if (ft->rawData) return true;
    
    fin = fopen(ft->path, "rb");
    if (!fin) return false;
    
    fseek(fin, 0, SEEK_END);
    size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    map = mmap(NULL, size, wantedAccess, MAP_SHARED, fileno(fin), 0);
    if (map != MAP_FAILED) {
        ft->size = size;
        ft->rawData = map; //firm.header == rawData
        ft->firm.data = map + LEN_HEADER;
    }
    
    fclose(fin);
    return true;
}

void disarmFileThing(FileThing* ft) {
    uint8_t* rawData = ft->rawData;
    uint32_t size = ft->size;
    
    memset(&ft->firm, 0, sizeof(Firmware));
    ft->size = 0;
    
    if (rawData) munmap(rawData, size);
}










//find what is possibly 64kb of encrypted blank space
/*int doBlankFind(uint32_t* outOff, uint32_t startOffset) {
    int nrSegments = (g_fileMemLen - startOffset - LEN_HEADER) / LEN_CRYPT;
    char* grandWinPtr = NULL;
    int grandWinNum = 1;
    
    printf("\n!Stage doBlankFind.\n");
    for (int i=0; i < nrSegments; i++) {
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
}

int XorUserFsAssumingSingleCharPlaintext(uint32_t decodeOff, uint8_t plainTextByte) {
    FILE* fout = fopen("decrypt.bin", "wb");
    uint32_t fsOffset = SWP24(g_header->osSize01);
    uint32_t mask = (LEN_CRYPT-1);
    uint32_t offsetCorrection = decodeOff;
    if(!fout) goto l_fail;
    
    fwrite(g_fileMem, 1, fsOffset, fout);
    printf("\n!Stage XorUserFsAssumingSingleCharPlaintext.\n");
    for (int i=fsOffset; i < g_fileMemLen; i++) {
        char cipher = g_fileMem[i];
        char key    = g_fileMem[decodeOff + ((i - LEN_HEADER) & (LEN_CRYPT-1))] ^ plainTextByte;
        char plainText = cipher ^ key;
        fwrite(&plainText, 1, 1, fout);
    }
    
    fclose(fout);
    
    return 1;
    l_fail:
        if (fout) fclose(fout);
        return 0;
}*/

//offset excludes header!
bool getKeyFromSingleCharPlaintext(CryptKey* ck, FileThing* ftFirm, int offset, uint8_t plainTextByte) {
    if (!armFileThing(ftFirm, PROT_READ)) return false;
    
    
    
    return true;
}

bool getKeyFromFilePlaintext(CryptKey* ck, FileThing* ftFirm, int offset, int len, FileThing* ftPlain) {
    if (!armFileThing(ftFirm, PROT_READ)) return false;
    if (!armFileThing(ftPlain, PROT_READ)) return false;
    
    
    
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

static CryptKey t1Keys[2] = {0};
static CryptKey t2Keys[2] = {0};

#define CHK(X) if (!(X)) return 1
int main(int argc, char* argv[]) {
    assert(LEN_HEADER == sizeof(FirmwareHeader));
    
    
    //CHK(g_fileMem = loadfile("", &g_fileMemLen));
    
    uint32_t blankOffset = 0xDE0030;
    //printHeader();
    //CHK(doBlankFind(&blankOffset, SWP24(g_header->osSize01)));
    
    //CHK(doDumbXOR(blankOffset, NULL));
    //CHK(XorUserFsAssumingSingleCharPlaintext(blankOffset, 0xFF));

    
    return 0;
}