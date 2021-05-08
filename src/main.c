//#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef __WIN32
    #include <io.h>
    #include "mman.h"
    #define open  _open
    #define fstat _fstat
    #define stat  _stat
    #define close _close
    #define O_ACCMODE _O_ACCMODE
    #define O_RDONLY  _O_RDONLY
    #define O_RDWR    _O_RDWR
    #define O_WRONLY  _O_WRONLY
    #define O_CREAT   _O_CREAT
    #define ftruncate _chsize
#else
    #include <sys/mman.h>
#endif

#define COUNTOF(X) (sizeof(X) / sizeof(X[0]))

#define GETBIT(BMAP, IND)   !!((BMAP)[(IND)>>3] &   (0x80>>((IND)&0x7)))
#define SETBIT(BMAP, IND)     ((BMAP)[(IND)>>3] |=  (0x80>>((IND)&0x7)))
#define UNSETBIT(BMAP, IND)   ((BMAP)[(IND)>>3] &= ~(0x80>>((IND)&0x7)))

#define SWP16(X) (((X)>>8)&0x00FF) | (((X)<<8)&0xFF00)
#define SWP24(X) (((X)>>16)&0x0000FF) | ((X)&0x00FF00) | (((X)<<16)&0xFF0000) 
#define SWP32(X) (((X)>>24)&0x000000FF) | (((X)>>8)&0x0000FF00) | (((X)<<8)&0x00FF0000) | (((X)<<24)&0xFF000000)

#define FT_DEFINE(PATH) {{0}, 0, PATH}




































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
#define MAX_HISTORY 8

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


//----------------------------------------------------------------------
bool openFileThing(FileThing* ft, int accessFlags) {
    #ifndef NONMMAP_FALLBACK
        struct stat sb;
        uint8_t* map;
        int fd;
        int wantedAccess = 0;
        uint32_t size = 0;
        
        if (ft->rawData) return true;
        
        switch (accessFlags & O_ACCMODE) {
            case O_RDONLY:
                wantedAccess = PROT_READ;
                break;
            case O_WRONLY:
                wantedAccess = PROT_WRITE;
                size = ft->size;
                break;
            case O_RDWR:
                wantedAccess = PROT_WRITE | PROT_READ;
                break;
        }
        if ((fd = open(ft->path, accessFlags)) == -1) goto l_fail;
        if (size == 0) {
            if (fstat(fd, &sb) == -1) goto l_fail;
            size = sb.st_size;
        } else {
            if (ftruncate(fd, size) == -1) goto l_fail;
        }
        
        map = mmap(NULL, size, wantedAccess, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) goto l_fail;
        
        ft->size = size;
        ft->rawData = map; //firm.header == rawData
        ft->firm.data = map + LEN_HEADER;
        
        close(fd);
        return true;
        
        l_fail:
            if (fd != -1) close(fd);
            return false;
    #else
        char* buf  = NULL;
        FILE* file = NULL;
        
        if ((accessFlags & O_ACCMODE) == O_WRONLY) {
            buf = calloc(ft->size, 1);
            if (!buf) return false;
            
            ft->rawData = buf; //firm.header == rawData
            ft->firm.data = buf + LEN_HEADER;
        } else {
            FILE* file = fopen(ft->path, "rb");
            uint32_t size;
            if (!file) return false;
            
            fseek(file, 0, SEEK_END);
            size = ftell(file);
            fseek(file, 0, SEEK_SET);
            
            buf = calloc(size, 1);
            if (!buf) {
                fclose(file);
                return false;
            }
            
            fread(buf, 1, size, file);
            fclose(file);
            
            ft->size = size;
            ft->rawData = buf; //firm.header == rawData
            ft->firm.data = buf + LEN_HEADER;
        }
        
        if (file) fclose(file);
        return true;
    #endif
}

void closeFileThing(FileThing* ft) {
    #ifndef NONMMAP_FALLBACK
        uint8_t* rawData = ft->rawData;
        uint32_t size = ft->size;
        
        memset(&ft->firm, 0, sizeof(Firmware));
        ft->size = 0;
        
        if (rawData) {
            msync(rawData, size, MS_SYNC|MS_INVALIDATE);
            munmap(rawData, size);
        }
    #else
        FILE* file = fopen(ft->path, "wb");
        if (file) {
            fwrite(ft->rawData, 1, ft->size, file);
            fclose(file);
        }
        if (ft->rawData) {
            free(ft->rawData);
        }
    #endif
}










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
        
        ck->data[(offset+i)&(LEN_CRYPT-1)] = key;
    }
    
    if (ck->usedHistory < MAX_HISTORY) {
        for (uint32_t i=0; i < LEN_CRYPT; i++) {
            SETBIT(ck->history[ck->usedHistory], (offset+i)&(LEN_CRYPT-1));
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
        uint8_t oldKey = ck->data[(offset+i)&(LEN_CRYPT-1)];
        
        ck->data[(offset+i)&(LEN_CRYPT-1)] = key;
        if (ck->usedHistory < MAX_HISTORY && key != oldKey) {
            SETBIT(ck->history[ck->usedHistory], (offset+i)&(LEN_CRYPT-1));
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
           ftOut.firm.data[j] = pFtFirm->firm.data[j] ^ ck->data[j&(LEN_CRYPT-1)];
        }
    }
    
    closeFileThing(&ftOut);
    return true;
}


#define RGB8(_B,_G,_R) ((_B)/64 + ((_G)/32)*4 + ((_R)/32)*32)
#define MAIN_WIDTH      256
#define MAIN_HEIGHT     LEN_CRYPT/MAIN_WIDTH
#define RULER_WIDTH     4*1
#define COL_RULKEYBG    RGB8(0,0,100)
#define COL_RULHISTBG   RGB8(100,0,0)
#define COL_RULORHISTBG RGB8(0,100,0)
#define COL_RULFG       RGB8(255,255,255)
#define COL_BITMFG      RGB8(255,255,255)
#define COL_BITMBG      0x00
#pragma pack(push,1)
typedef struct {
    uint16_t  bfType;
    uint32_t  bfSize;
    uint16_t  bfReserved1;
    uint16_t  bfReserved2;
    uint32_t  bfOffBits;
    
    uint32_t  biSize;
    int32_t   biWidth;
    int32_t   biHeight;
    uint16_t  biPlanes;
    uint16_t  biBitCount;
    uint32_t  biCompression;
    uint32_t  JUNK[5];
    uint32_t  palette[256];  
} BmpHeader;
#pragma pack(pop)
bool writeCryptkeyAndHistoryPixelmap(CryptKey* ck, char* outPath) {
    uint8_t orMap[LEN_CRYPT>>3] = {0};
    uint8_t* out;
    uint32_t imageCount = (1 + ck->usedHistory + 1);
    uint32_t pixelCount = ((MAIN_WIDTH+RULER_WIDTH)*MAIN_HEIGHT) * imageCount;
    FileThing ftOut = FT_DEFINE(outPath);
    ftOut.size = sizeof(BmpHeader) + (pixelCount);
    if (!openFileThing(&ftOut, O_WRONLY|O_CREAT)) return false;
    BmpHeader* bmpHead = ftOut.rawData;
    
    memset(bmpHead, 0x00, sizeof(BmpHeader));
    bmpHead->bfType        = 0x4D42; //BM
    bmpHead->bfSize        = sizeof(BmpHeader) + pixelCount;
    bmpHead->bfOffBits     = sizeof(BmpHeader);
    
    bmpHead->biSize        = 40; //offsetof(BmpFile,Pal)-offsetof(BmpFile,biSize)
    bmpHead->biWidth       = MAIN_WIDTH+RULER_WIDTH;
    bmpHead->biHeight      = -(MAIN_HEIGHT * imageCount);
    bmpHead->biPlanes      = 1;
    bmpHead->biBitCount    = 8;
    bmpHead->biCompression = 0; //BI_RGB
    
    //rgb(3:3:2) palette
    uint32_t i = 0;
    for (uint32_t red=0; red < 8; red++) {
        for (uint32_t green=0; green < 8; green++) {
            for (uint32_t blue=0; blue < 4; blue++) {
                bmpHead->palette[i++] = ((blue*255)/3) | (((green*255)/7) << 8) | (((red*255)/7) << 16);
            }
        }
    }
    
    void drawRuler(uint8_t** ppOut, uint8_t colBg) {
        #define NUM_DIVISIONS 3
        for (int i=0; i < MAIN_HEIGHT; i++) {
            *ppOut += MAIN_WIDTH;
            
            //background
            memset(*ppOut, colBg, RULER_WIDTH);
            
            //foreground
            for (int j=0; j < NUM_DIVISIONS; j++) {
                if (i % (MAIN_HEIGHT>>j)) continue;
                
                memset(*ppOut, COL_RULFG, RULER_WIDTH/(j+1));
                break;
            }
            
            *ppOut += RULER_WIDTH;
        }
    }
    
    //ruler
    
    out = ftOut.rawData + sizeof(BmpHeader);
    drawRuler(&out, COL_RULKEYBG);
    for (int i=0; i<ck->usedHistory; i++) drawRuler(&out, COL_RULHISTBG);
    drawRuler(&out, COL_RULORHISTBG);
    out = ftOut.rawData + sizeof(BmpHeader);
    //key
    for (int i=0; i < MAIN_HEIGHT; i++) {
        memcpy(out, &ck->data[i* MAIN_WIDTH], MAIN_WIDTH);
        out += MAIN_WIDTH+RULER_WIDTH;
    }
    
    //history
    for (int i=0; i < ck->usedHistory; i++) {
        for (int j=0; j < MAIN_HEIGHT; j++) {
            for (int k=0; k < MAIN_WIDTH; k++) {
                out[k] = GETBIT(ck->history[i], j*MAIN_WIDTH + k) ? COL_BITMFG : COL_BITMBG;
            }
            out += MAIN_WIDTH+RULER_WIDTH;
        }
    }
    
    //coverage OR map
    //skip first one, since it's done from single byte XOR over whole range
    for (int i=1; i < ck->usedHistory; i++) {
        for (int j=0; j < (LEN_CRYPT>>3); j++) {
            orMap[j] |= ck->history[i][j];
        }
    }

    for (int i=0; i < MAIN_HEIGHT; i++) {
        for (int j=0; j < MAIN_WIDTH; j++) {
            out[j] = GETBIT(orMap, (i*MAIN_WIDTH) + j) ? COL_BITMFG : COL_BITMBG;
        }
        out += MAIN_WIDTH+RULER_WIDTH;
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
    
    CHK(getKeyFromBytePlaintext(&t1Keys[1], &t1Firmwares[0], 0xDE0030,            0xFF));
    CHK(getKeyFromFilePlaintext(&t1Keys[1], &t1Firmwares[0], 0xE5109A-LEN_HEADER, &plaintexts[0])); //myv55: barthezz
    CHK(getKeyFromFilePlaintext(&t1Keys[1], &t1Firmwares[0], 0xF0D38A-LEN_HEADER, &plaintexts[1])); //myv55: mrvain
    
    CHK(writeCryptkeyAndHistoryPixelmap(&t1Keys[1], "./t1user.bmp"));
    CHK(writeXoredFirmwareWithCryptkeyPair(NULL, &t1Keys[1], &t1Firmwares[0], "./dec_myV-55.bin"));
    
    return 0;
}