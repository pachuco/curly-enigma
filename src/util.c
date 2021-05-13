#include "crypto.h"
#include "util.h"



#define RGB8(R, G, B)      ((B)/64 + ((G)/32)*4 + ((R)/32)*32)
#define DARKEN(COL, RATIO) (COL*RATIO/255)
#define MAIN_WIDTH      256
#define MAIN_HEIGHT     LEN_CRYPT/MAIN_WIDTH
#define RULER_WIDTH     4*2
#define COL_RULKEYBG    RGB8(100,0  ,0  )
#define COL_RULHISTBG   RGB8(0  ,0  ,200)
#define COL_RULORHISTBG RGB8(0  ,100,0  )
#define COL_RULFG       RGB8(255,255,255)
#define COL_BITMBG      RGB8(0  ,0  ,0  )
#define COL_BITMFGTRY   RGB8(128,128,128)
#define COL_BITMFGDID   RGB8(255,255,255)

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

bool writeCryptkeyAndHistoryPixelmap(CryptKey* ck, char* outPath) {
    uint8_t orMap[LEN_HISTORY] = {0};
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
    void drawHistory(uint8_t** ppOut, uint8_t* pHist) {
        for (int i=0; i < MAIN_HEIGHT; i++) {
            for (int j=0; j < MAIN_WIDTH; j++) {
                uint8_t hist = GETBITS(pHist, (i*MAIN_WIDTH) + j, HIST_MASK);
                
                if      (hist & HIST_DID)   (*ppOut)[j] = COL_BITMFGDID;
                else if (hist & HIST_TRIED) (*ppOut)[j] = COL_BITMFGTRY;
                else                        (*ppOut)[j] = COL_BITMBG;
            }
            *ppOut += MAIN_WIDTH+RULER_WIDTH;
        }
    }
    
    out = ftOut.rawData + sizeof(BmpHeader);
    //ruler
    drawRuler(&out, COL_RULKEYBG);
    for (int i=0; i<ck->usedHistory; i++) {
        uint8_t col = i&1 ? DARKEN(COL_RULHISTBG, 200) : COL_RULHISTBG;
        drawRuler(&out, col);
    }
    drawRuler(&out, COL_RULORHISTBG);
    
    out = ftOut.rawData + sizeof(BmpHeader);
    //key
    for (int i=0; i < MAIN_HEIGHT; i++) {
        memcpy(out, &ck->data[i* MAIN_WIDTH], MAIN_WIDTH);
        out += MAIN_WIDTH+RULER_WIDTH;
    }
    
    //history
    for (int i=0; i < ck->usedHistory; i++) {
        drawHistory(&out, &ck->history[i].data);
    }
    
    //coverage OR map of file plaintexts
    for (int i=0; i < ck->usedHistory; i++) {
        if (ck->history[i].operation != HISTOP_FILEXOR) continue;
        for (int j=0; j < LEN_HISTORY; j++) {
            orMap[j] |= ck->history[i].data[j];
        }
    }
    
    drawHistory(&out, &orMap);
    
    closeFileThing(&ftOut);
    return true;
}