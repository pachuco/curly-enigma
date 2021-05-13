#include <stdint.h>

#define SWP16(X) (((X)>>8)&0x00FF) | (((X)<<8)&0xFF00)
#define SWP24(X) (((X)>>16)&0x0000FF) | ((X)&0x00FF00) | (((X)<<16)&0xFF0000) 
#define SWP32(X) (((X)>>24)&0x000000FF) | (((X)>>8)&0x0000FF00) | (((X)<<8)&0x00FF0000) | (((X)<<24)&0xFF000000)

#define LEN_HEADER 0x30
#define MAX_HISTORY     8
#define LEN_CRYPT       0x10000
#define MASK_CRYPT      (LEN_CRYPT-1)
#define LEN_HISTORY     (LEN_CRYPT>>2)


#define GETBITS(BMAP, IND, MASK)    ((((uint8_t*)(BMAP))[(IND)>>2]>>(((IND)&3)<<1)) & ((MASK)&3))
#define SETBITS(BMAP, IND, MASK)     (((uint8_t*)(BMAP))[(IND)>>2] |=  (((MASK)&3)<<(((IND)&3)<<1)))
#define UNSETBITS(BMAP, IND, MASK)   (((uint8_t*)(BMAP))[(IND)>>2] &= ~(((MASK)&3)<<(((IND)&3)<<1)))

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

enum {
    HIST_TRIED  = 1<<0,
    HIST_DID    = 1<<1,
    HIST_MASK   = 3,
    
    HISTOP_BYTEXOR,
    HISTOP_FILEXOR,
};


typedef struct {
    uint8_t  data[LEN_CRYPT];
    //shows which bytes were changed each round
    uint32_t usedHistory;
    struct {
        uint8_t operation;
        uint8_t data[LEN_HISTORY];
    } history[MAX_HISTORY];
} CryptKey;

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