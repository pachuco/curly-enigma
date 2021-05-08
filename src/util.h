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
#define FT_DEFINE(PATH) {{0}, 0, PATH}

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

bool openFileThing(FileThing* ft, int accessFlags);
void closeFileThing(FileThing* ft);
bool writeCryptkeyAndHistoryPixelmap(CryptKey* ck, char* outPath);