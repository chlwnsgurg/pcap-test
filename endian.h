#define LITTLE_TO_BIG_ENDIAN_16(x) ( \
    ((((x) >> 8) & 0x00FF) | \
     (((x) << 8) & 0xFF00)) )
#define LITTLE_TO_BIG_ENDIAN_32(x) ( \
    ((((x) >> 24) & 0x000000FF) | \
     (((x) >> 8)  & 0x0000FF00) | \
     (((x) << 8)  & 0x00FF0000) | \
     (((x) << 24) & 0xFF000000)) )