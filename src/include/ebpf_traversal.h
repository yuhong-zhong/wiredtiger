/*
 * Config definitions
 */
#define FAKE_EBPF

#define EBPF_BUFFER_SIZE 4096
#define EBPF_BLOCK_SIZE 512

inline int ebpf_open_fd(const char *uri) {
    return 0;
}

/************************************************
 * FAKE_EBPF START
 * (need to port the following part to ebpf)
 ************************************************/
#ifdef FAKE_EBPF

/*
 * Error numbers
 */
#define EBPF_EINVAL 22
#define EBPF_NOT_FOUND 1

/*
 * Cell types & macros
 * extract from https://github.com/wiredtiger/wiredtiger/blob/9b32813d625d3dbdf0fd83a7eb4ce10fda0d18f3/src/include/cell.h#L10
 */
#define EBPF_CELL_SHORT_TYPE(v) ((v)&0x03U)

#define EBPF_CELL_ADDR_INT (1 << 4)
#define EBPF_CELL_TYPE_MASK (0x0fU << 4)
#define EBPF_CELL_TYPE(v) ((v)&WT_CELL_TYPE_MASK)

/* 
 * Variable-sized unpacking for unsigned integers
 * extracted from https://github.com/wiredtiger/wiredtiger/blob/9b32813d625d3dbdf0fd83a7eb4ce10fda0d18f3/src/include/intpack.i#L254
 */
#define EBPF_POS_1BYTE_MARKER (uint8_t)0x80
#define EBPF_POS_2BYTE_MARKER (uint8_t)0xc0
#define EBPF_POS_MULTI_MARKER (uint8_t)0xe0
#define EBPF_POS_1BYTE_MAX ((1 << 6) - 1)
#define EBPF_POS_2BYTE_MAX ((1 << 13) + POS_1BYTE_MAX)

/* Extract bits <start> to <end> from a value (counting from LSB == 0). */
#define GET_BITS(x, start, end) (((uint64_t)(x) & ((1U << (start)) - 1U)) >> (end))

inline int ebpf_unpack_posint(const uint8_t **pp, uint64_t *retp) {
    uint64_t x;
    uint8_t len, max_len = 16;  /* max_len is set to pass the ebpf verifier */
    const uint8_t *p;

    /* There are four length bits in the first byte. */
    p = *pp;
    len = (*p++ & 0xf);

    for (x = 0; len != 0 && max_len != 0; --len, --max_len)
        x = (x << 8) | *p++;

    *retp = x;
    *pp = p;
    return 0;
}

inline int ebpf_vunpack_uint(const uint8_t **pp, uint64_t *xp) {
    const uint8_t *p;
    int ret;

    /* encoding scheme: https://github.com/wiredtiger/wiredtiger/blob/9b32813d625d3dbdf0fd83a7eb4ce10fda0d18f3/src/include/intpack.i#L10 */
    p = *pp;
    switch (*p & 0xf0) {
    case EBPF_POS_1BYTE_MARKER:
    case EBPF_POS_1BYTE_MARKER | 0x10:
    case EBPF_POS_1BYTE_MARKER | 0x20:
    case EBPF_POS_1BYTE_MARKER | 0x30:
        /* higher 2 bits of the first byte is 10 */
        *xp = GET_BITS(*p, 6, 0);  /* extract integer from the remaining (8 - 2) = 6 bites */
        p += 1;
        break;
    case EBPF_POS_2BYTE_MARKER:
    case EBPF_POS_2BYTE_MARKER | 0x10:
        /* higher 3 bits of the first byte is 110 */
        *xp = GET_BITS(*p++, 5, 0) << 8;
        *xp |= *p++;
        *xp += EBPF_POS_1BYTE_MAX + 1;
        break;
    case EBPF_POS_MULTI_MARKER:
        /* higher 4 bits of the first byte is 1110 */
        ret = ebpf_unpack_posint(pp, xp);
        if (ret != 0) {
            return -EBPF_EINVAL;
        }
        *xp += EBPF_POS_2BYTE_MAX + 1;
        return 0;
    default:
        return -EBPF_EINVAL;
    }

    *pp = p;
    return 0;
}

inline int ebpf_addr_to_offset(const uint8_t *addr, uint64_t *offset, uint64_t *size) {
    uint64_t raw_offset, raw_size, raw_checksum;

    ebpf_vunpack_uint(&addr, &raw_offset);
    ebpf_vunpack_uint(&addr, &raw_size);
    ebpf_vunpack_uint(&addr, &raw_checksum);  /* checksum is not used */
    if (raw_size == 0) {
        *offset = 0;
        *size = 0;
    } else {
        /* assumption: allocation size is EBPF_BLOCK_SIZE */
        *offset = EBPF_BLOCK_SIZE * (raw_offset + 1);
        *size = EBPF_BLOCK_SIZE * raw_size;
    }
    return 0;
}

inline int ebpf_parse_cell_addr_int(const uint8_t *cell, uint64_t *offset, uint64_t *size) {
    const uint8_t *p = cell, *addr;
    uint64_t addr_len;
    int ret;

    /* verify cell type & validity window & RLE in descriptor byte (1B) */
    // if ((WT_CELL_SHORT_TYPE(cell[0]) != 0)
    //     || (WT_CELL_TYPE(cell[0]) != WT_CELL_ADDR_INT)
    //     || (cell[0] & WT_CELL_SECOND_DESC != 0)
    //     || (cell[0] & WT_CELL_64V != 0)) {
    //     return -EBPF_EINVAL;
    // }
    if (WT_CELL_SHORT_TYPE(cell[0]) != 0)
        return -1;
    if (WT_CELL_TYPE(cell[0]) != WT_CELL_ADDR_INT)
        return -10 - WT_CELL_TYPE(cell[0]);
    if (cell[0] & WT_CELL_SECOND_DESC != 0)
        return -3;
    if (cell[0] & WT_CELL_64V != 0)
        return -4;
    p += 1;

    /* the cell is followed by data length and a chunk of data */
    ret = ebpf_vunpack_uint(&p, &addr_len);
    if (ret != 0) {
        return ret;
    }
    addr = p;

    /* convert addr to file offset */
    ret = ebpf_addr_to_offset(addr, offset, size);
    if (ret != 0) {
        return ret;
    }

    return (p + addr_len) - cell;  /* return the size of cell + size of payload */
}

inline int ebpf_lookup(int fd, uint64_t offset, const uint8_t *key_buf, uint64_t key_buf_size, 
                uint8_t *value_buf, uint64_t value_buf_size) {
    return -EBPF_EINVAL;
}

#endif  /* FAKE_EBPF */

/************************************************
 * FAKE_EBPF END
 ************************************************/
