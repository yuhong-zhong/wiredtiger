/*
 * Config definitions
 */
#define FAKE_EBPF
#define EBPF_DEBUG

#define EBPF_BUFFER_SIZE 4096
#define EBPF_BLOCK_SIZE 512


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
 * Page layout
 */
 struct ebpf_page_header {
     uint64_t recno; /* 00-07: column-store starting recno */
     uint64_t write_gen; /* 08-15: write generation */
     uint32_t mem_size; /* 16-19: in-memory page size */
     union {
         uint32_t entries; /* 20-23: number of cells on page */
         uint32_t datalen; /* 20-23: overflow data length */
     } u;
     uint8_t type; /* 24: page type */
#define EBPF_PAGE_COMPRESSED 0x01u   /* Page is compressed on disk */
#define EBPF_PAGE_EMPTY_V_ALL 0x02u  /* Page has all zero-length values */
#define EBPF_PAGE_EMPTY_V_NONE 0x04u /* Page has no zero-length values */
#define EBPF_PAGE_ENCRYPTED 0x08u    /* Page is encrypted on disk */
#define EBPF_PAGE_UNUSED 0x10u       /* Historic lookaside store page updates, no longer used */
     uint8_t flags; /* 25: flags */
     uint8_t unused; /* 26: unused padding */
#define EBPF_PAGE_VERSION_ORIG 0 /* Original version */
#define EBPF_PAGE_VERSION_TS 1   /* Timestamps added */
     uint8_t version; /* 27: version */
};
#define EBPF_PAGE_HEADER_SIZE 28

struct ebpf_block_header {
    /* copy from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/block.h#L329 */

    uint32_t disk_size; /* 00-03: on-disk page size */
    uint32_t checksum; /* 04-07: checksum */
    uint8_t flags; /* 08: flags */
    uint8_t unused[3]; /* 09-11: unused padding */
};

/*
 * Cell types & macros
 * extract from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/cell.h#L10
 */
#define EBPF_CELL_SHORT_TYPE(v) ((v)&0x03U)

#define EBPF_CELL_ADDR_INT (1 << 4)
#define EBPF_CELL_TYPE_MASK (0x0fU << 4)
#define EBPF_CELL_TYPE(v) ((v)&WT_CELL_TYPE_MASK)

/* 
 * Variable-sized unpacking for unsigned integers
 * extracted from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/intpack.i#L254
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

    /* encoding scheme: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/intpack.i#L10 */
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
            return ret;
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

inline int ebpf_get_cell_type(const uint8_t *cell) {
    return WT_CELL_SHORT_TYPE(cell[0]) ? WT_CELL_SHORT_TYPE(cell[0]) : WT_CELL_TYPE(cell[0]);
}

inline int ebpf_parse_cell_addr_int(const uint8_t **cellp, uint64_t *offset, uint64_t *size, bool update_pointer) {
    const uint8_t *cell = *cellp, *p = *cellp, *addr;
    uint8_t flags;
    uint64_t addr_len;
    int ret;

    /* verify cell type & validity window & RLE in descriptor byte (1B) */
    if ((WT_CELL_SHORT_TYPE(cell[0]) != 0)
        || (WT_CELL_TYPE(cell[0]) != WT_CELL_ADDR_INT)
        || ((cell[0] & WT_CELL_64V) != 0)) {
        return -EBPF_EINVAL;
    }
    p += 1;

    if ((cell[0] & WT_CELL_SECOND_DESC) != 0) {
        /* the second descriptor byte */
        flags = *p;
        p += 1;
        if (flags != 0) {
            return -EBPF_EINVAL;
        }
    }

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

    if (update_pointer)
        *cellp = p + addr_len;
    return 0;
}

inline int 

inline int ebpf_lookup(int fd, uint64_t offset, const uint8_t *key_buf, uint64_t key_buf_size, 
                uint8_t *value_buf, uint64_t value_buf_size) {
    off_t lseek_ret;
    int read_ret;

    if (fd < 0 || key_buf == NULL || value_buf == NULL || value_buf_size < EBPF_BUFFER_SIZE) {
        printf("ebpf_lookup: illegal arguments\n");
        return -EBPF_EINVAL;
    }

    lseek_ret = lseek(fd, 0, SEEK_SET);
    if (lseek_ret != 0) {
        printf("ebpf_lookup: lseek error, errno %d, ret: %ld\n", errno, lseek_ret);
        return -EBPF_EINVAL;
    }
    read_ret = read(fd, value_buf, EBPF_BUFFER_SIZE);
    if (read_ret != EBPF_BUFFER_SIZE) {
        printf("ebpf_lookup: read error, errno %d, ret: %d\n", errno, read_ret);
        return -EBPF_EINVAL;
    }
    sprintf(value_buf, "Hongyi eats Karaage");
    return 0;
}

#endif  /* FAKE_EBPF */

/************************************************
 * FAKE_EBPF END
 ************************************************/
