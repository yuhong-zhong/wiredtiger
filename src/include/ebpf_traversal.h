/*
 * Config definitions
 */
#define FAKE_EBPF
// #define EBPF_DEBUG

#define EBPF_BUFFER_SIZE 4096
#define EBPF_SCRATCH_BUFFER_SIZE 8192
#define EBPF_BLOCK_SIZE 512
/* page is always block size */
#define EBPF_MAX_DEPTH 16
#define EBPF_KEY_MAX_LEN 64

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

#define EBPF_PAGE_INVALID 0       /* Invalid page */
#define EBPF_PAGE_BLOCK_MANAGER 1 /* Block-manager page */
#define EBPF_PAGE_COL_FIX 2       /* Col-store fixed-len leaf */
#define EBPF_PAGE_COL_INT 3       /* Col-store internal page */
#define EBPF_PAGE_COL_VAR 4       /* Col-store var-length leaf page */
#define EBPF_PAGE_OVFL 5          /* Overflow page */
#define EBPF_PAGE_ROW_INT 6       /* Row-store internal page */
#define EBPF_PAGE_ROW_LEAF 7      /* Row-store leaf page */

struct ebpf_block_header {
    /* copy from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/block.h#L329 */

    uint32_t disk_size; /* 00-03: on-disk page size */
    uint32_t checksum; /* 04-07: checksum */
    uint8_t flags; /* 08: flags */
    uint8_t unused[3]; /* 09-11: unused padding */
};
#define EBPF_BLOCK_HEADER_SIZE 12

/*
 * Cell types & macros
 * extract from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/cell.h#L10
 */
#define EBPF_CELL_KEY_SHORT 0x01     /* Short key */
#define EBPF_CELL_KEY_SHORT_PFX 0x02 /* Short key with prefix byte */
#define EBPF_CELL_VALUE_SHORT 0x03   /* Short data */
#define EBPF_CELL_SHORT_TYPE(v) ((v)&0x03U)

#define EBPF_CELL_SHORT_MAX 63  /* Maximum short key/value */
#define EBPF_CELL_SHORT_SHIFT 2 /* Shift for short key/value */

#define EBPF_CELL_64V 0x04         /* Associated value */
#define EBPF_CELL_SECOND_DESC 0x08 /* Second descriptor byte */

#define EBPF_CELL_ADDR_DEL (0)            /* Address: deleted */
#define EBPF_CELL_ADDR_INT (1 << 4)       /* Address: internal  */
#define EBPF_CELL_ADDR_LEAF (2 << 4)      /* Address: leaf */
#define EBPF_CELL_ADDR_LEAF_NO (3 << 4)   /* Address: leaf no overflow */
#define EBPF_CELL_DEL (4 << 4)            /* Deleted value */
#define EBPF_CELL_KEY (5 << 4)            /* Key */
#define EBPF_CELL_KEY_OVFL (6 << 4)       /* Overflow key */
#define EBPF_CELL_KEY_OVFL_RM (12 << 4)   /* Overflow key (removed) */
#define EBPF_CELL_KEY_PFX (7 << 4)        /* Key with prefix byte */
#define EBPF_CELL_VALUE (8 << 4)          /* Value */
#define EBPF_CELL_VALUE_COPY (9 << 4)     /* Value copy */
#define EBPF_CELL_VALUE_OVFL (10 << 4)    /* Overflow value */
#define EBPF_CELL_VALUE_OVFL_RM (11 << 4) /* Overflow value (removed) */

#define EBPF_CELL_TYPE_MASK (0x0fU << 4)
#define EBPF_CELL_TYPE(v) ((v)&EBPF_CELL_TYPE_MASK)

#define EBPF_CELL_SIZE_ADJUST (EBPF_CELL_SHORT_MAX + 1)

/*
 * Variable-sized unpacking for unsigned integers
 * extracted from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/intpack.i#L254
 */
#define EBPF_POS_1BYTE_MARKER (uint8_t)0x80
#define EBPF_POS_2BYTE_MARKER (uint8_t)0xc0
#define EBPF_POS_MULTI_MARKER (uint8_t)0xe0
#define EBPF_POS_1BYTE_MAX ((1 << 6) - 1)
#define EBPF_POS_2BYTE_MAX ((1 << 13) + EBPF_POS_1BYTE_MAX)

/* Extract bits <start> to <end> from a value (counting from LSB == 0). */
#define GET_BITS(x, start, end) (((uint64_t)(x) & ((1U << (start)) - 1U)) >> (end))

inline int ebpf_lex_compare(uint8_t *key_1, uint64_t key_len_1,
                            uint8_t *key_2, uint64_t key_len_2) {
    /* extracted from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/btree_cmp.i#L90 
     * ( might consider replace with vector operation :) although not sure whether ebpf supports it )
     */
    uint64_t len = (key_len_1 > key_len_2) ? key_len_2 : key_len_1, max_len = EBPF_KEY_MAX_LEN;
    for (; len > 0 && max_len > 0; --len, --max_len, ++key_1, ++key_2)
        if (*key_1 != *key_2)
            return (*key_1 < *key_2 ? -1 : 1);
    return ((key_len_1 == key_len_2) ? 0 : (key_len_1 < key_len_2) ? -1 : 1);
}

inline int ebpf_unpack_posint(uint8_t **pp, uint64_t *retp) {
    uint64_t x;
    uint8_t len, max_len = 16;  /* max_len is set to pass the ebpf verifier */
    uint8_t *p;

    /* There are four length bits in the first byte. */
    p = *pp;
    len = (*p++ & 0xf);

    for (x = 0; len != 0 && max_len != 0; --len, --max_len)
        x = (x << 8) | *p++;

    *retp = x;
    *pp = p;
    return 0;
}

static inline int ebpf_vunpack_uint(uint8_t **pp, uint64_t *xp) {
    uint8_t *p;
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

inline int ebpf_addr_to_offset(uint8_t *addr, uint64_t *offset, uint64_t *size) {
    int ret;
    uint64_t raw_offset, raw_size, raw_checksum;

    ret = ebpf_vunpack_uint(&addr, &raw_offset);
    if (ret < 0)
        return ret;
    ret = ebpf_vunpack_uint(&addr, &raw_size);
    if (ret < 0)
        return ret;
    ret = ebpf_vunpack_uint(&addr, &raw_checksum);  /* checksum is not used */
    if (ret < 0)
        return ret;
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

inline int ebpf_get_cell_type(uint8_t *cell) {
    return EBPF_CELL_SHORT_TYPE(cell[0]) ? EBPF_CELL_SHORT_TYPE(cell[0]) : EBPF_CELL_TYPE(cell[0]);
}

inline int ebpf_parse_cell_addr(uint8_t **cellp, uint64_t *offset, uint64_t *size, 
                                bool update_pointer) {
    uint8_t *cell = *cellp, *p = *cellp, *addr;
    uint8_t flags;
    uint64_t addr_len;
    int ret;

    /* read the first cell descriptor byte (cell type, RLE count) */
    if ((ebpf_get_cell_type(cell) != EBPF_CELL_ADDR_INT
         && ebpf_get_cell_type(cell) != EBPF_CELL_ADDR_LEAF
         && ebpf_get_cell_type(cell) != EBPF_CELL_ADDR_LEAF_NO)
        || ((cell[0] & EBPF_CELL_64V) != 0)) {
        return -EBPF_EINVAL;
    }
    p += 1;

    /* read the second cell descriptor byte (if present) */
    if ((cell[0] & EBPF_CELL_SECOND_DESC) != 0) {
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

inline int ebpf_parse_cell_key(uint8_t **cellp, uint8_t **key, uint64_t *key_size, 
                               bool update_pointer) {
    uint8_t *cell = *cellp, *p = *cellp;
    uint64_t data_len;
    int ret;

    /* read the first cell descriptor byte (cell type, RLE count) */
    if ((ebpf_get_cell_type(cell) != EBPF_CELL_KEY)
        || ((cell[0] & EBPF_CELL_64V) != 0)) {
        return -EBPF_EINVAL;
    }
    p += 1;

    /* key cell does not have the second descriptor byte */

    /* the cell is followed by data length and a chunk of data */
    ret = ebpf_vunpack_uint(&p, &data_len);
    if (ret != 0) {
        return ret;
    }
    data_len += EBPF_CELL_SIZE_ADJUST;

    *key = p;
    *key_size = data_len;

    if (update_pointer)
        *cellp = p + data_len;
    return 0;
}

inline int ebpf_parse_cell_short_key(uint8_t **cellp, uint8_t **key, uint64_t *key_size, 
                                     bool update_pointer) {
    uint8_t *cell = *cellp, *p = *cellp;
    uint64_t data_len;

    /* read the first cell descriptor byte */
    if (ebpf_get_cell_type(cell) != EBPF_CELL_KEY_SHORT) {
        return -EBPF_EINVAL;
    }
    data_len = cell[0] >> EBPF_CELL_SHORT_SHIFT;
    *key_size = data_len;

    p += 1;
    *key = p;

    if (update_pointer)
        *cellp = p + data_len;
    return 0;
}

inline int ebpf_parse_cell_value(uint8_t **cellp, uint8_t **value, uint64_t *value_size, 
                                 bool update_pointer) {
    uint8_t *cell = *cellp, *p = *cellp;
    uint8_t flags;
    uint64_t data_len;
    int ret;

    /* read the first cell descriptor byte (cell type, RLE count) */
    if ((ebpf_get_cell_type(cell) != EBPF_CELL_VALUE)
        || ((cell[0] & EBPF_CELL_64V) != 0)) {
        return -EBPF_EINVAL;
    }
    p += 1;

    /* read the second cell descriptor byte (if present) */
    if ((cell[0] & EBPF_CELL_SECOND_DESC) != 0) {
        flags = *p;
        p += 1;
        if (flags != 0) {
            return -EBPF_EINVAL;
        }
    }

    /* the cell is followed by data length and a chunk of data */
    ret = ebpf_vunpack_uint(&p, &data_len);
    if (ret != 0) {
        return ret;
    }
    if ((cell[0] & EBPF_CELL_SECOND_DESC) == 0) {
        data_len += EBPF_CELL_SIZE_ADJUST;
    }

    *value = p;
    *value_size = data_len;

    if (update_pointer)
        *cellp = p + data_len;
    return 0;
}

inline int ebpf_parse_cell_short_value(uint8_t **cellp, uint8_t **value, uint64_t *value_size, 
                                       bool update_pointer) {
    uint8_t *cell = *cellp, *p = *cellp;
    uint64_t data_len;

    /* read the first cell descriptor byte */
    if (ebpf_get_cell_type(cell) != EBPF_CELL_VALUE_SHORT) {
        return -EBPF_EINVAL;
    }
    data_len = cell[0] >> EBPF_CELL_SHORT_SHIFT;
    *value_size = data_len;

    p += 1;
    *value = p;

    if (update_pointer)
        *cellp = p + data_len;
    return 0;
}

inline int ebpf_get_page_type(uint8_t *page_image) {
    struct ebpf_page_header *header = (struct ebpf_page_header *)page_image;  /* page disk image starts with page header */
    return header->type;
}

/*
__wt_page_inmem: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/btree/bt_page.c#L128
__inmem_row_int: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/btree/bt_page.c#L375
WT_CELL_FOREACH_ADDR: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/cell.i#L1155
__wt_cell_unpack_safe: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/cell.i#L663
__wt_row_search: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/btree/row_srch.c#L331
*/
static inline int ebpf_search_int_page(uint8_t *page_image, 
                                       uint8_t *user_key_buf, uint64_t user_key_size,
                                       uint64_t *descent_offset, uint64_t *descent_size, uint64_t *descent_index) {
    uint8_t *p = page_image;
    struct ebpf_page_header *header = (struct ebpf_page_header *)page_image;
    uint32_t nr_kv = header->u.entries / 2, i, ii;
    uint64_t prev_cell_descent_offset = 0, prev_cell_descent_size = 0;
    int ret;

    if (page_image == NULL
        || user_key_buf == NULL
        || user_key_size == 0
        || ebpf_get_page_type(page_image) != EBPF_PAGE_ROW_INT
        || descent_offset == NULL
        || descent_size == NULL) {
        printf("ebpf_search_int_page: invalid arguments\n");
        return -EBPF_EINVAL;
    }

    /* skip page header + block header */
    p += (EBPF_PAGE_HEADER_SIZE + EBPF_BLOCK_HEADER_SIZE);

    /* traverse all key value pairs */
    for (i = 0, ii = EBPF_BLOCK_SIZE; i < nr_kv && ii > 0; ++i, --ii) {
        uint8_t *cell_key_buf;
        uint64_t cell_key_size;
        uint64_t cell_descent_offset, cell_descent_size;
        int cmp;

        /*
         * searching for the corresponding descent.
         * each cell (key, addr) corresponds to key range [key, next_key)
         * extracted from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/btree/row_srch.c#L331
         */

        /* parse key cell */
        switch (ebpf_get_cell_type(p)) {
        case EBPF_CELL_KEY:
            ret = ebpf_parse_cell_key(&p, &cell_key_buf, &cell_key_size, true);
            if (ret < 0) {
                printf("ebpf_search_int_page: ebpf_parse_cell_key failed, kv %d, offset %d, ret %d\n", i, (uint64_t)(p - page_image), ret);
                return ret;
            }
            break;
        case EBPF_CELL_KEY_SHORT:
            ret = ebpf_parse_cell_short_key(&p, &cell_key_buf, &cell_key_size, true);
            if (ret < 0) {
                printf("ebpf_search_int_page: ebpf_parse_cell_short_key failed, kv %d, offset %d, ret %d\n", i, (uint64_t)(p - page_image), ret);
                return ret;
            }
            break;
        default:
            printf("ebpf_search_int_page: invalid cell type %d, kv %d, offset %d\n", ebpf_get_cell_type(p), i, (uint64_t)(p - page_image));
            return -EBPF_EINVAL;
        }
        /* parse addr cell */
        ret = ebpf_parse_cell_addr(&p, &cell_descent_offset, &cell_descent_size, true);
        if (ret < 0) {
            printf("ebpf_search_int_page: ebpf_parse_cell_addr failed, kv %d, offset %d, ret %d\n", i, (uint64_t)(p - page_image), ret);
            return ret;
        }

        /*
         * compare with user key
         * extracted from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/btree/row_srch.c#L331
         */
        if (i == 0)
            cmp = 1;  /* 0-th key is MIN */
        else
            cmp = ebpf_lex_compare(user_key_buf, user_key_size, cell_key_buf, cell_key_size);
        if (cmp == 0) {
            /* user key = cell key */
            *descent_offset = cell_descent_offset;
            *descent_size = cell_descent_size;
            *descent_index = i;
            return 0;
        } else if (cmp < 0) {
            /* user key < cell key */
            *descent_offset = prev_cell_descent_offset;
            *descent_size = prev_cell_descent_size;
            *descent_index = i - 1;
            return 0;
        }
        prev_cell_descent_offset = cell_descent_offset;
        prev_cell_descent_size = cell_descent_size;
    }
    *descent_offset = prev_cell_descent_offset;
    *descent_size = prev_cell_descent_size;
    *descent_index = i - 1;
    return 0;
}

/*
__wt_page_inmem: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/btree/bt_page.c#L128
__inmem_row_leaf_entries: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/btree/bt_page.c#L492
__inmem_row_leaf: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/btree/bt_page.c#L532
WT_CELL_FOREACH_KV: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/cell.i#L1163
__wt_cell_unpack_safe: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/cell.i#L663
__wt_row_search: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/btree/row_srch.c#L331
wt_row: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/btmem.h#L953
    https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/btree.i#L885
*/
static inline int ebpf_search_leaf_page(uint8_t *page_image, 
                                        uint8_t *user_key_buf, uint64_t user_key_size,
                                        uint8_t **value_buf, uint64_t *value_size, uint64_t *descent_index) {
    uint8_t *p = page_image;
    struct ebpf_page_header *header = (struct ebpf_page_header *)page_image;
    uint32_t nr_cell = header->u.entries, i, ii, k;
    int ret;

    if (page_image == NULL
        || user_key_buf == NULL
        || user_key_size == 0
        || ebpf_get_page_type(page_image) != EBPF_PAGE_ROW_LEAF
        || value_buf == NULL
        || value_size == NULL) {
        printf("ebpf_search_leaf_page: invalid arguments\n");
        return -EBPF_EINVAL;
    }

    /* skip page header + block header */
    p += (EBPF_PAGE_HEADER_SIZE + EBPF_BLOCK_HEADER_SIZE);

    /* traverse all key value pairs */
    for (i = 0, ii = EBPF_BLOCK_SIZE, k = 0; i < nr_cell && ii > 0; ++i, --ii, ++k) {
        uint8_t *cell_key_buf;
        uint64_t cell_key_size;
        uint8_t *cell_value_buf;
        uint64_t cell_value_size;
        int cmp;

        /* parse key cell */
        switch (ebpf_get_cell_type(p)) {
        case EBPF_CELL_KEY:
            ret = ebpf_parse_cell_key(&p, &cell_key_buf, &cell_key_size, true);
            if (ret < 0) {
                printf("ebpf_search_leaf_page: ebpf_parse_cell_key failed, cell %d, offset %d, ret %d\n", i, (uint64_t)(p - page_image), ret);
                return ret;
            }
            break;
        case EBPF_CELL_KEY_SHORT:
            ret = ebpf_parse_cell_short_key(&p, &cell_key_buf, &cell_key_size, true);
            if (ret < 0) {
                printf("ebpf_search_leaf_page: ebpf_parse_cell_short_key failed, cell %d, offset %d, ret %d\n", i, (uint64_t)(p - page_image), ret);
                return ret;
            }
            break;
        default:
            printf("ebpf_search_leaf_page: invalid cell type %d, cell %d, offset %d\n", ebpf_get_cell_type(p), i, (uint64_t)(p - page_image));
            return -EBPF_EINVAL;
        }

        /* parse value cell */
        switch (ebpf_get_cell_type(p)) {  // TODO: potential out of bound
        case EBPF_CELL_VALUE:
            ret = ebpf_parse_cell_value(&p, &cell_value_buf, &cell_value_size, true);
            if (ret < 0) {
                printf("ebpf_search_leaf_page: ebpf_parse_cell_value failed, cell %d, offset %d, ret %d\n", i, (uint64_t)(p - page_image), ret);
                return ret;
            }
            ++i;
            break;
        case EBPF_CELL_VALUE_SHORT:
            ret = ebpf_parse_cell_short_value(&p, &cell_value_buf, &cell_value_size, true);
            if (ret < 0) {
                printf("ebpf_search_leaf_page: ebpf_parse_cell_short_value failed, cell %d, offset %d, ret %d\n", i, (uint64_t)(p - page_image), ret);
                return ret;
            }
            ++i;
            break;
        default:
            /* empty value */
            cell_value_buf = NULL;
            cell_value_size = 0;
        }

        cmp = ebpf_lex_compare(user_key_buf, user_key_size, cell_key_buf, cell_key_size);
        if (cmp == 0) {
            /* user key = cell key */
            *value_buf = cell_value_buf;
            *value_size = cell_value_size;
            *descent_index = k;
            return 0;
        } else if (cmp < 0) {
            /* user key < cell key */
            break;
        }
    }
    return EBPF_NOT_FOUND;  /* need to return a positive value */
}

static inline void ebpf_dump_page(uint8_t *page_image, uint64_t page_offset) {
    int row, column, addr;
    printf("=============================EBPF PAGE DUMP START=============================\n");
    for (row = 0; row < EBPF_BLOCK_SIZE / 16; ++row) {
        printf("%08lx  ", page_offset + 16 * row);
        for (column = 0; column < 16; ++column) {
            addr = 16 * row + column;
            printf("%02x ", page_image[addr]);
            if (column == 7 || column == 15) {
                printf(" ");
            }
        }
        printf("|");
        for (column = 0; column < 16; ++column) {
            addr = 16 * row + column;
            if (page_image[addr] >= '!' && page_image[addr] <= '~') {
                printf("%c", page_image[addr]);
            } else {
                printf(".");
            }
        }
        printf("|\n");
    }
    printf("==============================EBPF PAGE DUMP END==============================\n");
}

inline int ebpf_lookup_fake(int fd, uint64_t offset, uint8_t *key_buf, uint64_t key_buf_size, 
                            uint8_t *value_buf, uint64_t value_buf_size, uint8_t *page_data_arr,
                            uint64_t *child_index_arr, int *nr_page) {
    uint64_t page_offset = offset, page_size = EBPF_BLOCK_SIZE;
    uint8_t *page_value_buf;
    uint64_t page_value_size;
    int depth;
    int ret;
    uint64_t child_index;

    if (fd < 0
        || key_buf == NULL
        || key_buf_size == 0
        || value_buf == NULL
        || value_buf_size < EBPF_BUFFER_SIZE) {
        printf("ebpf_lookup: illegal arguments\n");
        return -EBPF_EINVAL;
    }

    for (depth = 0; depth < EBPF_MAX_DEPTH; ++depth) {
        /* read page into memory */
        ret = pread(fd, value_buf, EBPF_BLOCK_SIZE, page_offset);
        if (ret != EBPF_BLOCK_SIZE) {
            printf("ebpf_lookup: pread failed at %ld with errno %d, depth %d\n", offset, errno, depth);
            return -EBPF_EINVAL;
        }
        memcpy(&page_data_arr[EBPF_BLOCK_SIZE * depth], value_buf, EBPF_BLOCK_SIZE);

        /* search page */
        switch (ebpf_get_page_type(value_buf)) {
        case EBPF_PAGE_ROW_INT:
            ret = ebpf_search_int_page(value_buf, key_buf, key_buf_size, &page_offset, &page_size, &child_index);
            if (ret < 0) {
                printf("ebpf_lookup: ebpf_search_int_page failed, depth %d\n", depth);
                ebpf_dump_page(value_buf, page_offset);
                return -EBPF_EINVAL;
            }
            if (page_size != EBPF_BLOCK_SIZE) {
                printf("ebpf_lookup: wrong page size %ld, depth %d\n", page_size, depth);
                ebpf_dump_page(value_buf, page_offset);
                return -EBPF_EINVAL;
            }
            child_index_arr[depth] = child_index;
            break;

        case EBPF_PAGE_ROW_LEAF:
            ret = ebpf_search_leaf_page(value_buf, key_buf, key_buf_size, &page_value_buf, &page_value_size, &child_index);
            if (ret < 0) {
                printf("ebpf_lookup: ebpf_search_leaf_page failed, depth: %d, fd: %d, offset: 0x%lx\n", depth, fd, page_offset);
                ebpf_dump_page(value_buf, page_offset);
                return -EBPF_EINVAL;
            }
            if (ret == 0) {
                if (page_value_size > value_buf_size) {
                    printf("ebpf_lookup: value too large\n");
                    return -EBPF_EINVAL;
                }
                if (page_value_size > 0)
                    memmove(value_buf, page_value_buf, page_value_size);
                else
                    value_buf[0] = '\0';  /* empty value */
            }
            child_index_arr[depth] = child_index;
            *nr_page = depth + 1;
            return ret;

        default:
            printf("ebpf_lookup: unsupported page type %d\n", ebpf_get_page_type(value_buf));
        }
    }
    printf("ebpf_lookup: unfinished lookup\n");
    /* too many levels / no leaf page */
    return -EBPF_EINVAL;
}

#define __NR_imposter_pread 442

inline int ebpf_lookup_real(int fd, uint64_t offset, uint8_t *key_buf, uint64_t key_size, 
                            uint8_t *value_buf, uint64_t value_buf_size) {
    int ret;
    if (key_size > value_buf_size) {
        printf("ebpf_lookup: key_size > value_buf_size\n");
        return -EBPF_EINVAL;
    }
    memcpy(value_buf, key_buf, key_size);

    ret = syscall(__NR_imposter_pread, fd, value_buf, EBPF_BLOCK_SIZE, offset);
    if (ret != EBPF_BLOCK_SIZE) {
        printf("ebpf_lookup: imposter pread failed, ret %d\n", ret);
        return ret;
    }
    if (value_buf[0] == '\0') {
        if (value_buf[1] == 'e') {
            /* empty value */
        } else if (value_buf[1] == 'n') {
            /* not found */
            return EBPF_NOT_FOUND;
        }
    }
    return 0;
}
