/*
 * Config definitions
 */

#define EBPF_BUFFER_SIZE 4096
#define EBPF_EXTRA_BUFFER_SIZE 8192
#define EBPF_BLOCK_SIZE 512
/* page is always block size */
#define EBPF_MAX_DEPTH 6
#define EBPF_KEY_MAX_LEN 18

/*
 * Error numbers
 */
#define EBPF_EINVAL 22
#define EBPF_NOT_FOUND 1

/*
 * Cell types & macros
 * extract from https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/cell.h#L10
 */
#define EBPF_CELL_SHORT_TYPE(v) ((v)&0x03U)
#define EBPF_CELL_TYPE(v) ((v)&EBPF_CELL_TYPE_MASK)

#define __NR_imposter_pread 445

int ebpf_lookup_real(int fd, uint64_t offset, uint8_t *key_buf, uint64_t key_size, 
                     uint8_t *data_buf, uint8_t *scratch_buf, uint8_t **page_data_arr_p,
                     uint64_t *child_index_arr, int *nr_page);

struct wt_ebpf_scratch {
    uint64_t key_size;
    char key[EBPF_KEY_MAX_LEN];

    int32_t level;
    int32_t iteration;
    uint64_t page_offset;
    uint64_t prev_cell_descent_offset, prev_cell_descent_size;

    int32_t nr_page;
    uint64_t descent_index_arr[EBPF_MAX_DEPTH];
};
