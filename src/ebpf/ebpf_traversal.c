#include "wt_internal.h"

int ebpf_get_cell_type(uint8_t *cell) {
    return EBPF_CELL_SHORT_TYPE(cell[0]) ? EBPF_CELL_SHORT_TYPE(cell[0]) : EBPF_CELL_TYPE(cell[0]);
}

int ebpf_lookup_real(int fd, uint64_t offset, uint8_t *key_buf, uint64_t key_size, 
                     uint8_t *data_buf, uint8_t *scratch_buf, uint8_t **page_data_arr_p,
                     uint64_t *child_index_arr, int *nr_page) {
    struct wt_ebpf_scratch *scratch = (struct wt_ebpf_scratch *) scratch_buf;
    int i, ret;
    struct timespec start_ts, end_ts;
    if (clock_gettime(CLOCK_REALTIME, &start_ts) == -1) {
        printf("clock_gettime failed\n");
    }

    if (key_size > EBPF_KEY_MAX_LEN) {
        printf("ebpf_lookup_real: key size is too large\n");
        return -EBPF_EINVAL;
    }

    /* initialize data buf & scratch buf */
    memset(data_buf, 0, 4096);
    memset(scratch_buf, 0, 4096);
    scratch->key_size = key_size;
    memcpy(scratch->key, key_buf, key_size);

    /* call xrp read */
    ret = syscall(__NR_imposter_pread, fd, data_buf, scratch_buf, EBPF_BLOCK_SIZE, offset);
    if (ret != EBPF_BLOCK_SIZE) {
        printf("ebpf_lookup: imposter pread failed, ret %d\n", ret);
        return ret;
    }

    /* parse result */
    *page_data_arr_p = scratch_buf + 1024;
    *nr_page = scratch->nr_page;
    for (i = 0; i < *nr_page; ++i) {
        child_index_arr[i] = scratch->descent_index_arr[i];
    }
    if (clock_gettime(CLOCK_REALTIME, &end_ts) == -1) {
        printf("clock_gettime failed\n");
    }
    atomic_fetch_add(&bpf_io_time, (end_ts.tv_sec * 1000000000L + end_ts.tv_nsec) - (start_ts.tv_sec * 1000000000L + start_ts.tv_nsec));
    atomic_fetch_add(&bpf_io_count, 1);
    return 0;
}
