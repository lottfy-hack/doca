/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * DOCA RDMA Multi-Threaded Benchmark (Dynamic Threads)
 */

#define _GNU_SOURCE 
#include <sched.h>
#include <pthread.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_buf_inventory.h>
#include <doca_buf.h>
#include <doca_ctx.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "rdma_common.h"

DOCA_LOG_REGISTER(RDMA_TEST::DYNAMIC);

/* Configuration */
#define WINDOW_SIZE 64
#define TASK_POOL_SIZE 256
#define TEST_DURATION_SEC 10
#define PAYLOAD_SIZE 65536

struct worker_ctx {
    int thread_id;
    struct rdma_resources *global_res; 
    struct doca_pe *pe;
    struct doca_ctx *rdma_ctx;
    struct doca_rdma *rdma;
    struct doca_buf_inventory *buf_inv;
    const void *local_desc;
    size_t local_desc_len;
    char *remote_desc;
    size_t remote_desc_len;
    struct doca_buf *src_pool[WINDOW_SIZE];
    struct doca_buf *dst_pool[WINDOW_SIZE];
    int pool_idx;
    uint64_t completed_iters;
    bool is_running;
};

static uint64_t g_total_bytes_sent = 0;
static bool g_test_finished = false;

/* ... TCP Helper Functions (recv_blob_tcp, send_blob_tcp) 保持不变 ... */
/* 为了节省篇幅，这里省略 send_blob_tcp 和 recv_blob_tcp 的实现，请保留原有的 */
static doca_error_t send_blob_tcp(int sock, const void *data, size_t size) {
    uint32_t net_len = htonl((uint32_t)size);
    if (send(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) return DOCA_ERROR_IO_FAILED;
    if (send(sock, data, size, 0) != (ssize_t)size) return DOCA_ERROR_IO_FAILED;
    return DOCA_SUCCESS;
}

static doca_error_t recv_blob_tcp(int sock, void **data, size_t *size) {
    uint32_t net_len;
    ssize_t res;
    size_t total_received = 0;
    if (recv(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) return DOCA_ERROR_IO_FAILED;
    *size = ntohl(net_len);
    *data = malloc(*size);
    if (*data == NULL) return DOCA_ERROR_NO_MEMORY;
    while (total_received < *size) {
        res = recv(sock, (char *)(*data) + total_received, *size - total_received, 0);
        if (res <= 0) { free(*data); *data = NULL; return DOCA_ERROR_IO_FAILED; }
        total_received += res;
    }
    return DOCA_SUCCESS;
}

/* ... Worker Logic (submit_task, callbacks) 保持不变 ... */
/* 请保留之前的 reset_buf, check_completion_callback, error_callback, submit_task */
static void reset_buf(struct doca_buf *buf) {
    void *data;
    doca_buf_get_data(buf, &data);
    doca_buf_set_data(buf, data, 0);
}

static doca_error_t submit_task(struct worker_ctx *wctx);

static void check_completion_callback(struct doca_rdma_task_write *task, union doca_data task_user_data, union doca_data ctx_user_data) {
    struct worker_ctx *wctx = (struct worker_ctx *)ctx_user_data.ptr;
    doca_task_free(doca_rdma_task_write_as_task(task));
    wctx->completed_iters++;
    if (wctx->is_running) {
        doca_error_t res;
        int retries = 0;
        do {
            res = submit_task(wctx);
            if (res == DOCA_ERROR_NO_MEMORY) { doca_pe_progress(wctx->pe); retries++; }
        } while (res == DOCA_ERROR_NO_MEMORY && retries < 10);
        if (res != DOCA_SUCCESS && res != DOCA_ERROR_NO_MEMORY) wctx->is_running = false;
    }
}

static void error_callback(struct doca_rdma_task_write *task, union doca_data task_user_data, union doca_data ctx_user_data) {
    struct worker_ctx *wctx = (struct worker_ctx *)ctx_user_data.ptr;
    if (wctx->is_running) DOCA_LOG_ERR("Thread %d: Task failed", wctx->thread_id);
    wctx->is_running = false;
    doca_task_free(doca_rdma_task_write_as_task(task));
}

static doca_error_t submit_task(struct worker_ctx *wctx) {
    struct doca_rdma_task_write *task = NULL;
    union doca_data ud = {0};
    wctx->pool_idx = (wctx->pool_idx + 1) % WINDOW_SIZE;
    struct doca_buf *src = wctx->src_pool[wctx->pool_idx];
    struct doca_buf *dst = wctx->dst_pool[wctx->pool_idx];
    reset_buf(dst);
    doca_error_t res = doca_rdma_task_write_allocate_init(wctx->rdma, src, dst, ud, &task);
    if (res != DOCA_SUCCESS) return res;
    res = doca_task_submit(doca_rdma_task_write_as_task(task));
    if (res != DOCA_SUCCESS) doca_task_free(doca_rdma_task_write_as_task(task));
    return res;
}

static void *worker_thread_func(void *arg) {
    /* 保持原有的 worker 逻辑不变 */
    struct worker_ctx *wctx = (struct worker_ctx *)arg;
    doca_error_t result;
    enum doca_ctx_states state;
    
    result = doca_buf_inventory_create(TASK_POOL_SIZE * 2, &wctx->buf_inv);
    if (result != DOCA_SUCCESS) return NULL;
    doca_buf_inventory_start(wctx->buf_inv);

    result = doca_rdma_connect(wctx->rdma, wctx->remote_desc, wctx->remote_desc_len);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Thread %d connect failed", wctx->thread_id);
        return NULL;
    }

    do {
        doca_pe_progress(wctx->pe);
        doca_ctx_get_state(wctx->rdma_ctx, &state);
        if (state == DOCA_CTX_STATE_IDLE || state == DOCA_CTX_STATE_STOPPING) return NULL;
    } while (state != DOCA_CTX_STATE_RUNNING);

    char *remote_range; size_t remote_len;
    doca_mmap_get_memrange(wctx->global_res->remote_mmap, (void**)&remote_range, &remote_len);
    
    for (int i=0; i<WINDOW_SIZE; i++) {
        doca_buf_inventory_buf_get_by_data(wctx->buf_inv, wctx->global_res->mmap, wctx->global_res->mmap_memrange, PAYLOAD_SIZE, &wctx->src_pool[i]);
        doca_buf_inventory_buf_get_by_addr(wctx->buf_inv, wctx->global_res->remote_mmap, remote_range, PAYLOAD_SIZE, &wctx->dst_pool[i]);
    }

    wctx->is_running = true;
    for (int i=0; i<WINDOW_SIZE; i++) {
        if (submit_task(wctx) != DOCA_SUCCESS) { wctx->is_running = false; break; }
    }

    while (wctx->is_running && !g_test_finished) { doca_pe_progress(wctx->pe); }
    
    wctx->is_running = false;
    while (doca_pe_progress(wctx->pe) > 0);
    for (int i=0; i<WINDOW_SIZE; i++) {
        if (wctx->src_pool[i]) doca_buf_dec_refcount(wctx->src_pool[i], NULL);
        if (wctx->dst_pool[i]) doca_buf_dec_refcount(wctx->dst_pool[i], NULL);
    }
    return NULL;
}

/* ================= Modified Handshake (Dynamic Size) ================= */

static doca_error_t setup_multi_qp_handshake(struct rdma_resources *res, struct worker_ctx *workers, int num_threads) {
    int sock;
    struct sockaddr_in s_addr;
    const char *ip = res->cfg->ip_address;
    int port = res->cfg->port;

    DOCA_LOG_INFO("Connecting to Responder %s:%d...", ip, port);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return DOCA_ERROR_IO_FAILED;

    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &s_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
        close(sock);
        return DOCA_ERROR_IO_FAILED;
    }

    /* Send Thread Count first to check sync (Optional but recommended) */
    // For simplicity, we assume user ran both sides with same -t flag.

    /* 1. Recv N descriptors */
    for (int i=0; i<num_threads; i++) {
        if (recv_blob_tcp(sock, (void**)&workers[i].remote_desc, &workers[i].remote_desc_len) != DOCA_SUCCESS) return DOCA_ERROR_IO_FAILED;
    }
    
    if (recv_blob_tcp(sock, (void**)&res->remote_mmap_descriptor, &res->remote_mmap_descriptor_size) != DOCA_SUCCESS) return DOCA_ERROR_IO_FAILED;

    /* 2. Send N descriptors */
    for (int i=0; i<num_threads; i++) {
        if (send_blob_tcp(sock, workers[i].local_desc, workers[i].local_desc_len) != DOCA_SUCCESS) return DOCA_ERROR_IO_FAILED;
    }

    close(sock);
    return DOCA_SUCCESS;
}

/* ================= Modified Main Entry Point ================= */

doca_error_t rdma_write_requester(struct rdma_config *cfg)
{
    struct rdma_resources shared_res = {0};
    int n_threads = cfg->num_threads; // 从配置中读取
    
    /* === 动态分配内存 === */
    struct worker_ctx *workers = calloc(n_threads, sizeof(struct worker_ctx));
    pthread_t *threads = calloc(n_threads, sizeof(pthread_t));
    
    if (!workers || !threads) {
        DOCA_LOG_ERR("Failed to allocate memory for workers");
        return DOCA_ERROR_NO_MEMORY;
    }

    doca_error_t res;

    res = allocate_rdma_resources(cfg, DOCA_ACCESS_FLAG_LOCAL_READ_WRITE, DOCA_ACCESS_FLAG_LOCAL_READ_WRITE, 
                                  doca_rdma_cap_task_write_is_supported, &shared_res);
    if (res != DOCA_SUCCESS) goto cleanup;

    DOCA_LOG_INFO("Initializing %d Threads/QPs (Pool Size=%d)...", n_threads, TASK_POOL_SIZE);

    for (int i=0; i<n_threads; i++) {
        workers[i].thread_id = i;
        workers[i].global_res = &shared_res;
        
        doca_pe_create(&workers[i].pe);
        doca_rdma_create(shared_res.doca_device, &workers[i].rdma);
        workers[i].rdma_ctx = doca_rdma_as_ctx(workers[i].rdma);
        doca_pe_connect_ctx(workers[i].pe, workers[i].rdma_ctx);
        
        res = doca_rdma_task_write_set_conf(workers[i].rdma, check_completion_callback, error_callback, TASK_POOL_SIZE);
        if (res != DOCA_SUCCESS) goto cleanup;

        union doca_data ud = {.ptr = &workers[i]};
        doca_ctx_set_user_data(workers[i].rdma_ctx, ud);

        res = doca_ctx_start(workers[i].rdma_ctx);
        if (res != DOCA_SUCCESS && res != DOCA_ERROR_IN_PROGRESS) goto cleanup;

        res = doca_rdma_export(workers[i].rdma, &workers[i].local_desc, &workers[i].local_desc_len);
        if (res != DOCA_SUCCESS) goto cleanup;
    }

    /* 传递 n_threads 到握手函数 */
    res = setup_multi_qp_handshake(&shared_res, workers, n_threads);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Handshake failed.");
        goto cleanup;
    }

    doca_mmap_create_from_export(NULL, shared_res.remote_mmap_descriptor, shared_res.remote_mmap_descriptor_size,
                                 shared_res.doca_device, &shared_res.remote_mmap);

    DOCA_LOG_INFO("Starting Benchmark...");
    for (int i=0; i<n_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread_func, &workers[i]);
    }

    for (int t=0; t<TEST_DURATION_SEC; t++) {
        sleep(1);
        uint64_t current_total = 0;
        for (int i=0; i<n_threads; i++) current_total += workers[i].completed_iters;
        
        uint64_t diff = current_total - g_total_bytes_sent; 
        double gbps = (double)diff * PAYLOAD_SIZE * 8.0 / 1e9;
        
        DOCA_LOG_INFO("[T=%d] Aggregate BW: %.2f Gbps", t+1, gbps);
        g_total_bytes_sent = current_total;
    }

    g_test_finished = true;
    for (int i=0; i<n_threads; i++) pthread_join(threads[i], NULL);

    DOCA_LOG_INFO("Test Finished.");
    res = DOCA_SUCCESS;

cleanup:
    free(workers);
    free(threads);
    // 这里省略了 DOCA 对象的 destroy，实际产品代码需要添加
    return res;
}