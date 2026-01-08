/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * DOCA RDMA Write Bandwidth Benchmark Sample (Time-Based + Warmup Logic)
 * Features:
 * 1. Time-based duration
 * 2. Automatic Warm-up exclusion for accurate AVG calculation
 * 3. Pipeline Windowing
 */

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

DOCA_LOG_REGISTER(RDMA_WRITE_REQUESTER::BW_TEST);

/* --- Test Configuration --- */
#define WARMUP_SECONDS 2        // 预热时间 (不计入最终结果)
#define BENCHMARK_SECONDS 10    // 正式测试时间
#define WINDOW_SIZE 128         // 并发窗口
#define MAX_TASK_POOL_SIZE 512  // 任务池大小

/* Global State */
static size_t g_payload_size = 0;
static uint64_t g_completed_iters = 0;

/* Statistics State */
static struct timespec g_start_time_abs;  // 程序绝对开始时间
static struct timespec g_last_report_time;// 上次打印日志的时间
static uint64_t g_last_report_iters = 0;  // 上次打印时的包数

/* Warmup Logic State */
static bool g_warmup_done = false;
static struct timespec g_valid_start_time; // 预热结束、正式开始的时间
static uint64_t g_valid_start_iters = 0;   // 预热结束时的已传包数

static bool g_is_draining = false;

/* Buffer Pools */
static struct doca_buf *g_src_buf_pool[WINDOW_SIZE];
static struct doca_buf *g_dst_buf_pool[WINDOW_SIZE];
static int g_pool_idx = 0;

/* Forward Declaration */
static doca_error_t submit_write_task(struct rdma_resources *resources);

/* ================= TCP Helper Functions ================= */
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

static doca_error_t exchange_descriptors_tcp_client(struct rdma_resources *resources) {
    int sock;
    struct sockaddr_in server_addr;
    doca_error_t result = DOCA_SUCCESS;
    const char *server_ip = resources->cfg->ip_address;
    uint16_t port = resources->cfg->port;

    DOCA_LOG_INFO("Connecting to %s:%d...", server_ip, port);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return DOCA_ERROR_IO_FAILED;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) { close(sock); return DOCA_ERROR_INVALID_VALUE; }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) { close(sock); return DOCA_ERROR_IO_FAILED; }
    
    result = recv_blob_tcp(sock, &resources->remote_rdma_conn_descriptor, &resources->remote_rdma_conn_descriptor_size);
    if (result == DOCA_SUCCESS) result = recv_blob_tcp(sock, &resources->remote_mmap_descriptor, &resources->remote_mmap_descriptor_size);
    if (result == DOCA_SUCCESS) result = send_blob_tcp(sock, resources->rdma_conn_descriptor, resources->rdma_conn_descriptor_size);
    
    close(sock);
    return result;
}

/* ================= Core Logic ================= */

static void reset_buf_data_len(struct doca_buf *buf) {
    void *data;
    doca_buf_get_data(buf, &data);
    doca_buf_set_data(buf, data, 0);
}

/* Helper: Get time in seconds */
static double get_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Helper: Get timespec as double */
static double timespec_to_sec(struct timespec ts) {
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void rdma_write_completed_callback(struct doca_rdma_task_write *rdma_write_task,
                                          union doca_data task_user_data, union doca_data ctx_user_data)
{
    struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
    
    doca_task_free(doca_rdma_task_write_as_task(rdma_write_task));
    resources->num_remaining_tasks--;
    g_completed_iters++;

    double current_time = get_time_sec();
    double abs_start_sec = timespec_to_sec(g_start_time_abs);
    double elapsed_since_start = current_time - abs_start_sec;

    /* --- Logic 1: Handle Warmup Transition --- */
    if (!g_warmup_done) {
        if (elapsed_since_start >= WARMUP_SECONDS) {
            g_warmup_done = true;
            
            // Snapshot baseline for valid stats
            clock_gettime(CLOCK_MONOTONIC, &g_valid_start_time);
            g_valid_start_iters = g_completed_iters;

            DOCA_LOG_INFO(">>> Warmup Finished. Counters Reset. Starting Benchmark... <<<");
        }
    }

    /* --- Logic 2: Instant Bandwidth Reporting (Every 1.0s) --- */
    double report_delta = current_time - timespec_to_sec(g_last_report_time);
    if (report_delta >= 1.0) {
        uint64_t diff_iters = g_completed_iters - g_last_report_iters;
        double instant_gbps = (diff_iters * g_payload_size * 8.0) / report_delta / 1e9;
        
        // Add a tag to show if we are in Warmup or Benchmarking phase
        const char *phase_tag = g_warmup_done ? "[Benchmarking]" : "[Warmup]";
        
        DOCA_LOG_INFO("%s Instant BW: %.2f Gbps (PPS: %.0f)", phase_tag, instant_gbps, diff_iters / report_delta);

        clock_gettime(CLOCK_MONOTONIC, &g_last_report_time);
        g_last_report_iters = g_completed_iters;
    }

    /* --- Logic 3: Termination Check --- */
    // Total Run time = Warmup + Benchmark
    if (elapsed_since_start < (WARMUP_SECONDS + BENCHMARK_SECONDS)) {
        // Keep Pipeline Full
        if (submit_write_task(resources) != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to keep pipeline full");
            (void)doca_ctx_stop(resources->rdma_ctx);
        }
    } else {
        // Time is up.
        if (!g_is_draining) {
            g_is_draining = true;
        }
        
        // Wait for drain to complete
        if (resources->num_remaining_tasks == 0) {
            
            // Calculate Stats ONLY based on valid window (After warmup)
            double valid_end_sec = current_time;
            double valid_start_sec = timespec_to_sec(g_valid_start_time);
            double valid_duration = valid_end_sec - valid_start_sec;
            
            uint64_t valid_iters = g_completed_iters - g_valid_start_iters;
            double avg_gbps = (valid_iters * g_payload_size * 8.0) / valid_duration / 1e9;
            double avg_pps = valid_iters / valid_duration;

            DOCA_LOG_INFO("\n");
            DOCA_LOG_INFO("**************** FINAL RESULTS ****************");
            DOCA_LOG_INFO("Config        : Window=%d, Payload=%zu bytes", WINDOW_SIZE, g_payload_size);
            DOCA_LOG_INFO("Timing        : Warmup=%ds + Benchmark=%.2fs", WARMUP_SECONDS, valid_duration);
            DOCA_LOG_INFO("Valid Data    : %.2f GB (Excluded Warmup)", (double)valid_iters * g_payload_size / (1024*1024*1024));
            DOCA_LOG_INFO("AVG Throughput: %.4f Gbps", avg_gbps);
            DOCA_LOG_INFO("AVG PacketRate: %.0f PPS", avg_pps);
            DOCA_LOG_INFO("***********************************************");
            DOCA_LOG_INFO("\n");

            /* Cleanup */
            for(int i=0; i<WINDOW_SIZE; i++) {
                if(g_dst_buf_pool[i]) doca_buf_dec_refcount(g_dst_buf_pool[i], NULL);
                if(g_src_buf_pool[i]) doca_buf_dec_refcount(g_src_buf_pool[i], NULL);
            }
            (void)doca_ctx_stop(resources->rdma_ctx);
        }
    }
}

static void rdma_write_error_callback(struct doca_rdma_task_write *rdma_write_task,
                                      union doca_data task_user_data, union doca_data ctx_user_data)
{
    struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
    struct doca_task *task = doca_rdma_task_write_as_task(rdma_write_task);
    doca_error_t result = doca_task_get_status(task);
    
    DOCA_LOG_ERR("Task failed: %s", doca_error_get_descr(result));
    doca_task_free(task);
    (void)doca_ctx_stop(resources->rdma_ctx);
}

static doca_error_t submit_write_task(struct rdma_resources *resources) {
    struct doca_rdma_task_write *task = NULL;
    union doca_data user_data = {0};
    doca_error_t result;

    g_pool_idx = (g_pool_idx + 1) % WINDOW_SIZE;
    struct doca_buf *curr_src = g_src_buf_pool[g_pool_idx];
    struct doca_buf *curr_dst = g_dst_buf_pool[g_pool_idx];

    reset_buf_data_len(curr_dst);

    result = doca_rdma_task_write_allocate_init(resources->rdma, curr_src, curr_dst, user_data, &task);
    if (result != DOCA_SUCCESS) return result;

    result = doca_task_submit(doca_rdma_task_write_as_task(task));
    if (result == DOCA_SUCCESS) {
        resources->num_remaining_tasks++; 
    } else {
        doca_task_free(doca_rdma_task_write_as_task(task));
    }
    return result;
}

static doca_error_t start_bandwidth_benchmark(struct rdma_resources *resources) {
    doca_error_t result = DOCA_SUCCESS;
    
    g_payload_size = atol(resources->cfg->write_string);
    if (g_payload_size == 0) g_payload_size = 65536; 
    if (g_payload_size > MEM_RANGE_LEN) g_payload_size = MEM_RANGE_LEN;

    DOCA_LOG_INFO("Starting Benchmark: Warmup=%ds + Run=%ds", WARMUP_SECONDS, BENCHMARK_SECONDS);

    char *remote_mmap_range;
    size_t remote_mmap_range_len;
    
    result = doca_mmap_create_from_export(NULL, resources->remote_mmap_descriptor, resources->remote_mmap_descriptor_size,
                                          resources->doca_device, &(resources->remote_mmap));
    if (result != DOCA_SUCCESS) return result;

    result = doca_mmap_get_memrange(resources->remote_mmap, (void **)&remote_mmap_range, &remote_mmap_range_len);
    if (result != DOCA_SUCCESS) return result;

    /* Initialize Buffer Pool */
    for (int i = 0; i < WINDOW_SIZE; i++) {
        result = doca_buf_inventory_buf_get_by_data(resources->buf_inventory, resources->mmap, resources->mmap_memrange,
                                                    g_payload_size, &g_src_buf_pool[i]);
        if (result != DOCA_SUCCESS) return result;
        
        result = doca_buf_inventory_buf_get_by_addr(resources->buf_inventory, resources->remote_mmap, remote_mmap_range,
                                                    g_payload_size, &g_dst_buf_pool[i]);
        if (result != DOCA_SUCCESS) return result;
    }

    // Set Timers
    clock_gettime(CLOCK_MONOTONIC, &g_start_time_abs);
    clock_gettime(CLOCK_MONOTONIC, &g_last_report_time);

    /* Fill the Pipeline */
    for (int i = 0; i < WINDOW_SIZE; i++) {
        result = submit_write_task(resources);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to fill initial window: %s", doca_error_get_descr(result));
            return result;
        }
    }

    return DOCA_SUCCESS;
}

static doca_error_t rdma_write_requester_export_and_connect(struct rdma_resources *resources) {
    doca_error_t result;
    result = doca_rdma_export(resources->rdma, &(resources->rdma_conn_descriptor), &(resources->rdma_conn_descriptor_size));
    if (result != DOCA_SUCCESS) return result;
    result = exchange_descriptors_tcp_client(resources);
    if (result != DOCA_SUCCESS) return result;
    return doca_rdma_connect(resources->rdma, resources->remote_rdma_conn_descriptor, resources->remote_rdma_conn_descriptor_size);
}

static void rdma_write_requester_state_change_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                                       enum doca_ctx_states prev_state, enum doca_ctx_states next_state)
{
    struct rdma_resources *resources = (struct rdma_resources *)user_data.ptr;
    doca_error_t result = DOCA_SUCCESS;

    switch (next_state) {
    case DOCA_CTX_STATE_STARTING:
        DOCA_LOG_INFO("RDMA context starting...");
        result = rdma_write_requester_export_and_connect(resources);
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("RDMA context running.");
        result = start_bandwidth_benchmark(resources);
        break;
    case DOCA_CTX_STATE_STOPPING:
        DOCA_LOG_INFO("Context is stopping...");
        break;
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("Context is IDLE. Stopping PE.");
        resources->run_pe_progress = false;
        break;
    default: break;
    }

    if (result != DOCA_SUCCESS) {
        DOCA_ERROR_PROPAGATE(resources->first_encountered_error, result);
        (void)doca_ctx_stop(ctx);
    }
}

doca_error_t rdma_write_requester(struct rdma_config *cfg)
{
    struct rdma_resources resources = {0};
    union doca_data ctx_user_data = {0};
    const uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    const uint32_t rdma_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    doca_error_t result;

    result = allocate_rdma_resources(cfg, mmap_permissions, rdma_permissions,
                                     doca_rdma_cap_task_write_is_supported, &resources);
    if (result != DOCA_SUCCESS) return result;

    /* Set Task Pool size large enough for the window */
    result = doca_rdma_task_write_set_conf(resources.rdma, rdma_write_completed_callback,
                                           rdma_write_error_callback, MAX_TASK_POOL_SIZE); 
    if (result != DOCA_SUCCESS) goto destroy_resources;

    result = doca_ctx_set_state_changed_cb(resources.rdma_ctx, rdma_write_requester_state_change_callback);
    if (result != DOCA_SUCCESS) goto destroy_resources;

    /* Inventory size must support the pool */
    result = doca_buf_inventory_create(MAX_TASK_POOL_SIZE * 2, &resources.buf_inventory);
    if (result != DOCA_SUCCESS) goto destroy_resources;

    result = doca_buf_inventory_start(resources.buf_inventory);
    if (result != DOCA_SUCCESS) goto destroy_buf_inventory;

    ctx_user_data.ptr = &(resources);
    doca_ctx_set_user_data(resources.rdma_ctx, ctx_user_data);

    result = doca_ctx_start(resources.rdma_ctx);
    if (result != DOCA_ERROR_IN_PROGRESS) goto stop_buf_inventory;

    while (resources.run_pe_progress) {
        doca_pe_progress(resources.pe);
    }
    
    result = resources.first_encountered_error;

stop_buf_inventory:
    doca_buf_inventory_stop(resources.buf_inventory);
destroy_buf_inventory:
    doca_buf_inventory_destroy(resources.buf_inventory);
destroy_resources:
    destroy_rdma_resources(&resources, cfg);
    return result;
}