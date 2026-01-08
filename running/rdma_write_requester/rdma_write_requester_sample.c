/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <doca_error.h>
#include <doca_log.h>
#include <doca_buf_inventory.h>
#include <doca_buf.h>
#include <doca_ctx.h>
#include <unistd.h>       // close, sleep
#include <sys/socket.h>   // socket, bind, listen, accept
#include <netinet/in.h>   // sockaddr_in, INADDR_ANY
#include <arpa/inet.h>    // htons, inet_pton
#include <string.h>       // memset
#include <stdlib.h>       // malloc, free
#include <time.h>         // clock_gettime

#include "rdma_common.h"

DOCA_LOG_REGISTER(RDMA_WRITE_REQUESTER::SAMPLE);

/* --- Performance Test Configuration --- */
#define TEST_ITERATIONS 1000   // 总发送次数
#define WARMUP_ITERATIONS 10   // 预热次数

/* Static variables for benchmarking statistics */
static int g_current_iter = 0;
static double g_total_latency_us = 0;
static struct timespec g_start_time;

/* Forward declaration */
static doca_error_t rdma_write_prepare_and_submit_task(struct rdma_resources *resources);

/* TCP Helper Functions */
static doca_error_t send_blob_tcp(int sock, const void *data, size_t size)
{
	uint32_t net_len = htonl((uint32_t)size);
	if (send(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) return DOCA_ERROR_IO_FAILED;
	if (send(sock, data, size, 0) != (ssize_t)size) return DOCA_ERROR_IO_FAILED;
	return DOCA_SUCCESS;
}

static doca_error_t recv_blob_tcp(int sock, void **data, size_t *size)
{
	uint32_t net_len;
	ssize_t res;
	size_t total_received = 0;

	if (recv(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) return DOCA_ERROR_IO_FAILED;
	*size = ntohl(net_len);

	*data = malloc(*size);
	if (*data == NULL) return DOCA_ERROR_NO_MEMORY;

	while (total_received < *size) {
		res = recv(sock, (char *)(*data) + total_received, *size - total_received, 0);
		if (res <= 0) {
			free(*data);
			*data = NULL;
			return DOCA_ERROR_IO_FAILED;
		}
		total_received += res;
	}
	return DOCA_SUCCESS;
}

static doca_error_t exchange_descriptors_tcp_client(struct rdma_resources *resources)
{
	int sock;
	struct sockaddr_in server_addr;
	doca_error_t result = DOCA_SUCCESS;
	
	const char *server_ip = resources->cfg->ip_address;
	uint16_t port = resources->cfg->port;

	DOCA_LOG_INFO("Connecting to Responder at %s:%d...", server_ip, port);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) return DOCA_ERROR_IO_FAILED;

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
		close(sock);
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		close(sock);
		return DOCA_ERROR_IO_FAILED;
	}
	DOCA_LOG_INFO("Connected to Responder");

	result = recv_blob_tcp(sock, &resources->remote_rdma_conn_descriptor, &resources->remote_rdma_conn_descriptor_size);
	if (result != DOCA_SUCCESS) goto cleanup;

	result = recv_blob_tcp(sock, &resources->remote_mmap_descriptor, &resources->remote_mmap_descriptor_size);
	if (result != DOCA_SUCCESS) goto cleanup;

	result = send_blob_tcp(sock, resources->rdma_conn_descriptor, resources->rdma_conn_descriptor_size);
	if (result != DOCA_SUCCESS) goto cleanup;

	DOCA_LOG_INFO("Descriptor exchange completed via TCP");

cleanup:
	close(sock);
	return result;
}

/* * 核心修复函数：重置 buffer 状态 
 * DOCA 在 RDMA Write 完成时会尝试更新 dst_buf 的 data_len。
 * 如果 dst_buf 已经“满”了（data_len == len），就会报错 available memory=0。
 * 所以必须手动重置。
 */
static void reset_buf_data_len(struct doca_buf *buf) {
    void *data;
    doca_buf_get_data(buf, &data);
    doca_buf_set_data(buf, data, 0); // 设置 data_len 为 0
}

static void rdma_write_completed_callback(struct doca_rdma_task_write *rdma_write_task,
					  union doca_data task_user_data,
					  union doca_data ctx_user_data)
{
	struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
	// doca_error_t *first_encountered_error = (doca_error_t *)task_user_data.ptr;
	doca_error_t result = DOCA_SUCCESS;
    
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);

    double latency_us = (end.tv_sec - g_start_time.tv_sec) * 1e6 + 
                        (end.tv_nsec - g_start_time.tv_nsec) / 1e3;

    g_current_iter++;
    if (g_current_iter > WARMUP_ITERATIONS) {
        g_total_latency_us += latency_us;
    }

	doca_task_free(doca_rdma_task_write_as_task(rdma_write_task));

    /* Loop Control */
    if (g_current_iter < TEST_ITERATIONS) {
        // Ping-Pong: Submit next task
        result = rdma_write_prepare_and_submit_task(resources);
        if (result != DOCA_SUCCESS) {
             DOCA_LOG_ERR("Failed to submit next task: %s", doca_error_get_descr(result));
             (void)doca_ctx_stop(resources->rdma_ctx);
        }
    } else {
        // Report
        int measured_iters = TEST_ITERATIONS - WARMUP_ITERATIONS;
        double avg_latency = g_total_latency_us / measured_iters;
        size_t payload_size = atol(resources->cfg->write_string);
        if (payload_size == 0) payload_size = 1024;
        
        double bandwidth_gbps = (payload_size * 8.0) / (avg_latency / 1e6) / 1e9;
        double pps = 1e6 / avg_latency;

        DOCA_LOG_INFO("==================================================");
        DOCA_LOG_INFO("Config: Size=%zu bytes, Iterations=%d", payload_size, TEST_ITERATIONS);
        DOCA_LOG_INFO("Average Latency    : %.2f us", avg_latency);
        DOCA_LOG_INFO("Average Throughput : %.4f Gbps", bandwidth_gbps);
        DOCA_LOG_INFO("Packet Rate        : %.0f PPS", pps);
        DOCA_LOG_INFO("==================================================");

        doca_buf_dec_refcount(resources->dst_buf, NULL);
        doca_buf_dec_refcount(resources->src_buf, NULL);
        resources->num_remaining_tasks = 0;
        (void)doca_ctx_stop(resources->rdma_ctx);
    }
}

static void rdma_write_error_callback(struct doca_rdma_task_write *rdma_write_task,
				      union doca_data task_user_data,
				      union doca_data ctx_user_data)
{
	struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
	struct doca_task *task = doca_rdma_task_write_as_task(rdma_write_task);
	doca_error_t *first_encountered_error = (doca_error_t *)task_user_data.ptr;
	doca_error_t result;

	result = doca_task_get_status(task);
	DOCA_ERROR_PROPAGATE(*first_encountered_error, result);
	DOCA_LOG_ERR("RDMA write task failed: %s", doca_error_get_descr(result));

	doca_buf_dec_refcount(resources->dst_buf, NULL);
	doca_buf_dec_refcount(resources->src_buf, NULL);
	doca_task_free(task);
	(void)doca_ctx_stop(resources->rdma_ctx);
}

static doca_error_t rdma_write_requester_export_and_connect(struct rdma_resources *resources)
{
	doca_error_t result;

	result = doca_rdma_export(resources->rdma,
				  &(resources->rdma_conn_descriptor),
				  &(resources->rdma_conn_descriptor_size));
	if (result != DOCA_SUCCESS) return result;

	result = exchange_descriptors_tcp_client(resources);
	if (result != DOCA_SUCCESS) return result;

	result = doca_rdma_connect(resources->rdma,
				   resources->remote_rdma_conn_descriptor,
				   resources->remote_rdma_conn_descriptor_size);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to connect: %s", doca_error_get_descr(result));

	return result;
}

static doca_error_t rdma_write_prepare_and_submit_task(struct rdma_resources *resources)
{
	struct doca_rdma_task_write *rdma_write_task = NULL;
	union doca_data task_user_data = {0};
	doca_error_t result;

	task_user_data.ptr = &(resources->first_encountered_error);

    /* * IMPORTANT FIX: 在提交任务前，必须重置 dst_buf 的数据长度。
     * 否则 DOCA 会认为 buffer 已满 (len == data_len)，导致 "available buffer memory=0" 错误。
     */
    reset_buf_data_len(resources->dst_buf);

	result = doca_rdma_task_write_allocate_init(resources->rdma,
						    resources->src_buf,
						    resources->dst_buf,
						    task_user_data,
						    &rdma_write_task);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate task: %s", doca_error_get_descr(result));
		return result;
	}

    clock_gettime(CLOCK_MONOTONIC, &g_start_time);

	result = doca_task_submit(doca_rdma_task_write_as_task(rdma_write_task));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit task: %s", doca_error_get_descr(result));
		doca_task_free(doca_rdma_task_write_as_task(rdma_write_task));
	}
	return result;
}

static doca_error_t setup_buffers(struct rdma_resources *resources) {
    char *remote_mmap_range;
	size_t remote_mmap_range_len;
    doca_error_t result;
    size_t write_string_len = atol(resources->cfg->write_string);
    if (write_string_len == 0) write_string_len = 1024;
    // Cap size to avoid overflow
    if (write_string_len > MEM_RANGE_LEN) write_string_len = MEM_RANGE_LEN;

    /* Create remote mmap object */
    result = doca_mmap_create_from_export(NULL, resources->remote_mmap_descriptor, resources->remote_mmap_descriptor_size,
					      resources->doca_device, &(resources->remote_mmap));
	if (result != DOCA_SUCCESS) return result;

    result = doca_mmap_get_memrange(resources->remote_mmap, (void **)&remote_mmap_range, &remote_mmap_range_len);
	if (result != DOCA_SUCCESS) return result;

    /* Create Src Buffer */
    result = doca_buf_inventory_buf_get_by_data(resources->buf_inventory, resources->mmap, resources->mmap_memrange,
						    write_string_len, &resources->src_buf);
    if (result != DOCA_SUCCESS) return result;
    
    // Fill dummy data
    void *data;
    doca_buf_get_data(resources->src_buf, &data);
    memset(data, 'A', (write_string_len < 100) ? write_string_len : 100); 

    /* Create Dst Buffer */
    // get_by_addr 可能会把 data_len 设置为满，导致后续写入失败
    result = doca_buf_inventory_buf_get_by_addr(resources->buf_inventory, resources->remote_mmap, remote_mmap_range,
						    write_string_len, &resources->dst_buf);
    if (result != DOCA_SUCCESS) return result;

    /* 立即重置 dst_buf，确保它是空的 */
    reset_buf_data_len(resources->dst_buf);

    return result;
}

static void rdma_write_requester_state_change_callback(const union doca_data user_data,
						       struct doca_ctx *ctx,
						       enum doca_ctx_states prev_state,
						       enum doca_ctx_states next_state)
{
	struct rdma_resources *resources = (struct rdma_resources *)user_data.ptr;
	doca_error_t result = DOCA_SUCCESS;

	(void)prev_state;
	(void)ctx;

	switch (next_state) {
	case DOCA_CTX_STATE_STARTING:
		DOCA_LOG_INFO("RDMA context entered starting state");
		result = rdma_write_requester_export_and_connect(resources);
        if (result == DOCA_SUCCESS) {
            DOCA_LOG_INFO("Connected. Initializing Buffers...");
            result = setup_buffers(resources);
        }
		break;
	case DOCA_CTX_STATE_RUNNING:
		DOCA_LOG_INFO("RDMA context is running. Starting Benchmark...");
		result = rdma_write_prepare_and_submit_task(resources);
		break;
    case DOCA_CTX_STATE_STOPPING:
    case DOCA_CTX_STATE_IDLE:
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
	doca_error_t result, tmp_result;

	result = allocate_rdma_resources(cfg, mmap_permissions, rdma_permissions,
					 doca_rdma_cap_task_write_is_supported, &resources);
	if (result != DOCA_SUCCESS) return result;

	result = doca_rdma_task_write_set_conf(resources.rdma, rdma_write_completed_callback,
					       rdma_write_error_callback, NUM_RDMA_TASKS);
	if (result != DOCA_SUCCESS) goto destroy_resources;

	result = doca_ctx_set_state_changed_cb(resources.rdma_ctx, rdma_write_requester_state_change_callback);
	if (result != DOCA_SUCCESS) goto destroy_resources;

	result = doca_buf_inventory_create(INVENTORY_NUM_INITIAL_ELEMENTS, &resources.buf_inventory);
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