/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * DOCA RDMA Write Responder (Dynamic Multi-Thread / Multi-QP Ready)
 * Fixed: Supports dynamic thread count via command line (-t).
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

DOCA_LOG_REGISTER(RDMA_WRITE_RESPONDER::MULTI_QP);

#define LISTEN_QUEUE_LEN 1

/* Per-Connection Context */
struct responder_worker {
    int id;
    struct doca_pe *pe;
    struct doca_rdma *rdma;
    struct doca_ctx *rdma_ctx;
    
    /* Descriptors */
    const void *local_desc;
    size_t local_desc_len;
    char *remote_desc;
    size_t remote_desc_len;
};

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

/* Multi-QP Handshake Server Logic */
static doca_error_t perform_handshake_server(struct rdma_resources *shared_res, struct responder_worker *workers, int num_threads) {
    int listen_sock, conn_sock;
    struct sockaddr_in s_addr, c_addr;
    socklen_t addr_len = sizeof(c_addr);
    int port = shared_res->cfg->port;
    doca_error_t result = DOCA_SUCCESS;
    int opt = 1;

    DOCA_LOG_INFO("Waiting for Requester on port %d (Expect %d QPs)...", port, num_threads);

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) return DOCA_ERROR_IO_FAILED;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = htons(port);

    if (bind(listen_sock, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
        DOCA_LOG_ERR("Bind failed. Port %d may be in use.", port);
        close(listen_sock);
        return DOCA_ERROR_IO_FAILED;
    }
    listen(listen_sock, LISTEN_QUEUE_LEN);

    conn_sock = accept(listen_sock, (struct sockaddr *)&c_addr, &addr_len);
    if (conn_sock < 0) {
        close(listen_sock);
        return DOCA_ERROR_IO_FAILED;
    }
    DOCA_LOG_INFO("Requester connected.");

    /* 1. Send N Local Descriptors */
    for (int i = 0; i < num_threads; i++) {
        result = send_blob_tcp(conn_sock, workers[i].local_desc, workers[i].local_desc_len);
        if (result != DOCA_SUCCESS) goto cleanup;
    }

    /* 2. Send Shared Mmap Descriptor */
    result = send_blob_tcp(conn_sock, shared_res->mmap_descriptor, shared_res->mmap_descriptor_size);
    if (result != DOCA_SUCCESS) goto cleanup;

    /* 3. Receive N Remote Descriptors */
    for (int i = 0; i < num_threads; i++) {
        result = recv_blob_tcp(conn_sock, (void**)&workers[i].remote_desc, &workers[i].remote_desc_len);
        if (result != DOCA_SUCCESS) goto cleanup;
    }

    DOCA_LOG_INFO("Multi-QP Handshake completed.");

cleanup:
    close(conn_sock);
    close(listen_sock);
    return result;
}

/* Responder Side Logic */
doca_error_t rdma_write_responder(struct rdma_config *cfg)
{
    struct rdma_resources shared_res = {0};
    /* Read thread count from config */
    int n_threads = cfg->num_threads; 
    struct responder_worker *workers = NULL;
    doca_error_t result;
    
    /* Allocate workers array dynamically */
    workers = calloc(n_threads, sizeof(struct responder_worker));
    if (workers == NULL) {
        DOCA_LOG_ERR("Failed to allocate memory for workers");
        return DOCA_ERROR_NO_MEMORY;
    }

    /* 1. Initialize Shared Device & Memory */
    const uint32_t mmap_perm = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE | DOCA_ACCESS_FLAG_RDMA_WRITE;
    const uint32_t rdma_perm = DOCA_ACCESS_FLAG_RDMA_WRITE; 

    result = allocate_rdma_resources(cfg, mmap_perm, rdma_perm,
                                     doca_rdma_cap_task_write_is_supported, &shared_res);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to allocate shared resources: %s", doca_error_get_descr(result));
        free(workers);
        return result;
    }

    if (shared_res.mmap_descriptor == NULL) {
        result = doca_mmap_export_rdma(shared_res.mmap, shared_res.doca_device,
                                      (const void **)&shared_res.mmap_descriptor,
                                      &shared_res.mmap_descriptor_size);
        if (result != DOCA_SUCCESS) {
            free(workers);
            return result;
        }
    }

    DOCA_LOG_INFO("Initializing %d Responder Contexts...", n_threads);

    /* 2. Initialize N RDMA Contexts */
    for (int i = 0; i < n_threads; i++) {
        workers[i].id = i;
        
        result = doca_pe_create(&workers[i].pe);
        if (result != DOCA_SUCCESS) return result;

        result = doca_rdma_create(shared_res.doca_device, &workers[i].rdma);
        if (result != DOCA_SUCCESS) return result;

        workers[i].rdma_ctx = doca_rdma_as_ctx(workers[i].rdma);

        result = doca_rdma_set_permissions(workers[i].rdma, rdma_perm);
        if (result != DOCA_SUCCESS) return result;

        result = doca_pe_connect_ctx(workers[i].pe, workers[i].rdma_ctx);
        if (result != DOCA_SUCCESS) return result;

        /* Start Context */
        result = doca_ctx_start(workers[i].rdma_ctx);
        
        /* Allow IN_PROGRESS */
        if (result != DOCA_SUCCESS && result != DOCA_ERROR_IN_PROGRESS) {
            DOCA_LOG_ERR("Failed to start ctx %d: %s", i, doca_error_get_descr(result));
            return result;
        }

        /* Export Connection Info */
        result = doca_rdma_export(workers[i].rdma, &workers[i].local_desc, &workers[i].local_desc_len);
        if (result != DOCA_SUCCESS) return result;
    }

    /* 3. Perform Handshake */
    result = perform_handshake_server(&shared_res, workers, n_threads);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Handshake failed. Check if Requester NUM_THREADS matches.");
        return result;
    }

    /* 4. Connect All QPs */
    DOCA_LOG_INFO("Connecting RDMA contexts...");
    for (int i = 0; i < n_threads; i++) {
        result = doca_rdma_connect(workers[i].rdma, workers[i].remote_desc, workers[i].remote_desc_len);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Worker %d failed to connect: %s", i, doca_error_get_descr(result));
            return result;
        }
    }

    DOCA_LOG_INFO("All %d QPs Connected and Ready.", n_threads);
    DOCA_LOG_INFO("Server is listening for RDMA Writes. (Press Ctrl+C to stop)");

    /* 5. Main Loop (Passive) */
    while (1) {
        sleep(1);
    }

    /* Unreachable cleanup code */
    for (int i = 0; i < n_threads; i++) {
        doca_ctx_stop(workers[i].rdma_ctx);
        doca_rdma_destroy(workers[i].rdma);
        doca_pe_destroy(workers[i].pe);
    }
    free(workers);
    destroy_rdma_resources(&shared_res, cfg);

    return DOCA_SUCCESS;
}