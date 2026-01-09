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
#include <sys/socket.h>   // socket, bind, listen, accept, send, recv
#include <netinet/in.h>   // sockaddr_in, INADDR_ANY
#include <arpa/inet.h>    // htons, inet_pton, htonl, ntohl
#include <string.h>       // memset
#include <stdlib.h>       // malloc, free
#include <errno.h>        // errno

#include "rdma_protocol.h"
/* TXLKS Protocol Headers */
#include "txlks_proto/txlks_common.h"
#include "txlks_proto/protocol.h"
#include "txlks_proto/txlks.h"

#define MAX_BUFF_SIZE (256) /* Maximum DOCA buffer size */
#define TCP_PORT      12345 /* TCP Port for Out-Of-Band exchange */

DOCA_LOG_REGISTER(RDMA_WRITE_RESPONDER::SAMPLE);

/* * 声明外部函数 server_handle 
 * 注意：请确保 txlks_proto/server.c 中的 server_handle 函数已去掉 static 关键字
 */
extern int server_handle(int cfd, const char *gid_s_str, const char *cert_s_path, const char *key_s_path);

/* --- TCP Helper Functions --- */

/* Send data: length (4 bytes network order) + data payload */
static doca_error_t send_blob_tcp(int sock, const void *data, size_t size) {
    uint32_t net_len = htonl((uint32_t)size);
    
    // 1. Send length
    if (send(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) {
        DOCA_LOG_ERR("Failed to send data length: %s", strerror(errno));
        return DOCA_ERROR_IO_FAILED;
    }
    // 2. Send data
    if (send(sock, data, size, 0) != (ssize_t)size) {
        DOCA_LOG_ERR("Failed to send data payload: %s", strerror(errno));
        return DOCA_ERROR_IO_FAILED;
    }
    return DOCA_SUCCESS;
}

/* Receive data: length (4 bytes network order) + allocate buffer + receive data */
static doca_error_t recv_blob_tcp(int sock, void **data, size_t *size) {
    uint32_t net_len;
    
    // 1. Receive length
    ssize_t res = recv(sock, &net_len, sizeof(net_len), 0);
    if (res != sizeof(net_len)) {
        DOCA_LOG_ERR("Failed to receive data length (recvd=%zd): %s", res, strerror(errno));
        return DOCA_ERROR_IO_FAILED;
    }
    *size = ntohl(net_len);
    
    // 2. Allocate memory
    *data = malloc(*size);
    if (*data == NULL) {
        DOCA_LOG_ERR("Failed to allocate memory for received data (%zu bytes)", *size);
        return DOCA_ERROR_NO_MEMORY;
    }
    
    // 3. Receive data (loop to ensure complete reception)
    size_t total_received = 0;
    while (total_received < *size) {
        res = recv(sock, (char*)(*data) + total_received, *size - total_received, 0);
        if (res <= 0) {
            DOCA_LOG_ERR("Failed to receive complete data payload: %s", strerror(errno));
            free(*data);
            *data = NULL;
            return DOCA_ERROR_IO_FAILED;
        }
        total_received += res;
    }
    return DOCA_SUCCESS;
}

/* --- Main Exchange Logic --- */

/*
 * Exchange connection details using TCP Server
 * Includes TXLKS Handshake integration.
 */
static doca_error_t exchange_descriptors_tcp_server(struct rdma_resources *resources) {
    int listen_sock, conn_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    doca_error_t result = DOCA_SUCCESS;
    int rc;
    int port = resources->cfg->port > 0 ? resources->cfg->port : TCP_PORT;

    /* 1. Create Listening Socket */
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        DOCA_LOG_ERR("Failed to create socket: %s", strerror(errno));
        return DOCA_ERROR_IO_FAILED;
    }

    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        DOCA_LOG_WARN("Failed to set SO_REUSEADDR");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        DOCA_LOG_ERR("Failed to bind to port %d: %s", port, strerror(errno));
        close(listen_sock);
        return DOCA_ERROR_IO_FAILED;
    }
    
    if (listen(listen_sock, 1) < 0) {
        DOCA_LOG_ERR("Failed to listen: %s", strerror(errno));
        close(listen_sock);
        return DOCA_ERROR_IO_FAILED;
    }

    DOCA_LOG_INFO("Waiting for TCP connection on port %d...", port);
    
    /* 2. Accept Connection */
    conn_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (conn_sock < 0) {
        DOCA_LOG_ERR("Failed to accept connection: %s", strerror(errno));
        close(listen_sock);
        return DOCA_ERROR_IO_FAILED;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    DOCA_LOG_INFO("Client connected from %s. Starting TXLKS Handshake...", client_ip);

    /* ============================================================ */
    /* 3. Execute TXLKS Handshake                                  */
    /* ============================================================ */

    rc = server_handle(conn_sock, 
                   resources->cfg->txlks_server_gid,       // 从命令行获取的 GID
                   resources->cfg->txlks_server_cert_path, // 从命令行获取的 证书路径
                   resources->cfg->txlks_server_key_path); // 从命令行获取的 私钥路径

    if (rc != 0) {
        DOCA_LOG_ERR("TXLKS Handshake failed! Closing connection.");
        close(conn_sock);
        close(listen_sock);
        return DOCA_ERROR_BAD_STATE;
    }

    DOCA_LOG_INFO("TXLKS Handshake Successful! Proceeding to RDMA descriptor exchange...");

    /* ============================================================ */
    /* 4. Exchange RDMA Descriptors                                */
    /* ============================================================ */

    // 4.1 Send local RDMA connection descriptor
    result = send_blob_tcp(conn_sock, resources->rdma_conn_descriptor, resources->rdma_conn_descriptor_size);
    if (result != DOCA_SUCCESS) goto cleanup;

    // 4.2 Send local Mmap descriptor
    result = send_blob_tcp(conn_sock, resources->mmap_descriptor, resources->mmap_descriptor_size);
    if (result != DOCA_SUCCESS) goto cleanup;

    // 4.3 Receive remote RDMA connection descriptor
    result = recv_blob_tcp(conn_sock, &resources->remote_rdma_conn_descriptor, &resources->remote_rdma_conn_descriptor_size);
    if (result != DOCA_SUCCESS) goto cleanup;

    DOCA_LOG_INFO("Descriptor exchange completed via TCP");

cleanup:
    close(conn_sock);
    close(listen_sock);
    return result;
}

/*
 * Export and receive connection details, and connect to the remote RDMA
 *
 * @resources [in]: RDMA resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t rdma_write_responder_export_and_connect(struct rdma_resources *resources)
{
    doca_error_t result;

    /* Export RDMA connection details */
    result = doca_rdma_export(resources->rdma,
                  &(resources->rdma_conn_descriptor),
                  &(resources->rdma_conn_descriptor_size));
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to export RDMA: %s", doca_error_get_descr(result));
        return result;
    }

    /* Export RDMA mmap */
    result = doca_mmap_export_rdma(resources->mmap,
                       resources->doca_device,
                       (const void **)&(resources->mmap_descriptor),
                       &(resources->mmap_descriptor_size));
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to export DOCA mmap for RDMA: %s", doca_error_get_descr(result));
        return result;
    }

    /* Use TCP exchange + TXLKS handshake */
    result = exchange_descriptors_tcp_server(resources);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("TCP exchange/Handshake failed");
        return result;
    }

    /* Connect RDMA */
    result = doca_rdma_connect(resources->rdma,
                   resources->remote_rdma_conn_descriptor,
                   resources->remote_rdma_conn_descriptor_size);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to connect the responder's RDMA to the requester's RDMA: %s",
                 doca_error_get_descr(result));

    return result;
}

/*
 * RDMA write responder state change callback
 * This function represents the state machine for this RDMA program
 *
 * @user_data [in]: doca_data from the context
 * @ctx [in]: DOCA context
 * @prev_state [in]: Previous DOCA context state
 * @next_state [in]: Next DOCA context state
 */
static void rdma_write_responder_state_change_callback(const union doca_data user_data,
                               struct doca_ctx *ctx,
                               enum doca_ctx_states prev_state,
                               enum doca_ctx_states next_state)
{
    struct rdma_resources *resources = (struct rdma_resources *)user_data.ptr;
    int enter = 0;
    char buffer[MAX_BUFF_SIZE];
    doca_error_t result = DOCA_SUCCESS;

    (void)prev_state;
    (void)ctx;

    switch (next_state) {
    case DOCA_CTX_STATE_STARTING:
        DOCA_LOG_INFO("RDMA context entered starting state");

        result = rdma_write_responder_export_and_connect(resources);
        if (result != DOCA_SUCCESS)
            DOCA_LOG_ERR("rdma_write_responder_export_and_connect() failed: %s",
                     doca_error_get_descr(result));
        else
            DOCA_LOG_INFO("RDMA context finished initialization");
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("RDMA context is running");

        /* Wait for enter which means that the requester has finished writing */
        DOCA_LOG_INFO("Wait till the requester has finished writing and press enter");
        while (enter != '\r' && enter != '\n')
            enter = getchar();

        /* Initialize buffer to zeros */
        memset(buffer, 0, MAX_BUFF_SIZE);

        /* Read the data that was written on the mmap */
        strncpy(buffer, resources->mmap_memrange, MAX_BUFF_SIZE - 1);

        /* Check if the buffer is null terminated and of legal size */
        if (strnlen(buffer, MAX_BUFF_SIZE) == MAX_BUFF_SIZE) {
            DOCA_LOG_ERR("The message that was written by the requester exceeds buffer size %d",
                     MAX_BUFF_SIZE);
            result = DOCA_ERROR_INVALID_VALUE;
            break;
        }

        DOCA_LOG_INFO("Requester has written: \"%s\"", buffer);

        /* Stop context */
        (void)doca_ctx_stop(resources->rdma_ctx);
        break;
    case DOCA_CTX_STATE_STOPPING:
        DOCA_LOG_INFO("RDMA context entered into stopping state. Any inflight tasks will be flushed");
        break;
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("RDMA context has been stopped");

        /* We can stop progressing the PE */
        resources->run_pe_progress = false;
        break;
    default:
        break;
    }

    /* If something failed - update that an error was encountered and stop the ctx */
    if (result != DOCA_SUCCESS) {
        DOCA_ERROR_PROPAGATE(resources->first_encountered_error, result);
        (void)doca_ctx_stop(ctx);
    }
}

/*
 * Responder side of the RDMA write
 *
 * @cfg [in]: Configuration parameters
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t rdma_write_responder(struct rdma_config *cfg)
{
    struct rdma_resources resources = {0};
    union doca_data ctx_user_data = {0};
    const uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE | DOCA_ACCESS_FLAG_RDMA_WRITE;
    const uint32_t rdma_permissions = DOCA_ACCESS_FLAG_RDMA_WRITE;
    doca_error_t result, tmp_result;
    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = SLEEP_IN_NANOS,
    };

    /* Allocating resources */
    result = allocate_rdma_resources(cfg, mmap_permissions, rdma_permissions, NULL, &resources);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to allocate RDMA Resources: %s", doca_error_get_descr(result));
        return result;
    }

    result = doca_ctx_set_state_changed_cb(resources.rdma_ctx, rdma_write_responder_state_change_callback);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to set state change callback for RDMA context: %s", doca_error_get_descr(result));
        goto destroy_resources;
    }

    /* Include the program's resources in user data of context to be used in callbacks */
    ctx_user_data.ptr = &(resources);
    result = doca_ctx_set_user_data(resources.rdma_ctx, ctx_user_data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set context user data: %s", doca_error_get_descr(result));
        goto destroy_resources;
    }

    /* Start RDMA context */
    result = doca_ctx_start(resources.rdma_ctx);
    /* DOCA_ERROR_IN_PROGRESS is expected and handled by the state change callback function */
    if (result != DOCA_ERROR_IN_PROGRESS) {
        DOCA_LOG_ERR("Failed to start RDMA context: %s", doca_error_get_descr(result));
        goto destroy_resources;
    }

    /*
     * Run the progress engine which will run the state machine defined in
     * rdma_write_responder_state_change_callback() When the requester finishes writing, the user will signal to
     * stop running the progress engine.
     */
    while (resources.run_pe_progress) {
        if (doca_pe_progress(resources.pe) == 0)
            nanosleep(&ts, &ts);
    }

    /* Assign the result we update in the callbacks */
    result = resources.first_encountered_error;

destroy_resources:
    tmp_result = destroy_rdma_resources(&resources, cfg);
    if (tmp_result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to destroy DOCA RDMA resources: %s", doca_error_get_descr(tmp_result));
        DOCA_ERROR_PROPAGATE(result, tmp_result);
    }
    return result;
}