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

#include <stdlib.h>
#include <string.h>

#include <doca_log.h>
#include <doca_argp.h>

#include "rdma_protocol.h"

DOCA_LOG_REGISTER(RDMA_WRITE_REQUESTER::MAIN);

/* Sample's Logic */
doca_error_t rdma_write_requester(struct rdma_config *cfg);

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv)
{
    struct rdma_config cfg;
    doca_error_t result;
    struct doca_log_backend *sdk_log;
    int exit_status = EXIT_FAILURE;

    /* 1. Initialize configuration with zeros and defaults */
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = 12345;            // Default TCP port
    cfg.is_gid_index_set = false;

    /* Register a logger backend */
    result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS)
        goto sample_exit;

    /* Register a logger backend for internal SDK errors and warnings */
    result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
    if (result != DOCA_SUCCESS)
        goto sample_exit;
    result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
    if (result != DOCA_SUCCESS)
        goto sample_exit;

    DOCA_LOG_INFO("Starting the sample");

    /* 2. Initialize Arg Parser */
    /* IMPORTANT: doca_argp_init MUST be called before registering any parameters */
    result = doca_argp_init("doca_rdma_write_requester", &cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
        goto sample_exit;
    }

    /* 3. Register Parameters */
    
    /* Register RDMA common params (Device, IP, Port, GID Index) */
    result = register_rdma_common_params();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register sample parameters: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    /* Register Write String param (Used for payload size configuration) */
    result = register_rdma_write_string_param();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register write_string parameter: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    /* Register TXLKS specific params (Cert, Key, GID) */
    result = register_txlks_params();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register TXLKS parameters: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    /* 4. Start Parsing */
    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    /* 5. Validate Input */
    /* IP Address is mandatory for Requester to connect to Responder */
    if (strlen(cfg.ip_address) == 0) {
        DOCA_LOG_ERR("IP address is missing. Please provide it using -i or --ip");
        goto argp_cleanup;
    }

    /* 6. Start Sample Logic */
    result = rdma_write_requester(&cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("rdma_write_requester() failed: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    exit_status = EXIT_SUCCESS;

argp_cleanup:
    doca_argp_destroy();
sample_exit:
    if (exit_status == EXIT_SUCCESS)
        DOCA_LOG_INFO("Sample finished successfully");
    else
        DOCA_LOG_INFO("Sample finished with errors");
    return exit_status;
}