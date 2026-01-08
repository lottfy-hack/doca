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
#include <doca_error.h>

#include "rdma_common.h"

DOCA_LOG_REGISTER(RDMA_WRITE_RESPONDER::MAIN);

/* Sample's Logic */
doca_error_t rdma_write_responder(struct rdma_config *cfg);

/*
 * ARGP Callback - Handle thread count parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t thread_count_callback(void *param, void *config)
{
	struct rdma_config *cfg = (struct rdma_config *)config;
	int threads = *(int *)param;

	if (threads <= 0) {
		DOCA_LOG_ERR("Thread count must be positive integer > 0");
		return DOCA_ERROR_INVALID_VALUE;
	}
	cfg->num_threads = threads;
	return DOCA_SUCCESS;
}

/*
 * Register the thread count parameter
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t register_thread_param(void)
{
	struct doca_argp_param *thread_param;
	doca_error_t result;

	/* Create and register the thread count param */
	result = doca_argp_param_create(&thread_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create thread param: %s", doca_error_get_descr(result));
		return result;
	}

	doca_argp_param_set_short_name(thread_param, "t");
	doca_argp_param_set_long_name(thread_param, "threads");
	doca_argp_param_set_description(thread_param, "Number of threads/QPs to use (default: 1)");
	doca_argp_param_set_callback(thread_param, thread_count_callback);
	doca_argp_param_set_type(thread_param, DOCA_ARGP_TYPE_INT);

	result = doca_argp_register_param(thread_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register thread param: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv)
{
	struct rdma_config cfg = {0};
	doca_error_t result;
	struct doca_log_backend *sdk_log;
	int exit_status = EXIT_FAILURE;

	/* Set default configuration values */
	cfg.port = 12345;
	cfg.num_threads = 1; // 默认为单线程
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

	/* Initialize argparser */
	result = doca_argp_init("doca_rdma_write_responder", &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		goto sample_exit;
	}

	/* Register RDMA common params */
	result = register_rdma_common_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register sample parameters: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	/* Register Thread param (-t/--threads) */
	result = register_thread_param();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register thread parameter: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	/* Start argparser */
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	/* Start sample */
	result = rdma_write_responder(&cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("rdma_write_responder() failed: %s", doca_error_get_descr(result));
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