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

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dpdk.h>

#include <dpdk_utils.h>

#include "flow_switch_common.h"

#define FLOW_SWITCH_PROXY_PORT_NB 2

DOCA_LOG_REGISTER(FLOW_SWITCH::MAIN);

/* Sample's Logic */
doca_error_t flow_switch(int nb_queues, int nb_ports, struct doca_dev *dev_main, struct doca_dev *dev_sec);

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv)
{
	doca_error_t result;
	struct doca_log_backend *sdk_log;
	int exit_status = EXIT_FAILURE;
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 6,
		.port_config.nb_queues = 1,
		.port_config.isolated_mode = 1,
	};
	struct flow_switch_ctx ctx = {0};

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

	result = doca_argp_init("doca_flow_switch", &ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		goto sample_exit;
	}
	result = register_doca_flow_switch_param();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register flow param: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}
	doca_argp_set_dpdk_program(init_flow_switch_dpdk);
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	result = init_doca_flow_switch_common(&ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init flow switch common: %s", doca_error_get_descr(result));
		goto dpdk_cleanup;
	}

	/* update queues and ports */
	result = dpdk_queues_and_ports_init(&dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update ports and queues");
		goto dpdk_cleanup;
	}

	/* run sample */
	result = flow_switch(dpdk_config.port_config.nb_queues,
			     dpdk_config.port_config.nb_ports,
			     ctx.doca_dev[0],
			     ctx.doca_dev[1]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("flow_switch() encountered an error: %s", doca_error_get_descr(result));
		goto dpdk_ports_queues_cleanup;
	}

	exit_status = EXIT_SUCCESS;

dpdk_ports_queues_cleanup:
	dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_cleanup:
	dpdk_fini();
argp_cleanup:
	doca_argp_destroy();
sample_exit:
	destroy_doca_flow_switch_common(&ctx);
	if (exit_status == EXIT_SUCCESS)
		DOCA_LOG_INFO("Sample finished successfully");
	else
		DOCA_LOG_INFO("Sample finished with errors");
	return exit_status;
}
