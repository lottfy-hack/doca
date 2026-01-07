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

#include "rdma_common.h"

DOCA_LOG_REGISTER(RDMA_READ_RESPONDER::SAMPLE);

#define EXAMPLE_SET_VALUE (0xD0CA) /* Example value to use for setting sync event */

/*
 * Destroy DOCA sync event resources
 *
 * @resources [in]: DOCA RDMA resources, including the sync_event to destroy
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t rdma_sync_event_responder_destroy_sync_event_resources(struct rdma_resources *resources)
{
	doca_error_t tmp_result, result = DOCA_SUCCESS;

	resources->sync_event_descriptor = NULL;

	/* Stop and destroy sync event if exists */
	if (resources->sync_event != NULL) {
		tmp_result = doca_sync_event_stop(resources->sync_event);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to stop DOCA sync event: %s", doca_error_get_descr(tmp_result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}

		tmp_result = doca_sync_event_destroy(resources->sync_event);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to destroy DOCA sync event: %s", doca_error_get_descr(tmp_result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}

		resources->sync_event = NULL;
	}

	return result;
}

/*
 * Allocate DOCA sync event resources
 *
 * @resources [in/out]: DOCA RDMA resources, including the sync_event to allocate
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t rdma_sync_event_responder_allocate_sync_event_resources(struct rdma_resources *resources)
{
	doca_error_t result;

	result = doca_sync_event_create(&resources->sync_event);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA sync event: %s", doca_error_get_descr(result));
		goto destroy_se;
	}

	result = doca_sync_event_add_publisher_location_remote_net(resources->sync_event);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set publisher for DOCA sync event: %s", doca_error_get_descr(result));
		goto destroy_se;
	}

	result = doca_sync_event_add_subscriber_location_cpu(resources->sync_event, resources->doca_device);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set subscriber for DOCA sync event: %s", doca_error_get_descr(result));
		goto destroy_se;
	}

	result = doca_sync_event_start(resources->sync_event);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start DOCA sync event: %s", doca_error_get_descr(result));
		goto destroy_se;
	}

	return DOCA_SUCCESS;

destroy_se:
	(void)rdma_sync_event_responder_destroy_sync_event_resources(resources);

	return result;
}

/*
 * Write the connection details and the mmap details for the requester to read,
 * and read the connection details of the requester
 *
 * @cfg [in]: Configuration parameters
 * @resources [in/out]: DOCA RDMA resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t write_read_connection(struct rdma_config *cfg, struct rdma_resources *resources)
{
	int enter = 0;
	doca_error_t result = DOCA_SUCCESS;

	/* Write the RDMA connection details */
	result = write_file(cfg->local_connection_desc_path,
			    (char *)resources->rdma_conn_descriptor,
			    resources->rdma_conn_descriptor_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to write the RDMA connection details: %s", doca_error_get_descr(result));
		return result;
	}

	/* Write the RDMA connection details */
	result = write_file(cfg->remote_resource_desc_path,
			    (char *)resources->sync_event_descriptor,
			    resources->sync_event_descriptor_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to write sync event export blob: %s", doca_error_get_descr(result));
		return result;
	}

	DOCA_LOG_INFO("You can now copy %s and %s to the requester",
		      cfg->local_connection_desc_path,
		      cfg->remote_resource_desc_path);
	DOCA_LOG_INFO("Please copy %s from the requester and then press enter", cfg->remote_connection_desc_path);

	/* Wait for enter */
	while (enter != '\r' && enter != '\n')
		enter = getchar();

	/* Read the remote RDMA connection details */
	result = read_file(cfg->remote_connection_desc_path,
			   (char **)&resources->remote_rdma_conn_descriptor,
			   &resources->remote_rdma_conn_descriptor_size);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to read the remote RDMA connection details: %s", doca_error_get_descr(result));

	return result;
}

/*
 * Export and receive connection and sync event details, and connect to the remote RDMA
 *
 * @resources [in]: RDMA resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t rdma_sync_event_responder_export_and_connect(struct rdma_resources *resources)
{
	doca_error_t result;

	/* Export DOCA RDMA */
	result = doca_rdma_export(resources->rdma,
				  &(resources->rdma_conn_descriptor),
				  &(resources->rdma_conn_descriptor_size));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to export DOCA RDMA: %s", doca_error_get_descr(result));
		return result;
	}

	/* Export RDMA sync event */
	result = doca_sync_event_export_to_remote_net(resources->sync_event,
						      (const uint8_t **)&(resources->sync_event_descriptor),
						      &(resources->sync_event_descriptor_size));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to export DOCA sync event for RDMA: %s", doca_error_get_descr(result));
		return result;
	}

	/* write and read connection details from the requester */
	result = write_read_connection(resources->cfg, resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to write and read connection details from the requester: %s",
			     doca_error_get_descr(result));
		return result;
	}

	/* Connect RDMA */
	result = doca_rdma_connect(resources->rdma,
				   resources->remote_rdma_conn_descriptor,
				   resources->remote_rdma_conn_descriptor_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to connect the responder's DOCA RDMA to the requester's DOCA RDMA: %s",
			     doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Handle the event - wait for a signal, update the sync even and wait for completion.
 *
 * @sync_event [in]: DOCA sync event
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t rdma_sync_event_responder_handle_event(struct doca_sync_event *sync_event)
{
	doca_error_t result;

	DOCA_LOG_INFO("Waiting for sync event to be signaled from remote");
	result = doca_sync_event_wait_gt(sync_event, EXAMPLE_SET_VALUE - 1, UINT64_MAX);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Waiting for sync event to be signaled from remote failed");
		return result;
	}

	DOCA_LOG_INFO("Signaling sync event");
	result = doca_sync_event_update_set(sync_event, EXAMPLE_SET_VALUE + 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Signaling sync event failed");
		return result;
	}

	DOCA_LOG_INFO("Waiting for sync event to be notified for completion");
	result = doca_sync_event_wait_gt(sync_event, UINT64_MAX - 1, UINT64_MAX);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Waiting for sync event to be notified for completion failed");
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * RDMA sync event responder state change callback
 * This function represents the state machine for this RDMA program
 *
 * @user_data [in]: doca_data from the context
 * @ctx [in]: DOCA context
 * @prev_state [in]: Previous DOCA context state
 * @next_state [in]: Next DOCA context state
 */
static void rdma_sync_event_responder_state_change_callback(const union doca_data user_data,
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

		result = rdma_sync_event_responder_export_and_connect(resources);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("rdma_sync_event_responder_export_and_connect() failed: %s",
				     doca_error_get_descr(result));
			DOCA_ERROR_PROPAGATE(resources->first_encountered_error, result);
			(void)doca_ctx_stop(ctx);
		} else
			DOCA_LOG_INFO("RDMA context finished initialization");
		break;
	case DOCA_CTX_STATE_RUNNING:
		DOCA_LOG_INFO("RDMA context is running");

		result = rdma_sync_event_responder_handle_event(resources->sync_event);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("rdma_sync_event_responder_handle_event() failed: %s",
				     doca_error_get_descr(result));
			DOCA_ERROR_PROPAGATE(resources->first_encountered_error, result);
		}

		/* Stop the context */
		result = doca_ctx_stop(resources->rdma_ctx);
		if ((result != DOCA_SUCCESS) && (result != DOCA_ERROR_IN_PROGRESS)) {
			DOCA_LOG_ERR("doca_ctx_stop() failed: %s", doca_error_get_descr(result));
			DOCA_ERROR_PROPAGATE(resources->first_encountered_error, result);
		}
		break;
	case DOCA_CTX_STATE_STOPPING:
		/**
		 * doca_ctx_stop() has been called.
		 * In this sample, this happens either due to a failure encountered, in which case doca_pe_progress()
		 * will cause any inflight task to be flushed, or due to the successful compilation of the sample flow.
		 * In both cases, in this sample, doca_pe_progress() will eventually transition the context to idle
		 * state.
		 */
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
}

/*
 * Responder side
 *
 * @cfg [in]: Configuration parameters
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t rdma_sync_event_responder(struct rdma_config *cfg)
{
	struct rdma_resources resources = {0};
	union doca_data ctx_user_data = {0};
	const uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE | DOCA_ACCESS_FLAG_RDMA_READ |
					  DOCA_ACCESS_FLAG_RDMA_WRITE;
	const uint32_t rdma_permissions = DOCA_ACCESS_FLAG_RDMA_READ | DOCA_ACCESS_FLAG_RDMA_WRITE;
	doca_error_t result, tmp_result;
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Allocating resources */
	result = allocate_rdma_resources(cfg, mmap_permissions, rdma_permissions, NULL, &resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate RDMA resources: %s", doca_error_get_descr(result));
		return result;
	}

	result = rdma_sync_event_responder_allocate_sync_event_resources(&resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate sync event resources: %s", doca_error_get_descr(result));
		goto destroy_rdma_resources;
	}

	result = doca_ctx_set_state_changed_cb(resources.rdma_ctx, rdma_sync_event_responder_state_change_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set state change callback for RDMA context: %s", doca_error_get_descr(result));
		goto destroy_sync_event_resources;
	}

	/* Include the program's resources in user data of context to be used in callbacks */
	ctx_user_data.ptr = &(resources);
	result = doca_ctx_set_user_data(resources.rdma_ctx, ctx_user_data);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set context user data: %s", doca_error_get_descr(result));
		goto destroy_sync_event_resources;
	}

	/* Start RDMA context */
	result = doca_ctx_start(resources.rdma_ctx);
	/* DOCA_ERROR_IN_PROGRESS is expected and handled by the state change callback function */
	if (result != DOCA_ERROR_IN_PROGRESS) {
		DOCA_LOG_ERR("Failed to start RDMA context: %s", doca_error_get_descr(result));
		goto destroy_sync_event_resources;
	}

	/*
	 * Run the progress engine which will run the state machine defined in
	 * rdma_sync_event_responder_state_change_callback().
	 * When the context moves to idle, the context change callback call will signal to stop running the progress
	 * engine.
	 */
	while (resources.run_pe_progress) {
		if (doca_pe_progress(resources.pe) == 0)
			nanosleep(&ts, &ts);
	}

	/* Assign the result we update in the callback */
	result = resources.first_encountered_error;

	tmp_result = request_stop_ctx(resources.pe, resources.rdma_ctx);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to stop DOCA RDMA context: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_sync_event_resources:
	tmp_result = rdma_sync_event_responder_destroy_sync_event_resources(&resources);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA Sync Event resources: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_rdma_resources:
	tmp_result = destroy_rdma_resources(&resources, cfg);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA RDMA resources: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
	return result;
}
