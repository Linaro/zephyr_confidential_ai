/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <mbedtls/x509_crt.h>
#include <psa/protected_storage.h>

#include "bootstrap.h"
#include "dhcpwait.h"
#include "key_mgmt.h"
#include "provision.h"
#include "sntp_client.h"
#include "util_app_log.h"

LOG_MODULE_REGISTER(cert_mgmt, CONFIG_LOG_DEFAULT_LEVEL);

#define CERT_MGMT_THREAD_PRIORITY 7

#define ONE_DAY_IN_SEC 86400

static struct k_work_delayable cert_revalidate;

/* Semaphore waiting for command to start process. */
static K_SEM_DEFINE(cert_mgmt_thread_sem, 0, 1);

/* Device provisioning requires connecting to the bootstrap server, and sending a CSR for the key.
 * The device's public key is then registered with the bootstrap server/CA, and we obtain an X.509
 * certificate signed by the CA for the specified key id.
 */
static int cert_mgmt_do_prov_cert(enum km_key_type key_id)
{
	int status;
	uint8_t key_idx;
	bool is_valid_key_id = false;
	for (key_idx = 0; key_idx < KEY_COUNT; key_idx++) {
		struct km_key_context *ctx = km_get_context(key_idx);
		if (ctx == NULL) {
			status = -EINVAL;
			goto err;
		}

		if (ctx->key_id == key_id) {
			is_valid_key_id = true;
			break;
		}
	}
	if (!is_valid_key_id) {
		status = -EINVAL;
		goto err;
	}

	struct bootstrap bctx;

	status = bootstrap_open(&bctx);
	if (status != 0) {
		LOG_ERR("Failed to talk to bootstrap server: %d", status);
		goto err;
	}

	/* Request is static to prevent stack overflow. */
	static struct csr_req req;
	status = bootstrap_csr(&bctx, &req, key_idx);
	if (status != 0) {
		// TODO: Need to close on error.
		LOG_ERR("Unable to process CSR: %d", status);
		goto err;
	}

	/* If this is the TLS message, also retrieve the service
	 * information. */
	if (key_id == KEY_ID_CLIENT_TLS) {
		status = bootstrap_service(&bctx);
		if (status != 0) {
			// TODO: Need to close on error.
			goto err;
		}
	}

	/* Regardless of error return from the request, close the
	 * connection. */
	int status2 = bootstrap_close(&bctx);
	if (status2 != 0) {
		LOG_ERR("Error: Error closing bootstrap connection: %d", status2);
		return status2;
	}

err:
	return status;
}

static void trigger_cert_revalidate(struct k_work *work)
{
	/* Release semaphore to wake up cert mgmt thread*/
	k_sem_give(&cert_mgmt_thread_sem);
	k_work_reschedule(&cert_revalidate,
			  K_SECONDS(CONFIG_CERT_REVALIDATE_IN_DAYS * ONE_DAY_IN_SEC));
}

static int validate_x509_cert(const uint8_t *cert_der, size_t cert_der_len)
{
	mbedtls_x509_crt cert;
	int ret = 0;
	mbedtls_x509_crt_init(&cert);
	ret = mbedtls_x509_crt_parse(&cert, cert_der, cert_der_len);
	if (0 != ret) {
		LOG_ERR("cert parse failed, ret: 0x%X", (int)ret);
		return ret;
	}

	LOG_INF("The issuer is: %.*s", (int)cert.issuer.val.len, cert.issuer.val.p);
	LOG_INF("Valid: %d/%d/%d - %d/%d/%d", cert.valid_from.day, cert.valid_from.mon,
		cert.valid_from.year, cert.valid_to.day, cert.valid_to.mon, cert.valid_to.year);
	if (mbedtls_x509_time_is_past(&cert.valid_to) ||
	    mbedtls_x509_time_is_future(&cert.valid_from)) {
		LOG_ERR("The certificate expired");
		LOG_ERR("Cert validity: %d/%d/%d - %d/%d/%d", cert.valid_from.day,
			cert.valid_from.mon, cert.valid_from.year, cert.valid_to.day,
			cert.valid_to.mon, cert.valid_to.year);
		ret = -EINVAL;
	}

	mbedtls_x509_crt_free(&cert);
	return ret;
}

psa_status_t get_x506_cert(psa_storage_uid_t uid, unsigned char *cert_der, size_t cert_buff_size,
			   size_t *cert_len)
{
	psa_status_t status;
	status = al_psa_status(psa_ps_get(uid, 0, cert_buff_size, cert_der, cert_len), __func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to get the certificate %d", status);
	}
	return status;
}

static int cert_validate(psa_storage_uid_t uid)
{
	static uint8_t cert_buffer[1024];
	size_t cert_len;
	int ret;
	memset(cert_buffer, 0, sizeof(cert_buffer));
	ret = get_x506_cert(uid, cert_buffer, sizeof(cert_buffer), &cert_len);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("Failed to get cert");
		return ret;
	}
	if ((ret = validate_x509_cert(cert_buffer, cert_len)) != 0) {
		LOG_INF("Cert validation failed:: %d", ret);
	}
	return ret;
}

static bool is_device_prov_done(enum km_key_idx key_idx)
{
	struct psa_storage_info_t p_info;
	int ret = psa_ps_get_info(APP_PS_BASE + key_idx, &p_info);
	if (ret != PSA_SUCCESS) {
		LOG_INF("No record found in PS for certificate for 0x%d", key_idx);
		LOG_DBG("PS storage capacity %d size %d, flage %x", p_info.capacity, p_info.size,
			p_info.flags);
		return false;
	} else {
		LOG_INF("Found existing certificate in PS for key id 0x%d (size %d)", key_idx,
			p_info.size);
		if (p_info.size > 0) {
			km_set_key_status(key_idx, KEY_X_509_CERT_GEN);
		}
	}
	return true;
}

static void cert_mgmt_init()
{
	int ret;
	for (int key_idx = 0; key_idx < KEY_COUNT; key_idx++) {
		struct km_key_context *ctx = km_get_context(key_idx);
		if (ctx == NULL) {
			LOG_ERR("Unable to get the key context for idx:: %d\n", key_idx);
			return;
		}

		if (!is_device_prov_done(key_idx) && ctx->status == KEY_GEN) {

			LOG_INF("Starting provisioning process for 0x%x", ctx->key_id);
			ret = cert_mgmt_do_prov_cert(ctx->key_id);
			if (ret != 0) {
				LOG_ERR("Failed to provision 0x%x\n", ctx->key_id);
				return;
			}
		}

		ret = cert_validate(APP_PS_BASE + key_idx);
		if (ret != 0) {
			LOG_ERR("Cert validation failed for 0x%x\n", ctx->key_id);
			return;
		}
	}
}

/* Certificate management thread */
void cert_mgmt_thread(void)
{
	/* Wait for the network interface to be up. */
	LOG_INF("waiting for network...");
	await_dhcp();
	while (true) {
		if (is_sntp_init_done()) {
			break;
		}
		k_sleep(K_MSEC(10));
	}
	cert_mgmt_init();

	k_work_init_delayable(&cert_revalidate, trigger_cert_revalidate);

	k_work_reschedule(&cert_revalidate,
			  K_SECONDS(CONFIG_CERT_REVALIDATE_IN_DAYS * ONE_DAY_IN_SEC));

	while (true) {
		k_sem_take(&cert_mgmt_thread_sem, K_FOREVER);
		for (int key_idx = 0; key_idx < KEY_COUNT; key_idx++) {
			int ret;
			struct km_key_context *ctx = km_get_context(key_idx);
			if (ctx == NULL) {
				LOG_ERR("Unable to get the key contex for idx:: %d\n", key_idx);
				return;
			}

			ret = cert_validate(APP_PS_BASE + key_idx);
			if (ret != 0) {
				LOG_ERR("Cert validation failed for 0x%x\n", ctx->key_id);
				return;
			}
		}
	}
}

K_THREAD_DEFINE(cert_mgmt, CONFIG_CERT_MGMT_STACK_SIZE, cert_mgmt_thread, NULL, NULL, NULL,
		CERT_MGMT_THREAD_PRIORITY, 0, 0);
