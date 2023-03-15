/*
 * Copyright (c) 2021-2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "tfm_huk_deriv_srv.h"
#include "nv_ps_counters.h"

#define LABEL_BUFF_SIZE 40

/* To verify CSR ASN.1 tag and length of the payload */
static psa_status_t tfm_huk_csr_verify(unsigned char *csr_data, size_t csr_len, int tag)
{
	unsigned char *csr_start = csr_data, *csr_end = (csr_data + csr_len);
	size_t len;

	if ((csr_end - csr_start) < 1) {
		return (PSA_ERROR_INSUFFICIENT_DATA);
	}

	if (*csr_start != tag) {
		return (PSA_ERROR_INVALID_ARGUMENT);
	}

	csr_start++;

	/* Check CSR data payload length between 0 to 255 */
	if ((*csr_start & 0x7F) == TFM_HUK_ASN1_DATA_LENGTH_0_255) {
		len = csr_start[1];
		csr_start += 2;
	} else {
		return (PSA_ERROR_NOT_SUPPORTED);
	}

	if (len != ((size_t)(csr_end - csr_start))) {
		return (PSA_ERROR_SERVICE_FAILURE);
	}
	return PSA_SUCCESS;
}

static psa_status_t tfm_encode_random_bytes_to_uuid(uint8_t *random_bytes, size_t random_bytes_len,
						    uint8_t *uuid_buf, size_t uuid_buf_len)
{
	int j = 0;
	int hyphen_index = 8;

	if (random_bytes_len != (KEY_LEN_BYTES / 2)) {
		return PSA_ERROR_INSUFFICIENT_DATA;
	}

	if (uuid_buf_len != UUID_STR_LEN) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}

	for (int i = 0; i < random_bytes_len; i++) {
		if (i == 6) {
			random_bytes[i] =
				(random_bytes[i] & UUID_7TH_BYTE_MASK) | UUID_7TH_BYTE_SET;
		}
		if (i == 8) {
			random_bytes[i] =
				(random_bytes[i] & UUID_9TH_BYTE_MASK) | UUID_9TH_BYTE_SET;
		}

		uuid_buf[j++] = hex_digits[random_bytes[i] >> 4];
		uuid_buf[j++] = hex_digits[random_bytes[i] & 0x0f];

		if (j == hyphen_index) {
			uuid_buf[j++] = '-';
			if (hyphen_index == 23) {
				hyphen_index = 0;
			} else {
				hyphen_index += 5;
			}
		}
	}
	uuid_buf[j] = '\0';
}

static psa_status_t tfm_huk_deriv_unique_key(uint8_t *label, size_t label_size,
					     psa_key_usage_t key_usage_flag,
					     psa_key_handle_t *key_handle)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

	if (label == NULL || label_size == 0) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Set the key attributes for the key */
	psa_set_key_usage_flags(&attributes, key_usage_flag);

	/* Set the algorithm, key type and the number of bits of the key. This is
	 * mandatory for key derivation. Setting these attributes will ensure that
	 * derived key is in accordance with the standard, if any.
	 */
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(KEY_LEN_BYTES));

	/* Set up a key derivation operation with HUK derivation as the alg */
	status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Supply the UUID label as an input to the key derivation */
	status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, label,
						label_size);
	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
					      TFM_BUILTIN_KEY_ID_HUK);
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Create the storage key from the key derivation operation */
	status = psa_key_derivation_output_key(&attributes, &op, key_handle);
	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	return PSA_SUCCESS;

err_release_op:
	(void)psa_key_derivation_abort(&op);

	return status;
}

static huk_key_context_t *tfm_huk_get_context(huk_key_idx_t idx)
{
	static huk_key_context_t huk_ctx[HUK_KEY_COUNT] = {0};

	if ((idx < HUK_KEY_COSE) || (idx >= HUK_KEY_COUNT)) {
		log_err_print("Invalid argument %d", PSA_ERROR_INVALID_ARGUMENT);
		return NULL;
	}

	return &huk_ctx[idx];
}

static psa_status_t tfm_huk_key_context_init(huk_key_idx_t idx, psa_key_id_t key_id,
					     huk_key_stat_t stat, psa_key_handle_t key_handle)
{
	if ((idx < HUK_KEY_COSE) || (idx >= HUK_KEY_COUNT)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	huk_key_context_t *ctx = tfm_huk_get_context(idx);
	if (ctx == NULL) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	ctx->key_id = key_id;
	ctx->status = stat;
	ctx->key_handle = key_handle;
	return PSA_SUCCESS;
}

static psa_status_t tfm_huk_key_get_idx(psa_key_id_t key_id, huk_key_idx_t *idx)
{
	/* Map the Key id to key idx */
	if (key_id == HUK_COSE) {
		*idx = HUK_KEY_COSE;
	} else {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return PSA_SUCCESS;
}

static psa_status_t tfm_huk_key_get_status(huk_key_idx_t idx, huk_key_stat_t *stat)
{
	if ((idx < HUK_KEY_COSE) || (idx >= HUK_KEY_COUNT)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	huk_key_context_t *ctx = tfm_huk_get_context(idx);
	if (ctx == NULL) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	*stat = ctx->status;
	return PSA_SUCCESS;
}

static psa_status_t tfm_huk_key_set_status(huk_key_idx_t idx, huk_key_stat_t stat)
{
	if ((idx < HUK_KEY_COSE) || (idx >= HUK_KEY_COUNT)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	huk_key_context_t *ctx = tfm_huk_get_context(idx);

	if (ctx == NULL) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	ctx->status = stat;
	return PSA_SUCCESS;
}

static psa_status_t tfm_huk_key_handle_get(psa_key_id_t key_id, psa_key_handle_t *handle)
{
	huk_key_idx_t idx;
	psa_status_t status;

	status = tfm_huk_key_get_idx(key_id, &idx);
	if (status != PSA_SUCCESS) {
		return status;
	}

	huk_key_context_t *ctx = tfm_huk_get_context(idx);
	if (ctx == NULL) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	*handle = ctx->key_handle;
	return PSA_SUCCESS;
}

static psa_status_t tfm_huk_ec_key_status(psa_msg_t *msg)
{
	psa_key_id_t key_id;
	huk_key_idx_t idx;
	huk_key_stat_t stat;
	psa_status_t status = PSA_SUCCESS;
	_Bool set_sts = false;

	/* Check size of invec parameters */
	if (msg->in_size[0] != sizeof(psa_key_id_t)) {
		return PSA_ERROR_PROGRAMMER_ERROR;
	}
	psa_read(msg->handle, 0, &key_id, msg->in_size[0]);
	psa_read(msg->handle, 1, &set_sts, msg->in_size[1]);

	status = tfm_huk_key_get_idx(key_id, &idx);
	if (status != PSA_SUCCESS) {
		return status;
	}
	if (set_sts) {
		psa_read(msg->handle, 2, &stat, msg->in_size[2]);
		if (stat != HUK_X_509_CERT_GEN) {
			return PSA_ERROR_INVALID_ARGUMENT;
		}

		status = tfm_huk_key_set_status(idx, stat);
		if (status != PSA_SUCCESS) {
			return status;
		}
	} else {
		status = tfm_huk_key_get_status(idx, &stat);
		if (status != PSA_SUCCESS) {
			return status;
		}
		psa_write(msg->handle, 0, &stat, sizeof(huk_key_stat_t));
	}

	return status;
}

/**
 * Generate EC Key
 */
static psa_status_t tfm_huk_deriv_ec_key(const uint8_t *rx_label, const psa_key_id_t key_id,
					 psa_key_usage_t key_usage_flag)
{
	psa_status_t status = PSA_SUCCESS;
	huk_key_idx_t idx;
	huk_key_stat_t stat;
	uint8_t label[LABEL_BUFF_SIZE] = {0};
	psa_key_handle_t tflm_cose_key_handle = 0;

	status = tfm_huk_key_get_idx(key_id, &idx);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = tfm_huk_key_get_status(idx, &stat);
	if (status != PSA_SUCCESS) {
		return status;
	}

	if (stat == HUK_X_509_CERT_GEN || stat == HUK_KEY_GEN) {
		return PSA_SUCCESS;
	}

	if (LABEL_BUFF_SIZE > (strlen((char *)rx_label) + strlen(LABEL))) {
		/* Add LABEL to rx_label to create unique label. */
		strcpy((char *)label, (char *)rx_label);
		strcat((char *)label, LABEL);
	} else {
		log_err_print("Insufficient memory to store label");
		return PSA_ERROR_INSUFFICIENT_MEMORY;
	}

	/* For MPS2 AN521 platform, TF-M always returns a 16-byte sample key
	 * as the HUK derived key. But the size of EC private key is 32-bytes.
	 * Therefore, we decided to call HUK based key derivation twice.
	 */
	status = tfm_huk_deriv_unique_key(label, strlen((char *)label), key_usage_flag,
					  &tflm_cose_key_handle);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = tfm_huk_key_context_init(idx, key_id, HUK_KEY_GEN, tflm_cose_key_handle);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		return status;
	}

	log_info_print("Successfully derived the key for %s", rx_label);

	return status;
}

void tfm_huk_ec_keys_init()
{
	psa_status_t status = PSA_SUCCESS;
	/** These are the hpke_info passed to key derivation for generating
	 *  two unique keys - Device client TLS, Device COSE SIGN/Encrypt.
	 */
	const char *hpke_info[1] = {"HUK_COSE"};

	status = tfm_huk_deriv_ec_key((const uint8_t *)hpke_info[0], HUK_COSE,
				      (PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH));
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		goto err;
	}

	return;
err:
	psa_panic();
}

static psa_status_t tfm_huk_export_pubkey(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	psa_key_id_t key_id = 0;
	psa_key_handle_t key_handle;
	uint8_t data_out[65] = {0}; /* EC public key = 65 bytes. */
	size_t data_len;

	psa_read(msg->handle, 0, &key_id, msg->in_size[0]);
	status = tfm_huk_key_handle_get(key_id, &key_handle);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		goto err;
	}

	status = psa_export_public_key(key_handle, data_out, sizeof(data_out), &data_len);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		goto err;
	}

	psa_write(msg->handle, 0, data_out, data_len);
err:
	return status;
}

static psa_status_t tfm_huk_cose_encode_sign(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	huk_enc_format_t enc_format;
	uint8_t inf_val_encoded_buf[msg->out_size[0]];
	size_t inf_val_encoded_buf_len = 0;
	float inf_value = 0;
	psa_key_handle_t key_handle;

	psa_read(msg->handle, 1, &enc_format, msg->in_size[1]);
	psa_read(msg->handle, 0, &inf_value, msg->in_size[0]);

	if (enc_format == HUK_ENC_CBOR) {
		status = tfm_cbor_encode(inf_value, inf_val_encoded_buf, msg->out_size[0],
					 &inf_val_encoded_buf_len);
		if (status != PSA_SUCCESS) {
			log_err_print("failed with %d", status);
			return status;
		}
	} else if (enc_format == HUK_ENC_COSE_SIGN1) {
		status = tfm_huk_key_handle_get(HUK_COSE, &key_handle);
		if (status != PSA_SUCCESS) {
			log_err_print("failed with %d", status);
			return status;
		}

#ifdef NV_PS_COUNTERS_SUPPORT
		tfm_inc_nv_ps_counter_tracker(NV_PS_COUNTER_TRACKER);
#endif

		status = tfm_cose_encode_sign(key_handle, inf_value, inf_val_encoded_buf,
					      msg->out_size[0], &inf_val_encoded_buf_len);
		if (status != PSA_SUCCESS) {
			log_err_print("failed with %d", status);
			return status;
		}

#ifdef NV_PS_COUNTERS_SUPPORT
		static _Bool overflow_happen = false;
		uint32_t nv_ps_counter = 0;
		tfm_get_nv_ps_counter_tracker(NV_PS_COUNTER_TRACKER, &nv_ps_counter);
		if (nv_ps_counter == NV_PS_COUNTER_ROLLOVER_MAX) {
			tfm_inc_nv_ps_counter_tracker(NV_PS_COUNTER_ROLLOVER_TRACKER);
			status = psa_write_nv_ps_counter(NV_PS_COUNTER_ROLLOVER_TRACKER);
			if (status != PSA_SUCCESS) {
				log_err_print(
					"Failed to overwrite nv_ps_counter_rollover_uid! (%d)\n",
					status);
				return;
			}
			/* Reset the NV tracker counter */
			status = tfm_set_nv_ps_counter_tracker(NV_PS_COUNTER_TRACKER, 0);
			if (status != PSA_SUCCESS) {
				log_err_print(
					"Failed to overwrite nv_ps_counter_rollover_uid! (%d)\n",
					status);
				return;
			}
			overflow_happen = true;
		}

		if (((nv_ps_counter % NV_COUNTER_TRACKER_THRESHOLD_LIMIT) == 0) ||
		    overflow_happen) {
			status = psa_write_nv_ps_counter(NV_PS_COUNTER_TRACKER);
			if (status != PSA_SUCCESS) {
				log_err_print("Failed to overwrite nv_ps_counter_uid! (%d)\n",
					      status);
				return status;
			}

			if (overflow_happen) {
				log_info_print("NV counter overflow %d", nv_ps_counter);
				overflow_happen = false;
			}
		}
#endif

	} else if (enc_format == HUK_ENC_COSE_ENCRYPT0) {
		log_err_print(" COSE ENCRYPT0 encode format is not supported");
		return PSA_ERROR_NOT_SUPPORTED;
	} else {
		log_err_print(" Invalid encode format");
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	psa_write(msg->handle, 0, inf_val_encoded_buf, inf_val_encoded_buf_len);
	psa_write(msg->handle, 1, &inf_val_encoded_buf_len, sizeof(inf_val_encoded_buf_len));
	return status;
}

/* Calculate the SHA256 hash value of the given CSR payload and sign the hash
 * value using the private key of the given key ID.
 */
static psa_status_t tfm_huk_hash_sign_csr(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	psa_algorithm_t psa_alg_id = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
	psa_key_handle_t key_handle;
	size_t signature_len;
	unsigned char hash[64];
	psa_key_id_t key_id = 0;
	size_t csr_data_size = msg->in_size[1];
	uint8_t csr_data[csr_data_size], sig[64];
	psa_hash_operation_t hash_operation = PSA_HASH_OPERATION_INIT;
	size_t hash_len;
	psa_algorithm_t hash_alg = PSA_ALG_SHA_256;

	psa_read(msg->handle, 0, &key_id, msg->in_size[0]);
	psa_read(msg->handle, 1, csr_data, msg->in_size[1]);
	status = tfm_huk_key_handle_get(key_id, &key_handle);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		return status;
	}

	/* Verify CSR ASN.1 tag and length of the payload in bytes to
	 * avoid fake payload getting signed by this service
	 */
	status = tfm_huk_csr_verify(csr_data, msg->in_size[1],
				    TFM_HUK_ASN1_CONSTRUCTED | TFM_HUK_ASN1_SEQUENCE);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		goto err;
	} else {
		log_info_print("Verified ASN.1 tag and length of the payload");
	}

	if (!PSA_ALG_IS_ECDSA(psa_alg_id)) {
		status = PSA_ERROR_NOT_SUPPORTED;
		goto err;
	}
	/* Calculate the SHA256 hash value of the CSR data using PSA crypto service */
	status = psa_hash_setup(&hash_operation, hash_alg);
	if (status != PSA_SUCCESS) {
		goto err;
	}

	status = psa_hash_update(&hash_operation, csr_data, csr_data_size);
	if (status != PSA_SUCCESS) {
		goto err;
	}

	status = psa_hash_finish(&hash_operation, hash, sizeof(hash), &hash_len);
	if (status != PSA_SUCCESS) {
		goto err;
	}

	/* Sign the hash value using PSA crypto service */
	status = psa_sign_hash(key_handle, psa_alg_id, hash, hash_len, sig, /* Sig buf */
			       sizeof(sig),				    /* Sig buf size */
			       &signature_len);				    /* Sig length */
	if (status != PSA_SUCCESS) {
		goto err;
	}

#if PSA_HUK_HASH_SIGN_VERIFY
	status = psa_verify_hash(key_handle, psa_alg_id, hash, hash_len, sig, /* Sig buf */
				 signature_len);			      /* Sig length */

	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		goto err;
	} else {
		log_info_print("hash sign verification passed");
	}
#endif

	psa_write(msg->handle, 0, sig, signature_len);
	psa_write(msg->handle, 1, &signature_len, sizeof(signature_len));
err:
	return status;
}

/* Generates an UUID based on
 * https://datatracker.ietf.org/doc/html/rfc4122#section-4.4
 */
static psa_status_t tfm_huk_gen_uuid(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	size_t uuid_length;
	static uint8_t uuid_encoded[37] = {0};
	uint8_t uuid[32] = {0};
	uint8_t uuid_label[LABEL_BUFF_SIZE] = {0};
	static uint8_t is_uuid_generated = 0;
	psa_key_handle_t key_handle = 0;
	/* Populate uuid_label from label macro. */
	if (LABEL_BUFF_SIZE > strlen(LABEL_UUID)) {
		strcpy((char *)uuid_label, LABEL_UUID);
	} else {
		log_err_print("Insufficient memory to store label");
		return PSA_ERROR_INSUFFICIENT_MEMORY;
	}

	if (!is_uuid_generated) {
		status = tfm_huk_deriv_unique_key(uuid_label, strlen((char *)uuid_label),
						  PSA_KEY_USAGE_EXPORT, &key_handle);
		if (status != PSA_SUCCESS) {
			return status;
		}
		status = psa_export_key(key_handle, uuid, sizeof(uuid), &uuid_length);
		if (status != PSA_SUCCESS) {
			return status;
		}

		tfm_encode_random_bytes_to_uuid(uuid, (uuid_length / 2), uuid_encoded,
						sizeof(uuid_encoded));
		is_uuid_generated = 1;
		log_info_print("Generated UUID: %s", uuid_encoded);
	}
	psa_write(msg->handle, 0, uuid_encoded, sizeof(uuid_encoded));
	return status;
}

static psa_status_t tfm_huk_cose_aat_sign(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	uint8_t encoded_buf[msg->out_size[0]];
	size_t encoded_buf_len = 0;
	psa_key_handle_t key_handle;
	infer_version_t tflm_infer_ver;
	infer_version_t utvm_infer_ver;

	psa_read(msg->handle, 0, &tflm_infer_ver, msg->in_size[0]);
	psa_read(msg->handle, 1, &utvm_infer_ver, msg->in_size[1]);

	status = tfm_huk_key_handle_get(HUK_COSE, &key_handle);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		goto err;
	}

	status = tfm_cose_enc_aat_sign(key_handle, &tflm_infer_ver, &utvm_infer_ver, encoded_buf,
				       msg->out_size[0], &encoded_buf_len);
	if (status != PSA_SUCCESS) {
		log_err_print("AAT creation failed with %d", status);
		goto err;
	}

	psa_write(msg->handle, 0, encoded_buf, encoded_buf_len);
	psa_write(msg->handle, 1, &encoded_buf_len, sizeof(encoded_buf_len));
err:
	return status;
}

static void tfm_huk_deriv_signal_handle(psa_signal_t signal, signal_handler_t pfn)
{
	psa_status_t status;
	psa_msg_t msg;

	status = psa_get(signal, &msg);
	switch (msg.type) {
	case PSA_IPC_CONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	case PSA_IPC_CALL:
		status = pfn(&msg);
		psa_reply(msg.handle, status);
		break;
	case PSA_IPC_DISCONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	default:
		psa_panic();
	}
}

psa_status_t tfm_huk_deriv_req_mgr_init(void)
{
	psa_signal_t signals = 0;

	/* EC keys init */
	tfm_huk_ec_keys_init();

#ifdef NV_PS_COUNTERS_SUPPORT
	/* Initialize all NV tracker counters */
	psa_nv_ps_counter_tracker_init();
#endif

	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
		if (signals & TFM_HUK_EXPORT_PUBKEY_SIGNAL) {
			tfm_huk_deriv_signal_handle(TFM_HUK_EXPORT_PUBKEY_SIGNAL,
						    tfm_huk_export_pubkey);
		} else if (signals & TFM_HUK_EC_KEY_STAT_SIGNAL) {
			tfm_huk_deriv_signal_handle(TFM_HUK_EC_KEY_STAT_SIGNAL,
						    tfm_huk_ec_key_status);
		} else if (signals & TFM_HUK_COSE_CBOR_ENC_SIGN_SIGNAL) {
			tfm_huk_deriv_signal_handle(TFM_HUK_COSE_CBOR_ENC_SIGN_SIGNAL,
						    tfm_huk_cose_encode_sign);
		} else if (signals & TFM_HUK_GEN_UUID_SIGNAL) {
			tfm_huk_deriv_signal_handle(TFM_HUK_GEN_UUID_SIGNAL, tfm_huk_gen_uuid);
		} else if (signals & TFM_HUK_HASH_SIGN_SIGNAL) {
			tfm_huk_deriv_signal_handle(TFM_HUK_HASH_SIGN_SIGNAL,
						    tfm_huk_hash_sign_csr);
		} else if (signals & TFM_HUK_COSE_AAT_SIGN_SIGNAL) {
			tfm_huk_deriv_signal_handle(TFM_HUK_COSE_AAT_SIGN_SIGNAL,
						    tfm_huk_cose_aat_sign);
		} else {
			psa_panic();
		}
	}

	return PSA_SUCCESS;
}
