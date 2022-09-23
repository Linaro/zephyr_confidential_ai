/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cbor_cose.h"

#include "t_cose_common.h"

#include "tfm_sp_log.h"
#include "psa/service.h"
#include "psa/crypto.h"
#include "tfm_huk_deriv_srv_api.h"
#include "nv_ps_counters.h"

/* The algorithm used in COSE */
#define T_COSE_ALGORITHM              T_COSE_ALGORITHM_ES256

#define SERV_NAME "COSE SERVICE"

static psa_status_t
t_cose_err_to_psa_err(enum t_cose_err_t err)
{
	switch (err) {

	case T_COSE_SUCCESS:
		return PSA_SUCCESS;

	case T_COSE_ERR_UNSUPPORTED_HASH:
		return PSA_ERROR_NOT_SUPPORTED;

	case T_COSE_ERR_TOO_SMALL:
		return PSA_ERROR_BUFFER_TOO_SMALL;

	default:
		/* A lot of the errors are not mapped because they are
		 * primarily internal errors that should never happen. They
		 * end up here.
		 */
		return PSA_ERROR_GENERIC_ERROR;
	}
}

psa_status_t tfm_cose_encode_start(psa_key_handle_t key_handle,
				   struct tfm_cose_encode_ctx *me,
				   int32_t cose_alg_id,
				   const struct q_useful_buf *out_buf)
{
	enum t_cose_err_t cose_ret;
	psa_status_t return_value = PSA_SUCCESS;
	int32_t t_cose_options = 0;
	struct t_cose_key inf_val_sign_key;

	t_cose_sign1_sign_init(&(me->signer_ctx), t_cose_options, cose_alg_id);

	inf_val_sign_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;
	inf_val_sign_key.k.key_handle = key_handle;
	t_cose_sign1_set_signing_key(&(me->signer_ctx),
				     inf_val_sign_key,
				     NULL_Q_USEFUL_BUF_C);

	/* Spin up the CBOR encoder */
	QCBOREncode_Init(&(me->cbor_enc_ctx), *out_buf);

	/* This will cause the cose headers to be encoded and written into
	 *  out_buf using me->cbor_enc_ctx
	 */
	cose_ret = t_cose_sign1_encode_parameters(&(me->signer_ctx),
						  &(me->cbor_enc_ctx));
	if (cose_ret) {
		return_value = t_cose_err_to_psa_err(cose_ret);
	}

	QCBOREncode_OpenMap(&(me->cbor_enc_ctx));

	return return_value;
}

psa_status_t tfm_cbor_encode(float inf_val,
			     uint8_t *inf_val_encoded_buf,
			     size_t inf_val_encoded_buf_size,
			     size_t *inf_val_encoded_buf_len)
{
	QCBOREncodeContext cbor_enc_ctx;
	struct q_useful_buf_c inf_val_buf;
	struct q_useful_buf inf_val_encode;
	struct q_useful_buf_c completed_inf_val_encode;
	QCBORError qcbor_result;

	inf_val_encode.ptr = inf_val_encoded_buf;
	inf_val_encode.len = inf_val_encoded_buf_size;

	QCBOREncode_Init(&cbor_enc_ctx, inf_val_encode);

	inf_val_buf.ptr = &inf_val;
	inf_val_buf.len = sizeof(inf_val);

	QCBOREncode_OpenMap(&cbor_enc_ctx);
	QCBOREncode_AddBytesToMapN(&cbor_enc_ctx,
				   EAT_CBOR_LINARO_LABEL_INFERENCE_VALUE,
				   inf_val_buf);
	QCBOREncode_CloseMap(&cbor_enc_ctx);

	qcbor_result = QCBOREncode_Finish(&cbor_enc_ctx, &completed_inf_val_encode);
	if (qcbor_result == QCBOR_ERR_BUFFER_TOO_SMALL) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	} else if (qcbor_result != QCBOR_SUCCESS) {
		return PSA_ERROR_PROGRAMMER_ERROR;
	} else {
		inf_val_encoded_buf = (uint8_t *)completed_inf_val_encode.ptr;
		*inf_val_encoded_buf_len = completed_inf_val_encode.len;
	}

	return PSA_SUCCESS;
}

psa_status_t
tfm_cose_encode_finish(struct tfm_cose_encode_ctx *me,
		       struct q_useful_buf_c *completed_token)
{
	psa_status_t return_value = PSA_SUCCESS;
	/* The completed and signed encoded cose_sign1 */
	struct q_useful_buf_c completed_token_ub;
	QCBORError qcbor_result;
	enum t_cose_err_t cose_return_value;

	QCBOREncode_CloseMap(&(me->cbor_enc_ctx));

	/* -- Finish up the COSE_Sign1. This is where the signing happens -- */
	cose_return_value = t_cose_sign1_encode_signature(&(me->signer_ctx),
							  &(me->cbor_enc_ctx));
	if (cose_return_value) {
		/* Main errors are invoking the hash or signature */
		return_value = t_cose_err_to_psa_err(cose_return_value);
		goto Done;
	}

	/* Finally close off the CBOR formatting and get the pointer and length
	 * of the resulting COSE_Sign1
	 */
	qcbor_result = QCBOREncode_Finish(&(me->cbor_enc_ctx), &completed_token_ub);
	if (qcbor_result == QCBOR_ERR_BUFFER_TOO_SMALL) {
		return_value = PSA_ERROR_BUFFER_TOO_SMALL;
	} else if (qcbor_result != QCBOR_SUCCESS) {
		/* likely from array not closed, too many closes, ... */
		return_value = PSA_ERROR_PROGRAMMER_ERROR;
	} else {
		*completed_token = completed_token_ub;
	}

Done:
	return return_value;
}

psa_status_t
tfm_cose_add_data(struct tfm_cose_encode_ctx *token_ctx, int64_t label,
		  void *data, size_t data_len)
{
	struct q_useful_buf_c data_buf;

	data_buf.ptr = data;
	data_buf.len = data_len;

	QCBOREncode_AddBytesToMapN(&(token_ctx->cbor_enc_ctx),
				   label,
				   data_buf);

	return PSA_SUCCESS;
}

psa_status_t tfm_cose_encode_sign(psa_key_handle_t key_handle,
				  float inf_val,
				  uint8_t *inf_val_encoded_buf,
				  size_t inf_val_encoded_buf_size,
				  size_t *inf_val_encoded_buf_len)
{
	psa_status_t status = PSA_SUCCESS;
	struct tfm_cose_encode_ctx encode_ctx;
	struct q_useful_buf inf_val_encode_sign;
	struct q_useful_buf_c completed_inf_val_encode_sign;

	inf_val_encode_sign.ptr = inf_val_encoded_buf;
	inf_val_encode_sign.len = inf_val_encoded_buf_size;

	/* Get started creating the token. This sets up the CBOR and COSE contexts
	 * which causes the COSE headers to be constructed.
	 */
	status = tfm_cose_encode_start(key_handle,
				       &encode_ctx,
				       T_COSE_ALGORITHM,     /* alg_select   */
				       &inf_val_encode_sign);

	if (status != PSA_SUCCESS) {
		return status;
	}

	status = tfm_cose_add_data(&encode_ctx,
				   EAT_CBOR_LINARO_LABEL_INFERENCE_VALUE,
				   (void *)&inf_val,
				   sizeof(inf_val));
	if (status != PSA_SUCCESS) {
		return status;
	}

#ifdef NV_PS_COUNTERS_SUPPORT
	uint32_t nv_ps_counter = 0;
	status = tfm_get_nv_ps_counter_tracker(NV_PS_COUNTER_ROLLOVER_TRACKER, &nv_ps_counter);
	if (status != PSA_SUCCESS) {
		return status;
	}
	status = tfm_cose_add_data(&encode_ctx,
				   EAT_CBOR_LINARO_NV_COUNTER_ROLL_OVER,
				   (void *)&nv_ps_counter,
				   sizeof(nv_ps_counter));
	if (status != PSA_SUCCESS) {
		return status;
	}

	nv_ps_counter = 0;
	status = tfm_get_nv_ps_counter_tracker(NV_PS_COUNTER_TRACKER, &nv_ps_counter);
	if (status != PSA_SUCCESS) {
		return status;
	}
	status = tfm_cose_add_data(&encode_ctx,
				   EAT_CBOR_LINARO_NV_COUNTER_VALUE,
				   (void *)&nv_ps_counter,
				   sizeof(nv_ps_counter));
	if (status != PSA_SUCCESS) {
		return status;
	}
#endif  /* NV_PS_COUNTERS_SUPPORT */

	/* Finish up creating the token. This is where the actual signature
	 * is generated. This finishes up the CBOR encoding too.
	 */
	status = tfm_cose_encode_finish(&encode_ctx,
					&completed_inf_val_encode_sign);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		return status;
	}

	inf_val_encoded_buf = (uint8_t *)completed_inf_val_encode_sign.ptr;
	*inf_val_encoded_buf_len = completed_inf_val_encode_sign.len;

#if CONFIG_COSE_VERIFY_SIGN_ON_S_SIDE
	/* Verify signature */
	struct t_cose_key inf_val_sign_key;

	inf_val_sign_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;
	inf_val_sign_key.k.key_handle = key_handle;

	struct q_useful_buf_c payload;
	int32_t return_value;
	struct t_cose_sign1_verify_ctx verify_ctx;

	t_cose_sign1_verify_init(&verify_ctx, 0);

	t_cose_sign1_set_verification_key(&verify_ctx, inf_val_sign_key);

	return_value =  t_cose_sign1_verify(&verify_ctx,
					    completed_inf_val_encode_sign,      /* COSE to verify */
					    &payload,                           /* Payload from signed_cose */
					    NULL);                              /* Don't return parameters */

	if (return_value != T_COSE_SUCCESS) {
		log_err_print("failed with %d", return_value);
	} else {
		log_info_print("COSE signature verification succeeded");
	}
#endif
	return status;
}
