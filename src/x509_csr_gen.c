/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/zephyr.h>
#include <zephyr/data/json.h>
#include <nanocbor/nanocbor.h>

#include "util_app_log.h"
#include "x509_csr_gen.h"

/*
 * Declare a reference to the application logging interface.
 */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

struct csr_json_struct {
	const char *CSR;
};

static const struct json_obj_descr csr_json_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct csr_json_struct, CSR, JSON_TOK_STRING)
};

int x509_csr_hash_calc(const uint8_t *buf,
		       const size_t buf_len,
		       uint8_t *hash)
{
	mbedtls_md_context_t md_ctx;

	mbedtls_md_setup(&md_ctx,
			 mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			 0);
	mbedtls_md_starts(&md_ctx);
	mbedtls_md_update(&md_ctx, buf, buf_len);

	if (mbedtls_md_finish(&md_ctx, hash)) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	return 0;
}

static int x509_csr_hash_sign(enum km_key_idx key_idx,
			      uint8_t *csr_data,
			      size_t csr_data_size,
			      uint8_t *sig,
			      size_t sig_size,
			      size_t *sig_len)
{
	unsigned char hash[64];
	struct km_key_context *ctx = km_get_context(key_idx);
	int ret = PSA_SUCCESS;

	ret = x509_csr_hash_calc((uint8_t *)csr_data,
				 csr_data_size,
				 hash);
	if (ret != 0) {
		printf("Hash calc failed with %d\n", ret);
		return(ret);
	}

	psa_algorithm_t psa_alg_id = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
	/* Sign the hash value using PSA crypto service */
	ret = psa_sign_hash(ctx->key_handle,
			    psa_alg_id,
			    hash,
			    64,
			    sig,                        /* Sig buf */
			    sig_size,                   /* Sig buf size */
			    sig_len);                   /* Sig length */
	if (ret != 0) {
		printf("sign hash failed with %d\n", ret);
		return(ret);
	}

	return ret;
}

static int x509_csr_write_mpibuf(unsigned char **p, unsigned char *start,
				 size_t n_len)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	size_t len = 0;

	if ((size_t)(*p - start) < n_len) {
		return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	len = n_len;
	*p -= len;
	memmove(*p, start, len);

	/* ASN.1 DER encoding requires minimal length, so skip leading 0s.
	 * Neither r nor s should be 0, but as a failsafe measure, still detect
	 * that rather than overflowing the buffer. */
	while (len > 0 && **p == 0x00) {
		++(*p);
		--len;
	}

	/* this is only reached if the signature was invalid */
	if (len == 0) {
		return(MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
	}

	/* if the msb is 1, ASN.1 requires that we prepend a 0.
	 * Neither r nor s can be 0, so we can assume len > 0 at all times. */
	if (**p & 0x80) {
		if (*p - start < 1) {
			return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
		}

		*--(*p) = 0x00;
		len += 1;
	}

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(p,
						    start,
						    MBEDTLS_ASN1_INTEGER));

	return((int) len);
}

static int x509_csr_write_sign(enum km_key_idx key_idx,
			       uint8_t *csr_data,
			       size_t csr_data_size,
			       uint8_t *sig,
			       size_t sig_size,
			       size_t *sig_len)
{
	unsigned char *p = sig + sig_size;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	size_t len = 0;
	struct km_key_context *ctx = km_get_context(key_idx);
	psa_status_t status = PSA_SUCCESS;

	if (ctx == NULL) {
		return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	}

	/* Send the CSR payload to tfm service to sign,
	 * return filled sig buffer with hash signature
	 */
	if (ctx->key_id == KEY_ID_CLIENT_TLS) {
		ret = x509_csr_hash_sign(key_idx,
					 csr_data,
					 csr_data_size,
					 sig,
					 sig_size,
					 sig_len);
		if (status != PSA_SUCCESS) {
			return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
		}
	} else if (ctx->key_id == KEY_ID_COSE) {
		status =  psa_huk_hash_sign(&ctx->key_id,
					    csr_data,
					    csr_data_size,
					    sig,
					    sig_size,
					    sig_len);
		if (status != PSA_SUCCESS) {
			return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
		}
	}

	const size_t rs_len = *sig_len / 2;
	/* transcode sign to ASN.1 sequence */
	MBEDTLS_ASN1_CHK_ADD(len, x509_csr_write_mpibuf(&p, sig + rs_len, rs_len));
	MBEDTLS_ASN1_CHK_ADD(len, x509_csr_write_mpibuf(&p, sig, rs_len));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, sig, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(&p,
						    sig,
						    MBEDTLS_ASN1_CONSTRUCTED |
						    MBEDTLS_ASN1_SEQUENCE));

	memmove(sig, p, len);
	*sig_len = len;
	return 0;

}

static int x509_csr_der(mbedtls_x509write_csr *ctx,
			unsigned char *buf,
			size_t size,
			const enum km_key_idx key_idx)
{
	unsigned char *sig;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	const char *sig_oid;
	size_t sig_oid_len = 0;
	unsigned char *c, *c2;
	size_t public_key_len = 0, sig_and_oid_len = 0, sig_len;
	size_t len = 0;
	mbedtls_pk_type_t pk_alg = MBEDTLS_PK_ECDSA;
	size_t sig_size = MBEDTLS_PK_SIGNATURE_MAX_SIZE;

	if ((sig = mbedtls_calloc(1, MBEDTLS_PK_SIGNATURE_MAX_SIZE)) == NULL) {
		return(MBEDTLS_ERR_X509_ALLOC_FAILED);
	}
	/* Write the CSR backwards starting from the end of buf */
	c = buf + size;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(
				     &c, buf,
				     MBEDTLS_ASN1_CONSTRUCTED |
				     MBEDTLS_ASN1_CONTEXT_SPECIFIC));

	if ((ret = km_enc_pubkey_der(key_idx,
				     buf,
				     c - buf,
				     &public_key_len)) != 0) {
		return ret;
	}

	c -= public_key_len;
	len += public_key_len;

	/*
	 *  Subject  ::=  Name
	 */
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c,
							   buf,
							   ctx->MBEDTLS_PRIVATE(subject)));

	/*
	 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	 */
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf, 0));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(
				     &c, buf,
				     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	/*
	 * Sign the written CSR data into the sig buffer
	 * Note: hash errors can happen only after an internal error
	 */
	ret = x509_csr_write_sign(key_idx,
				  (uint8_t *)c,
				  len,
				  (uint8_t *)sig,
				  sig_size,
				  &sig_len);
	if (ret != 0) {
		return(ret);
	}

	if ((ret = mbedtls_oid_get_oid_by_sig_alg(pk_alg,
						  ctx->MBEDTLS_PRIVATE(md_alg),
						  &sig_oid,
						  &sig_oid_len)) != 0) {
		return(ret);
	}

	/*
	 * Move the written CSR data to the start of buf to create space for
	 * writing the signature into buf.
	 */
	memmove(buf, c, len);

	/*
	 * Write sig and its OID into buf backwards from the end of buf.
	 * Note: mbedtls_x509_write_sig will check for c2 - ( buf + len ) < sig_len
	 * and return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL if needed.
	 */
	c2 = buf + size;
	MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len,
			     mbedtls_x509_write_sig(&c2,
						    buf + len,
						    sig_oid,
						    sig_oid_len,
						    sig,
						    sig_len));

	/*
	 * Compact the space between the CSR data and signature by moving the
	 * CSR data to the start of the signature.
	 */
	c2 -= len;
	memmove(c2, buf, len);

	/* ASN encode the total size and tag the CSR data with it. */
	len += sig_and_oid_len;
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c2, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(
				     &c2,
				     buf,
				     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	/* Zero the unused bytes at the start of buf */
	memset(buf, 0, c2 - buf);

	mbedtls_free(sig);

	return((int) len);
}

#if defined(MBEDTLS_PEM_WRITE_C)
int x509_csr_sign_request(mbedtls_x509write_csr *ctx,
			  unsigned char *buf,
			  size_t size,
			  const enum km_key_idx key_idx,
			  x509_csr_fmt_t fmt)
{
	int ret = 0;
	size_t olen = 0;

	/* Generate CSR in DER format */
	if ((ret = x509_csr_der(ctx,
				buf,
				size,
				key_idx)) < 0) {
		return(ret);
	}
	if (fmt == CSR_PEM_FORMAT || fmt == CSR_JSON_FORMAT) {
		/* Convert CSR from DER to PEM format using MbedTLS */
		if ((ret = mbedtls_pem_write_buffer(X509_CSR_PEM_BEGIN,
						    X509_CSR_PEM_END,
						    buf + size - ret,
						    ret,
						    buf,
						    size,
						    &olen)) != 0) {
			return(ret);
		}
	}
	return(ret);
}

/**
 * @brief Generates device certificate signing request (CSR) using Mbed TLS
 * X.509 and HUK CSR ROT service.
 */
int x509_csr_generate(const enum km_key_idx key_idx,
		      unsigned char *csr,
		      size_t csr_len,
		      unsigned char *uuid,
		      size_t uuid_size,
		      x509_csr_fmt_t fmt)
{
	int ret;
	struct km_key_context *ctx = km_get_context(key_idx);
	mbedtls_x509write_csr req;

	if (ctx == NULL) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* length of CSR subject name is calculated as
	 * strlen(O=Linaro,CN=) + UUID length + OU lenth + null character
	 */
	char csr_subject_name[80] = { 0 };

	printf("\nGenerating X.509 CSR for '%s' key:\n", ctx->label);

	/* CSR subject name: O=Linaro,CN= <UUID>,OU=<Key label> */
	sprintf(csr_subject_name, "%s%s%s%s%s", X509_CSR_SUB_ORG,
		",CN=", uuid, ",OU=", ctx->label);

	printf("Subject: %s\n", csr_subject_name);

	/* Initialize Mbed TLS structures. */
	mbedtls_x509write_csr_init(&req);
	memset(csr, 0, csr_len);

	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);

	/* Adding subject name to CSR */
	ret = mbedtls_x509write_csr_set_subject_name(&req, csr_subject_name);
	if (ret != 0) {
		LOG_ERR("Setting a CSR subject name failed with error %d", ret);
		goto err;
	}

	/* Create device Certificate Signing Request */
	ret = x509_csr_sign_request(&req,
				    csr,
				    csr_len,
				    key_idx,
				    fmt);
	if (ret < 0) {
		LOG_ERR("CSR PEM format generation failed with error -0x%04x",
			(unsigned int) -ret);
		goto err;
	}

	al_dump_log();

err:
	al_dump_log();
	mbedtls_x509write_csr_free(&req);
	return ret;
}

psa_status_t x509_csr_cbor(const enum km_key_idx key_idx,
			   unsigned char *csr_cbor,
			   size_t *csr_cbor_len,
			   unsigned char *uuid,
			   size_t uuid_size)
{
	struct km_key_context *ctx = km_get_context(key_idx);
	int ret = PSA_SUCCESS;

	if (ctx == NULL) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	printf("\nGenerating X.509 CSR for '%s' key:\n", ctx->label);

	/* Generate CSR in DER format */
	ret = x509_csr_generate(key_idx,
				csr_cbor,
				*csr_cbor_len,
				uuid,
				uuid_size,
				CSR_DER_FORMAT);
	if (ret < 0) {
		goto err;
	}

	/* The above put the DER encoded packet at the end of the
	 * buffer. */
	size_t pos = *csr_cbor_len - ret;
	printf("cert starts at 0x%x into buffer\n", *csr_cbor_len - ret);

	/* Wrap the data in a single element CBOR array with the DER
	 * data as a bstr. */
	nanocbor_encoder_t encoder;
	nanocbor_encoder_init(&encoder, csr_cbor, pos);

	/* TODO: Handle overflow better. */
	nanocbor_fmt_array(&encoder, 1);
	nanocbor_fmt_bstr(&encoder, ret);

	memcpy(encoder.cur, csr_cbor + (*csr_cbor_len - ret), ret);

	*csr_cbor_len = encoder.len + ret;

	return PSA_SUCCESS;
err:
	al_dump_log();

	return ret;
}

psa_status_t x509_csr_json_encode(unsigned char *csr,
				  unsigned char *csr_json_buff,
				  size_t csr_json_buff_len)
{
	psa_status_t status = PSA_SUCCESS;


	struct csr_json_struct csr_json = {
		.CSR = csr
	};

	/*
	 * Encoding CSR as JSON
	 */
	status = json_obj_encode_buf(csr_json_descr,
				     ARRAY_SIZE(csr_json_descr),
				     &csr_json,
				     csr_json_buff,
				     csr_json_buff_len);
	if (status != 0) {
		LOG_ERR("CSR encoding to JSON format failed with error 0x%04x",
			status);
	}
	return status;
}

#endif  /* MBEDTLS_PEM_WRITE_C */
