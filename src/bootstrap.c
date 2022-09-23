/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/zephyr.h>
#include <net/socket.h>
#include <net/tls_credentials.h>
#include <net/http_client.h>
#include <nanocbor/nanocbor.h>

#include <bootstrap.h>
#include "test_certs.h"
#include <util_app_log.h>
#include <x509_csr_gen.h>

#include <provision.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#define HTTPS_PORT 1443
#define HTTPS_PORT_TEXT "1443"
#define HOST CONFIG_BOOTSTRAP_SERVER_HOST

/* These tags need to be globally allocated across the app. */
#define APP_CA_CERT_TAG 5
#define APP_SERVER_CRT_TAG 6
#define APP_SERVER_KEY_TAG 7

static sec_tag_t m_sec_tags[] = {
	APP_CA_CERT_TAG,
	APP_SERVER_CRT_TAG,
	APP_SERVER_KEY_TAG,
};

/* DNS lookup data. */
static struct zsock_addrinfo hints;
static struct zsock_addrinfo *haddr;

static const char *cbor_header[] = {
	"Content-Type: application/cbor\r\n",
	0,
};

#define RECV_BUF_LEN 1025

static uint8_t recv_buf[RECV_BUF_LEN];

/* User data for the rest API callback.
 */
struct rest_cb_data {
	enum km_key_idx key_idx;
};

#ifdef DEBUG_WALK_CBOR
/* Walk a CBOR structure, at least with certain fields.  This can help
 * us understand how to use the nanocbor API.
 */
static int walk_cbor(struct nanocbor_value *item)
{
	int kind;
	int res;
	struct nanocbor_value map;
	uint32_t ukey;
	const uint8_t *buf;
	size_t buf_len;

	while (!nanocbor_at_end(item)) {
		kind = nanocbor_get_type(item);
		switch (kind) {
		case NANOCBOR_TYPE_UINT:
			res = nanocbor_get_uint32(item, &ukey);
			if (res < 0)
				return res;
			LOG_INF("uint: %d", ukey);
			break;
		case NANOCBOR_TYPE_BSTR:
			res = nanocbor_get_bstr(item, &buf, &buf_len);
			if (res < 0)
				return res;
			LOG_INF("bstr: %d bytes", buf_len);
			break;
		case NANOCBOR_TYPE_TSTR:
			res = nanocbor_get_tstr(item, &buf, &buf_len);
			if (res < 0)
				return res;
			LOG_INF("tstr: %d bytes", buf_len);
			break;
		case NANOCBOR_TYPE_MAP:
			res = nanocbor_enter_map(item, &map);
			if (res < 0)
				return res;
			LOG_INF("map: %d entries", map.remaining);
			res = walk_cbor(&map);
			if (res < 0)
				return res;
			nanocbor_leave_container(item, &map);
			break;
		default:
			LOG_ERR("Unhandled cbor: %d", kind);
			return -EIO;
		}
	}

	return 0;
}
#endif /* DEBUG_WALK_CBOR */

/* Build a CSR request for the given key.
 *
 * Returns 0 for success, or negative errno on error. */
static int build_csr_req(struct csr_req *req, uint8_t key_idx)
{
	int status = al_psa_status(km_get_uuid(req->uuid, sizeof(req->uuid)), __func__);
	if (status != PSA_SUCCESS) {
		return -EINVAL;
	}

	req->cbor_len = sizeof(req->cbor);
	status = x509_csr_cbor(key_idx,
			       req->cbor,
			       &req->cbor_len,
			       req->uuid,
			       sizeof(req->uuid));
	if (status != PSA_SUCCESS) {
		return -EINVAL;
	}

	return 0;
}

static int decode_csr_response(struct provision_data *prov, const uint8_t *buf, size_t len,
			       struct rest_cb_data *data)
{
	struct nanocbor_value decode;
	struct nanocbor_value map;
	int res;
	uint32_t value;

#ifdef DEBUG_WALK_CBOR
	nanocbor_decoder_init(&decode, buf, len);
	walk_cbor(&decode);
#endif

	nanocbor_decoder_init(&decode, buf, len);

	res = nanocbor_enter_map(&decode, &map);
	if (res < 0) {
		return res;
	}

	/* This first key must be 1 for status. */
	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	if (value != 1) {
		return -EINVAL;
	}

	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	/* The second key must be 2 for the certificate. */
	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	if (value != 2) {
		return -EINVAL;
	}

	switch (data->key_idx) {
	case KEY_CLIENT_TLS:
		res = nanocbor_get_bstr(&map, &prov->tls_cert_der, &prov->tls_cert_der_len);
		if (res < 0) {
			return res;
		}
		prov->present |= PROVISION_TLS_CERT;
		break;
	case KEY_COSE:
		res = nanocbor_get_bstr(&map, &prov->cose_cert_der, &prov->cose_cert_der_len);
		if (res < 0) {
			return res;
		}
		prov->present |= PROVISION_COSE_CERT;
		break;
	case KEY_COUNT:
		break;
	}

	nanocbor_leave_container(&decode, &map);
	return res;
}

static void csr_cb(struct http_response *rsp, enum http_final_call final_data,
			  void *user_data)
{
	struct provision_data prov;
	int res;
	struct rest_cb_data *data = user_data;

	if (final_data == HTTP_DATA_MORE) {
		LOG_INF("Partial data %zd bytes", rsp->data_len);
	} else if (final_data == HTTP_DATA_FINAL) {
		LOG_INF("All data received %zd bytes", rsp->data_len);
	}

	LOG_INF("Response to req");
	LOG_INF("Status %s", rsp->http_status);

	memset(&prov, 0, sizeof(prov));
	res = decode_csr_response(&prov, rsp->body_frag_start, rsp->content_length, data);
	LOG_INF("Result: %d", res);

	if (res >= 0) {
		/* Provided the provisioning worked, store the information in persistent storage. */
		res = provision_store(&prov);
	}

	/* TODO: How should we handle errors here.  Presumably, we won't store
	 * the provision data, and may retry later. */

	switch (data->key_idx) {
	case KEY_CLIENT_TLS:
		LOG_HEXDUMP_INF(prov.tls_cert_der, prov.tls_cert_der_len, "TLS Certificate (DER)");
		break;
	case KEY_COSE:
		LOG_HEXDUMP_INF(prov.cose_cert_der, prov.cose_cert_der_len, "COSE Certificate (DER)");
		break;
	case KEY_COUNT:
		break;
	}
}

static int decode_service_response(struct provision_data *prov, const uint8_t *buf, size_t len)
{
	struct nanocbor_value decode;
	struct nanocbor_value map;
	int res;
	uint32_t value;
	uint32_t port;

#ifdef DEBUG_WALK_CBOR
	nanocbor_decoder_init(&decode, buf, len);
	walk_cbor(&decode);
#endif

	nanocbor_decoder_init(&decode, buf, len);

	res = nanocbor_enter_map(&decode, &map);
	if (res < 0) {
		return res;
	}

	/* The first key must be 1, for the hubname. */
	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	if (value != 1) {
		return -EINVAL;
	}

	res = nanocbor_get_tstr(&map, (const uint8_t **)&prov->hubname, &prov->hubname_len);
	if (res < 0) {
		return res;
	}
	prov->present |= PROVISION_HUBNAME;

	/* The next key must be 2, for the port. */
	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	if (value != 2) {
		return -EINVAL;
	}

	res = nanocbor_get_uint32(&map, &port);
	if (res < 0) {
		return res;
	}
	prov->hubport = port;
	prov->present |= PROVISION_HUBPORT;

	nanocbor_leave_container(&decode, &map);
	return 0;
}

static void service_cb(struct http_response *rsp, enum http_final_call final_data,
		       void *user_data)
{
	struct provision_data prov;
	int res;

	if (final_data == HTTP_DATA_MORE) {
		LOG_INF("Partial data %zd bytes", rsp->data_len);
		return;
	} else if (final_data == HTTP_DATA_FINAL) {
		LOG_INF("Service data received %zd bytes", rsp->data_len);
	} else {
		return;
	}

	LOG_INF("Content len: %d", (int)rsp->content_length);
	LOG_HEXDUMP_INF(rsp->body_frag_start, rsp->content_length, "Content");

	memset(&prov, 0, sizeof(prov));
	res = decode_service_response(&prov, rsp->body_frag_start, rsp->content_length);
	if (res >= 0) {
		/* Store the information we retrieved into the
		 * persistent storage. */
		res = provision_store(&prov);
	} else {
		LOG_ERR("Unable to decode service provisioning data");
	}
}

static int get_bootstrap_addrinfo(void)
{
	int retries = 3;
	int rc = -EINVAL;

	while (retries--) {
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = 0;

		rc = zsock_getaddrinfo(HOST, HTTPS_PORT_TEXT, &hints, &haddr);
		if (rc == 0) {
			LOG_INF("Got DNS for linaroca");
			return 0;
		}
	}

	return rc;
}

/* Set the credentials with Zephyr's API needed to authenticate this
 * connection. */
static int set_bootstrap_cred(void)
{
	int rc;

	/* TODO: This makes this function non-reentrant, especially
	 * from other threads. */
	static bool credentialed;

	if (!credentialed) {
		rc = tls_credential_add(APP_CA_CERT_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, caroot_crt,
					caroot_crt_len);
		if (rc < 0) {
			LOG_ERR("Failed to register public certificate: %d", rc);
			return rc;
		}

		rc = tls_credential_add(APP_SERVER_CRT_TAG, TLS_CREDENTIAL_SERVER_CERTIFICATE,
					bootstrap_crt, bootstrap_crt_len);
		if (rc < 0) {
			LOG_ERR("Failed to register bootstrap certificate: %d", rc);
			return rc;
		}

		rc = tls_credential_add(APP_SERVER_KEY_TAG, TLS_CREDENTIAL_PRIVATE_KEY, bootstrap_key,
					bootstrap_key_len);
		if (rc < 0) {
			LOG_ERR("Failed to register bootstrap certificate key: %d", rc);
			return rc;
		}

		credentialed = true;
	}

	return 0;
}

int bootstrap_open(struct bootstrap *ctx)
{
	int rc;
	rc = get_bootstrap_addrinfo();
	if (rc < 0) {
		return rc;
	}

	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (sock < 0) {
		return sock;
	}

	/* Add credentials. */
	rc = setsockopt(sock, SOL_TLS, TLS_HOSTNAME, HOST, sizeof(HOST));
	if (rc < 0) {
		LOG_ERR("Failed to set %s TLS_HOSTNAME option (%d)",
			"IPv4", -errno);
		return rc;
	}

	rc = set_bootstrap_cred();
	if (rc < 0) {
		LOG_ERR("Failed to set boostrap socket options (%d)", -errno);
		return rc;
	}

	// TODO: How do we get these symbols without bringing in all
	// of the MbedTLS headers?
	int peer_verify = 2;
	rc = zsock_setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify, sizeof(peer_verify));
	if (rc < 0) {
		LOG_ERR("Failed to set peer verify");
		return rc;
	}

	rc = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, m_sec_tags, 3 * sizeof(sec_tag_t));
	if (rc < 0) {
		LOG_ERR("Failed to set tls configuration");
		return rc;
	}

	struct sockaddr_in daddr;

	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(HTTPS_PORT);

	net_ipaddr_copy(&daddr.sin_addr, &net_sin(haddr->ai_addr)->sin_addr);

	/* Attempt to connect */
	rc = connect(sock, (struct sockaddr *)&daddr, sizeof(daddr));
	if (rc < 0) {
		LOG_ERR("Failed to connect to bootstrap: %d", -errno);
		return rc;
	}

	ctx->sock = sock;

	return 0;
}

int bootstrap_close(struct bootstrap *ctx)
{
	return zsock_close(ctx->sock);
}

static int rest_call(struct bootstrap *ctx, unsigned char *payload, size_t payload_len,
		     enum http_method method,
		     const char *url, http_response_cb_t cb,
		     void *cb_data)
{
	int rc;
	struct http_request req;
	memset(&req, 0, sizeof(req));

	req.method = method;
	req.url = url;
	req.host = HOST;
	req.protocol = "HTTP/1.1";
	req.response = cb;
	req.payload = payload;
	req.payload_len = payload_len;
	req.recv_buf = recv_buf;
	req.recv_buf_len = sizeof(recv_buf);
	req.header_fields = cbor_header;

	rc = http_client_req(ctx->sock, &req, 5 * MSEC_PER_SEC, cb_data);
	LOG_INF("Request result: %d", rc);

	return rc < 0 ? rc : 0;
}

int bootstrap_csr(struct bootstrap *ctx, struct csr_req *req, uint8_t key_idx)
{
	/* http_client_req waits to be finished, so the cb will happen
	 * before the function call returns. */
	struct rest_cb_data data = {
		.key_idx = key_idx,
	};

	int rc = build_csr_req(req, key_idx);
	if (rc != 0) {
		return rc;
	}

	return rest_call(ctx, req->cbor, req->cbor_len, HTTP_POST, "/api/v1/cr", csr_cb, &data);
}

int bootstrap_service(struct bootstrap *ctx)
{
	return rest_call(ctx, NULL, 0, HTTP_GET, "/api/v1/ccs", service_cb, NULL);
}
