/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __PROVISION_H__
#define __PROVISION_H__

#include <zephyr/zephyr.h>

#include "psa/error.h"
#include "key_mgmt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Base for persistent storage used by this app.
 */
#define APP_PS_BASE  0x3e28e8993c690000

/** Device certificate.  Returned from CA server.
 */
#define APP_PS_TLS_CERT (APP_PS_BASE + 0x0001)

/** MQTT Broker hub name.  Stored as a string.
 */
#define APP_PS_HUBNAME (APP_PS_BASE + 0x0002)

/** MQTT Broker port.  Stored as a uint16_t.
 */
#define APP_PS_HUBPORT (APP_PS_BASE + 0x0003)

/** Enum describing which fields are populated.
 */
enum provision_present {
	PROVISION_TLS_CERT = 1 << 0,
	PROVISION_HUBNAME = 1 << 1,
	PROVISION_HUBPORT = 1 << 2,
	PROVISION_COSE_CERT = 1 << 3,
};

/** Bits for all provision data. */
#define ALL_PROVISION_DATA (PROVISION_TLS_CERT | PROVISION_HUBNAME | PROVISION_HUBPORT \
			    | PROVISION_COSE_CERT)

/** Mask for provisioning data needed to speak with the MQTT TLS
 * server. */
#define PROV_MASK_TLS (PROVISION_TLS_CERT | PROVISION_HUBNAME | PROVISION_HUBPORT)

/**
 * @brief Provisioning data.
 *
 * Represents the device provisioned data.  The pointers point to data outside
 * of this struct, which for cbor fetched data points to the original buffer,
 * and for data retrieved from persistent storage, allocated from a buffer.
 *
 * Not all of the data may be present, and `present` indicates
 * which fields are populated.
 */
struct provision_data {
	/** Bits that indicate which fields are populated in the
	 * struct. */
	enum provision_present present;
        /** The TLS client certificate, as signed by the CA.  Encoded in DER format. */
        const uint8_t *tls_cert_der;
        /** The length of the certificate, in bytes. */
        size_t tls_cert_der_len;
	/** The COSE client certificate, as signed by the CA.  Encoded in DER format. */
	const uint8_t *cose_cert_der;
	/** The length of the COSE certificate, in bytes. */
	size_t cose_cert_der_len;
        /** The name of the Azure IoT hub used by this device.  This string will
         * be NULL terminated when retrieved from storage, but is not
         * necessarily terminated when fetched from CBOR. */
        const char *hubname;
        /** The length, in bytes, of the hubname. */
        size_t hubname_len;
        /** The port used to contact the MQTT server. */
        uint16_t hubport;
};

/**
 * @brief Wait until provisioning data is available.
 *
 * Blocks the caller until we have provisioning data available.  If the
 * provisioning has already been aquired, and is stored in persistent storage,
 * returns immediately.  Otherwise, will block until the bootstrap server has
 * returned this information.
 */
int provision_wait(enum provision_present mask);

/**
 * @brief Set or create provisioning data.
 *
 * Stores the given provisioning data in persistent storage.  The pointers are
 * assumed to be held in something like a CBOR buffer, and will not outlive this
 * call.
 */
int provision_store(const struct provision_data *prov);

/**
 * @brief Read provisioning data.
 *
 * Attempts to read the provisioning data from non-volatile storage.  The
 * variable-sized entries will be placed into #buf, which has #buf_len bytes of
 * space available.
 *
 * @return If the buffer is not large enough to contain the results, will return
 * -ENOSPC.  If the persistent storage values are not present, will return
 * -ENOENT.  Otherwise returns the number of bytes of #buf that were used.
 */
int provision_get(struct provision_data *prov, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* not __PROVISION_H__ */
