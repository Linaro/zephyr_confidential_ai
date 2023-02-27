/*
 * Copyright (c) 2022 Linaro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TEST_CERTS_H__
#define __TEST_CERTS_H__

#include <sys/types.h>

/* The root of trust for the MQTT server. */
extern const unsigned char *ca_certificate;
extern const size_t ca_certificate_len;

/* The root of trust for the bootstrap service.
 */
extern const unsigned char *caroot_crt;
extern const size_t caroot_crt_len;

/* The certificate and key for the bootstrap service.
 */
extern const unsigned char *bootstrap_crt;
extern const size_t bootstrap_crt_len;

/* The private key for the bootstrap service.
 */
extern const unsigned char *bootstrap_key;
extern const size_t bootstrap_key_len;

#endif /* not __TEST_CERTS_H__ */
