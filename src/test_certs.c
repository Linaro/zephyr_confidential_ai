/*
 * Copyright (c) 2022 Linaro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_certs.h"

static const unsigned char raw_ca_certificate[] = {
#include "digicert.cer"
};
const unsigned char *ca_certificate = raw_ca_certificate;
const size_t ca_certificate_len = sizeof(raw_ca_certificate);

/* The setup-ca.sh script in the linarca repo should create this file.
 */
static const unsigned char raw_caroot_crt[] = {
#include "ca_crt.txt"
};
const unsigned char *caroot_crt = raw_caroot_crt;
const size_t caroot_crt_len = sizeof(raw_caroot_crt);

/* From the linaroca setup-bootstrap.h
 */
static const unsigned char raw_bootstrap_crt[] =
#include "bootstrap_crt.txt"
;
const unsigned char *bootstrap_crt = raw_bootstrap_crt;
const size_t bootstrap_crt_len = sizeof(raw_bootstrap_crt);

/* The private key for the above certificate.
 */
static const unsigned char raw_bootstrap_key[] = {
#include "bootstrap_key.txt"
};
const unsigned char *bootstrap_key = raw_bootstrap_key;
const size_t bootstrap_key_len = sizeof(raw_bootstrap_key);
