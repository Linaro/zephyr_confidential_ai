/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <math.h>
#include <zephyr/logging/log.h>

#include "shell_common.h"
#include "cose/cose_verify.h"
#include "cose/mbedtls_ecdsa_verify_sign.h"
#include "infer_mgmt.h"
#include "tfm_partition_huk.h"
#include "tfm_partition_tflm.h"
#include "util_app_log.h"

#define SINE_INPUT_MIN 0
#define SINE_INPUT_MAX 359

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

static int
cmd_infer_list_models(const struct shell *shell, size_t argc, char **argv)
{
	char *row1[] = { "Model Label", "Model ID", "Status" };
	char *m_sts[] = { "Not Active", "Active", "Unknown" };
	infer_ctx_t *ctx = infer_context_get();

	shell_print(shell, "| %-15s| %-12s | %-8s |", row1[0], row1[1],
		    row1[2]);
	for (int i = 0; i < INFER_MODEL_COUNT; i++) {
		shell_print(shell, "| %-15s| 0x%-10x | %-8s |",
			    ctx[i].sid_label,
			    ctx[i].sid,
			    m_sts[ctx[i].sts]);
	}

	return 0;
}

static int
cmd_infer_get_sine_val(const struct shell *shell,
		       size_t argc,
		       char **argv,
		       infer_get_cose_output cose_output,
		       const char *model)
{
	psa_status_t status;
	const float PI = 3.14159265359f;
	float deg = PI / 180.0;
	float usr_in_val_start = 0,
	      usr_in_val_end = 0,
	      stride = 1.0,
	      model_out_val,
	      usr_in_val_deg;
	static uint8_t infval_enc_buf[INFER_ENC_MAX_VALUE_SZ];
	size_t infval_enc_buf_len = 0;
	infer_enc_t enc_fmt;
	char *payload_format[3] = { "CBOR", "SIGN1", "ENCRYPT0" };
	_Bool is_valid_payload_format = false;

	if ((argc == 1) || (strcmp(argv[1], "help") == 0)) {
		shell_print(shell, "Requests a new sine wave approximation using TFLM.\n");
		shell_print(shell, "  $ %s %s %s <format> <start> <[stop] [stride]>\n",
			    argv[-2], argv[-1], argv[0]);
		shell_print(shell,
			    "  <format>   Payload format (CBOR, SIGN1, ENCRYPT0)");
		shell_print(shell,
			    "  <start>    Initial inference valid input 0 to 359");
		shell_print(shell,
			    "  [stop]     Optional: Final inference valid input 0 to 359");
		shell_print(shell,
			    "  [stride]   Optional: Stride between start and stop\n");
		shell_print(shell,
			    "Example: $ %s %s %s SIGN1 1.5", argv[-2], argv[-1], argv[0]);
		shell_print(shell,
			    "         $ %s %s %s CBOR 1.0 2.0 0.25",
			    argv[-2], argv[-1], argv[0]);
		return 0;
	}

	for (int i = 0; i < INFER_ENC_NONE; i++) {
		if (strcmp(argv[1], payload_format[i]) == 0) {
			enc_fmt = i;
			is_valid_payload_format = true;
			break;
		}
	}

	if (!is_valid_payload_format) {
		return shell_com_invalid_arg(shell, argv[1]);
	}

	if (argc == 2) {
		return shell_com_missing_arg(shell, "start");
	}

	if (!shell_com_str_to_float_min_max(argv[2],
					    &usr_in_val_start,
					    SINE_INPUT_MIN,
					    SINE_INPUT_MAX)) {
		return shell_com_invalid_arg(shell, argv[2]);
	}

	if (argc > 3) {
		if (!shell_com_str_to_float_min_max(argv[3],
						    &usr_in_val_end,
						    SINE_INPUT_MIN,
						    SINE_INPUT_MAX)) {
			return shell_com_invalid_arg(shell, argv[3]);
		}

		if (usr_in_val_start > usr_in_val_end) {
			return shell_com_invalid_arg(shell,
						     "Invalid start value (start > stop)");
		}
	} else {
		usr_in_val_end = usr_in_val_start;
	}

	if (argc > 4) {
		if (!shell_com_str_to_float_min_max(argv[4],
						    &stride,
						    SINE_INPUT_MIN,
						    SINE_INPUT_MAX) || stride == 0) {
			return shell_com_invalid_arg(shell, argv[4]);
		}

		if ((usr_in_val_start + stride) > usr_in_val_end) {
			return shell_com_invalid_arg(shell,
						     "Out of boundary ((start + stride) > stop)");
		}
	}

	shell_print(shell,
		    "Start: %.2f End: %.2f stride: %.2f",
		    usr_in_val_start, usr_in_val_end, stride);

	while (usr_in_val_start <= usr_in_val_end) {
		usr_in_val_deg = usr_in_val_start * deg;
		status =  cose_output(
			enc_fmt,
			model,
			(void *)&usr_in_val_deg,
			sizeof(usr_in_val_deg),
			&infval_enc_buf[0],
			sizeof(infval_enc_buf),
			&infval_enc_buf_len);

		if (status != 0) {
			return shell_com_rc_code(shell,
						 "Failed to get encoded inference output",
						 status);
		} else {
			shell_print(shell,
				    "%s encoded inference value:", payload_format[enc_fmt]);
			shell_hexdump(shell, infval_enc_buf, infval_enc_buf_len);
		}

		status = infer_get_value(enc_fmt,
					 infval_enc_buf,
					 infval_enc_buf_len,
					 &model_out_val);
		if (status != 0) {
			return shell_com_rc_code(shell,
						 "Failed to decode COSE payload",
						 status);
		}

		shell_print(shell, "Model: Sine of %.2f deg is: %f\t",
			    usr_in_val_start, model_out_val);
		shell_print(shell, "C Mathlib: Sine of %.2f deg is: %f\t",
			    usr_in_val_start, sin(usr_in_val_start * deg));
		shell_print(shell, "Deviation: %f\n",
			    fabs(sin(usr_in_val_start) - model_out_val));
		usr_in_val_start += stride;
	}
	return 0;
}

static int
cmd_infer_get_tflm_sine_val(const struct shell *shell,
			    size_t argc,
			    char **argv)
{
	return
		cmd_infer_get_sine_val(shell,
				       argc,
				       argv,
				       infer_get_tflm_cose_output,
				       "TFLM_MODEL_SINE");
}

static int
cmd_infer_get_utvm_sine_val(const struct shell *shell,
			    size_t argc,
			    char **argv)
{
	return
		cmd_infer_get_sine_val(shell,
				       argc,
				       argv,
				       infer_get_utvm_cose_output,
				       "UTVM_MODEL_SINE");
}

static int
cmd_infer_get(const struct shell *shell, size_t argc, char **argv)
{
	infer_ctx_t *m_ctx = infer_context_get();

	if ((argc == 1) || (strcmp(argv[1], "help") == 0)) {
		shell_print(shell, "Requests an inference output from the specified model.\n");
		shell_print(shell, "  $ %s %s <model> ...\n",
			    argv[-1], argv[0]);
		shell_print(shell, "  <model>    Model name\n");
		shell_print(shell, "Models available:");
		for (int i = 0; i < INFER_MODEL_COUNT; i++) {
			shell_print(shell, "  -%s", m_ctx[i].sid_label);
		}
	} else {
		return shell_com_invalid_arg(shell, argv[1]);
	}

	return 0;
}

static int
cmd_infer_aat(const struct shell *shell, size_t argc, char **argv)
{
	psa_status_t status;
	static uint8_t encoded_buf[INFER_ENC_MAX_VALUE_SZ];
	size_t encoded_buf_size = INFER_ENC_MAX_VALUE_SZ;
	size_t encoded_buf_len;

	status = psa_huk_aat(encoded_buf,
			     encoded_buf_size,
			     &encoded_buf_len);

	if (status != 0) {
		return shell_com_rc_code(shell,
					 "AAT creation failed with ",
					 status);
	} else {
		shell_print(shell,
			    "AAT token:");
		shell_hexdump(shell, encoded_buf, encoded_buf_len);
	}

	return 0;
}

/* Subcommand array for "model" (level 2). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_model,
	/* 'tflm_sine' command handler. */
	SHELL_CMD_ARG(tflm_sine, NULL, "$ infer get tflm_sine format start <[stop] [stride]>", cmd_infer_get_tflm_sine_val, 1, 4),
	/* 'utvm_sine' command handler. */
	SHELL_CMD_ARG(utvm_sine, NULL, "$ infer get utvm_sine format start <[stop] [stride]>", cmd_infer_get_utvm_sine_val, 1, 4),
	/* Array terminator. */
	SHELL_SUBCMD_SET_END
	);

/* Subcommand array for "infer" (level 1). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_infer,
	/* 'model' command handler. */
	SHELL_CMD_ARG(model, NULL, "List inference models", cmd_infer_list_models, 1, 0),
	/* 'get' command handler. */
	SHELL_CMD(get, &sub_cmd_model, "Run inference on given input(s)", cmd_infer_get),
        /* 'token' command handler. */
	SHELL_CMD_ARG(token, NULL, "Create Application Attestation Token(AAT)", cmd_infer_aat, 1, 0),
        /* Array terminator. */
	SHELL_SUBCMD_SET_END
	);

/* Root command "infer" (level 0). */
SHELL_CMD_REGISTER(infer, &sub_cmd_infer, "Inference engine", NULL);

#endif /* CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT */
