/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "shell_common.h"
#include <stdlib.h>

int
shell_com_invalid_arg(const struct shell *shell, char *arg_name)
{
	shell_print(shell, "Error: invalid argument \"%s\"\n", arg_name);

	return -EINVAL;
}

int
shell_com_too_many_arg(const struct shell *shell, char *arg_name)
{
	shell_print(shell, "Error: too many arguments \"%s\"\n", arg_name);

	return -EINVAL;
}

int
shell_com_missing_arg(const struct shell *shell, char *arg_name)
{
	shell_print(shell, "Error: missing argument: \"%s\"\n", arg_name);

	return -EINVAL;
}

int
shell_com_rc_code(const struct shell *shell, char *error, int rc)
{
	shell_print(shell, "Error: %s: \"%d\"\n", error, rc);

	return -EINVAL;
}

_Bool
shell_com_str_to_float_min_max(char *str, float *value, float min, float max)
{
	char *endptr;

	*value = strtof(str, &endptr);
	if (endptr == str) {
		return false;
	}

	if (min >= 0 && max > 0) {
		if ((*value < min || *value > max)) {
			return false;
		}
	}

	return true;
}

_Bool shell_com_str_to_float(char *str, float *value)
{
	return shell_com_str_to_float_min_max(str, value, 0, 0);
}
