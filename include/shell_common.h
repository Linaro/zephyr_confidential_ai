/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SHELL_COMMON_H
#define SHELL_COMMON_H

#include <zephyr/shell/shell.h>

/**
 * @brief Helper utility function to print the invalid argument error message
 * with arg_name and return invalid error code.
 *
 * @param       shell     Shell instance
 * @param       arg_name  String to print on the shell console.
 *
 * @return -EINVAL
 */
int
shell_com_invalid_arg(const struct shell *shell, char *arg_name);

/**
 * @brief Helper utility function to print the too many arguments error
 * message with arg_name and return invalid error code.
 *
 * @param       shell     Shell instance
 * @param       arg_name  String to print on the shell console.
 *
 * @return -EINVAL
 */
int
shell_com_too_many_arg(const struct shell *shell, char *arg_name);

/**
 * @brief Helper utility function to print the missing argument error
 * message with arg_name and return invalid error code.
 *
 * @param       shell     Shell instance
 * @param       arg_name  String to print on the shell console.
 *
 * @return -EINVAL
 */
int
shell_com_missing_arg(const struct shell *shell, char *arg_name);

/**
 * @brief Helper utility function to print the error and arg_name and return
 * invalid error code.
 *
 * @param       shell     Shell instance
 * @param       error     String to print on the shell console.
 * @param       rc        Error status code to print on the shell console with
 *                        @p error.
 *
 * @return -EINVAL
 */
int
shell_com_rc_code(const struct shell *shell, char *error, int rc);

/**
 * @brief Helper utility function to convert string to float.
 *
 * @param       str     Pointer to a stored buffer of string.
 * @param       value   Value to store the converted string to float value.
 *
 * @return true  Succesful conversion
 *         false Unsuccessful conversion
 */
_Bool shell_com_str_to_float(char *str, float *value);

/**
 * @brief Helper utility function to convert string to float, validate the
 * converted value in the range between min to max.
 *
 * @param       str     Pointer to a stored buffer of string.
 * @param       value   Value to store the converted string to float value.
 * @param       min     Minimum value.
 * @param       max     Maximum value.
 *
 * @return true  Succesful conversion
 *         false Unsuccessful conversion or invalid range
 */
_Bool
shell_com_str_to_float_min_max(char *str, float *value, float min, float max);

#endif /* SHELL_COMMON_H */
