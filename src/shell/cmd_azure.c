/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <azure.h>
#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>

LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#ifdef CONFIG_AZURE_SHELL_CMD_SUPPORT

static int
cmd_azure_status(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "TODO: Implement meaningful status");

	return 0;
}

#ifdef CONFIG_APP_NETWORKING
static int
cmd_azure_start(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Starting Azure work thread");
	start_azure_service();

	return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_azure,
	/* Status */
	SHELL_CMD(status, NULL, "Azure connection status", cmd_azure_status),
#ifdef CONFIG_APP_NETWORKING
	SHELL_CMD(start, NULL, "Start Azure client", cmd_azure_start),
#endif
	SHELL_SUBCMD_SET_END
	);

SHELL_CMD_REGISTER(azure, &sub_cmd_azure, "Azure commands", NULL);

#endif /* CONFIG_AZURE_SHELL_CMD_SUPPORT */
