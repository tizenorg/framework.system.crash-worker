/*
 * crash-manager
 *
 * Copyright (c) 2012 - 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file    core.c
 * @brief   crash manager main loop.
 *
 * This file includes Main loop.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include "shared/util.h"
#include "shared/log.h"
#include "crash-dbus.h"
#include "manager.h"
#include "worker.h"

/**
 * @addtogroup CRASH_MANAGER
 * @{
 */

static void sig_handler(int signo, siginfo_t *info, void *data)
{
	_E("Terminated by signal(%d)", signo);
	exit(1);
}

static void signal_init(void)
{
	struct sigaction sig_act;

	memset(&sig_act, 0, sizeof(struct sigaction));
	sig_act.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sig_act, NULL);
	sigaction(SIGPIPE, &sig_act, NULL);
	sig_act.sa_handler = NULL;
	sig_act.sa_sigaction = sig_handler;
	sig_act.sa_flags = SA_SIGINFO;
	sigaction(SIGTERM, &sig_act, NULL);
}

int main(int argc, char **argv)
{
	Manager *manager;

	g_type_init();

	signal_init();

	manager = manager_new();
	if (!manager) {
		_E("Failed to malloc struct manager");
		goto exit;
	}

	manager_init(manager);

	if (manager_init_noti(manager) < 0) {
		_E("Failed to manager_init_noti");
		goto exit_free;
	}
	manager_config(manager);

	dbus_init(manager);

	manager_add_noti_watch(manager);

	manager_add_timeout(manager, manager->conf.run_timeout_sec);

	if (worker_init(manager) < 0) {
		_E("Failed to worker_init");
		goto exit;
	}

	manager_run(manager);

	dbus_exit(manager);

	worker_exit(manager);

exit_free:
	manager_exit(manager);
exit:
	_I("Crash-manager Exit!!");
	return 0;
}

/**
 * @}
 */
