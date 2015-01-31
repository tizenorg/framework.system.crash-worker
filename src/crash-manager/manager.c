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
 * @file    manager.c
 * @brief   crash manager.
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <systemd/sd-daemon.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "shared/config-parser.h"
#include "shared/util.h"
#include "shared/log.h"
#include "worker.h"
#include "manager.h"

#define DEF_ALLOW_ZIP           (1) /* (1) = yes, (0) = no */
#define DEF_ALLOW_POPUP         (1) /* (1) = yes, (0) = no */
#define DEF_RUN_TIMEOUT         (1) /* (1) = yes, (0) = no */
#define DEF_RUN_TIMEOUT_SEC     (30) /* seconds */
#define MAX_RUN_TIMEOUT_SEC     (DEF_RUN_TIMEOUT_SEC * 4) /* 120 sec */
#define DEF_KEEP_FREE_UPPER     (1ULL * 1024ULL * 1024ULL) /* 1 GiB */
#define DEF_MAX_CONCUR_JOB      (3)        /* 3 */
#define MAX_CONCUR_JOB          (4)
#define DEF_MAX_CRASH_DUMP      (4)
#define MAX_CRASH_DUMP          (20)
#define DEF_MAX_CRASH_REPORT    (DEF_MAX_CRASH_DUMP * 2)        /* MAX_CRASH_DUMP * 2 */
#define MAX_CRASH_REPORT        (MAX_CRASH_DUMP)
#define DEF_MAX_RETENTION_SEC   (60 * 60 * 24 * 15)   /* 15 days */
#define MIN_RETENTION_SEC       (60 * 10)   /* 10 min */
#define DEF_MAX_USE_UPPER       (DEF_MAX_CRASH_DUMP * 50ULL * 1024ULL)   /* max_crash_dump * 50 MiB*/
#define CRASH_CONF_FILE         "/etc/crash/crash-manager.conf"
#define CRASH_SOCKET            "/tmp/crash_socket"

static int load_config(struct parse_result *result, void *user_data)
{
	struct crash_config *c = (struct crash_config *)user_data;
	int val;

	if (!c)
		return -EINVAL;

	if (strncmp(result->section, "CrashManager", 11))
		return -EINVAL;

	if (!strncmp(result->name, "RunTimeoutSec", 13)) {
		val = atoi(result->value);
		if (0 <= val && val < MAX_RUN_TIMEOUT_SEC)
			c->run_timeout_sec = val;
		else
			c->run_timeout_sec = DEF_RUN_TIMEOUT_SEC;
		_D("RunTimeoutSec is [ %d ]", c->run_timeout_sec);
	} else if (!strncmp(result->name, "SystemMaxUse", 12)) {
		val = atoi(result->value);
		if (val >= 0)
			c->system_max_use = val;
		_D("SystemMaxUse [ %d kbyte]", c->system_max_use);
	} else if (!strncmp(result->name, "SystemKeepFree", 14)) {
		val = atoi(result->value);
		if (val >= 0)
			c->system_keep_free = val;
		_D("SystemKeepFree is [ %d kbyte]", c->system_keep_free);
	} else if (!strncmp(result->name, "MaxRetentionSec", 15)) {
		val = atoi(result->value);
		if (val >= MIN_RETENTION_SEC)
			c->max_retention_sec = val;
		_D("MaxRetentionSec is [ %d ]", c->max_retention_sec);
	} else if (!strncmp(result->name, "MaxCrashDump", 12)) {
		val = atoi(result->value);
		if (val >= 0 && val < MAX_CRASH_DUMP)
			c->max_crash_dump = val;
		else
			c->max_crash_dump = DEF_MAX_CRASH_DUMP;
		_D("MaxCrashDump is [ %d ]", c->max_crash_dump);
	} else if (!strncmp(result->name, "MaxCrashReport", 14)) {
		val = atoi(result->value);
		if (val >= 0 && val < MAX_CRASH_REPORT + 1)
			c->max_crash_report = val;
		else
			c->max_crash_report = DEF_MAX_CRASH_REPORT;
		_D("MaxCrashReport is [ %d ]", c->max_crash_report);
	} else if (!strncmp(result->name, "MaxConcurrentJob", 16)) {
		val = atoi(result->value);
		if (val > 0 && val < MAX_CONCUR_JOB + 1)
			c->max_concurrent_job = val;
		else
			c->max_concurrent_job = DEF_MAX_CONCUR_JOB;
		_D("MaxConcurrentJob is [ %d ]", c->max_concurrent_job);
	} else if (!strncmp(result->name, "AllowPopup", 10)) {
		c->allow_popup = (!strncmp(result->value, "yes", 3)) ? 1 : 0;
		_D("AllowPopup is [ %d ]", c->allow_popup);
	} else if (!strncmp(result->name, "AllowZip", 8)) {
		c->allow_zip = (!strncmp(result->value, "yes", 3)) ? 1 : 0;
		_D("AllowZip is [ %d ]", c->allow_zip);
	}
	return 0;
}

static void handle_error(GError *error)
{
	if (error) {
		_E("ERROR: %s", error->message);
		g_error_free(error);
	}
}

static gboolean handle_read_message(GIOChannel *gio, GIOCondition condition, gpointer data)
{
	GIOStatus ret;
	GError *err = NULL;
	gsize len;
	gchar *msg;
	struct work_data *work = (struct work_data *)data;
	if (!work)
		return FALSE;

	if (condition == G_IO_ERR || condition == G_IO_HUP) {
		_I("G_IO_ERR, G_IO_HUP");
		g_io_channel_shutdown(gio, true, &err);
		worker_close_work(work);
		return FALSE;
	}
	ret = g_io_channel_read_line(gio, &msg, &len, NULL, &err);
	if (ret == G_IO_STATUS_ERROR) {
		_I("G_IO_STATUS_ERROR");
		g_io_channel_shutdown(gio, true, &err);
		worker_close_work(work);
		handle_error(err);
		return FALSE;
	} else if (ret == G_IO_STATUS_EOF) {
		g_io_channel_shutdown(gio, true, &err);
		handle_error(err);
		return FALSE;
	} else if (len == 0) {
		_I("Read msg length 0");
		g_io_channel_shutdown(gio, true, &err);
		worker_close_work(work);
		handle_error(err);
		return FALSE;
	} else if (len > 0) {
		_I("Read %u bytes: %s", len, msg);
		manager_remove_timeout(work->manager);
		work->msg = msg;
		worker_push_work(work);
	}
	return TRUE;
}

gboolean handle_noti(GIOChannel *in, GIOCondition condition, gpointer data)
{
	GIOChannel *client_channel;
	struct work_data *work;

	work = (struct work_data *)malloc(sizeof(struct work_data));
	if (!work) {
		_W("Failed to malloc to push work");
		return FALSE;
	}
	work->manager = (Manager *)data;
	work->fd = accept(g_io_channel_unix_get_fd(in), NULL, NULL);
	if (work->fd < 0) {
		_E("Error client socket!");
		free(work);
		return FALSE;
	}
	client_channel = NULL;
	client_channel = g_io_channel_unix_new(work->fd);
	g_io_channel_set_close_on_unref(client_channel, TRUE);
	g_io_add_watch(client_channel, G_IO_IN | G_IO_HUP,
			(GIOFunc)handle_read_message, work);
	g_io_channel_unref(client_channel);

	return TRUE;
}

void manager_add_noti_watch(Manager *manager)
{
	manager->noti_channel = g_io_channel_unix_new(manager->noti_fd);
	g_io_channel_set_close_on_unref(manager->noti_channel, TRUE);

	if (!(manager->noti_channel)) {
		_E("Error noti channel!");
		return;
	}
	g_io_add_watch(manager->noti_channel, G_IO_IN | G_IO_HUP,
			handle_noti, (gpointer)manager);
	g_io_channel_unref(manager->noti_channel);
}

static gboolean timeout_cb(gpointer user_data)
{
	_I("Time out!");
	g_main_loop_quit((GMainLoop *)user_data);
	return 0;
}

void manager_add_timeout(Manager *manager, guint interval)
{
	if (!interval)
		return;

	g_mutex_lock(&manager->timeout_mutex);
	if (manager->timeout_id) {
		g_source_remove(manager->timeout_id);
	}
	manager->timeout_id = g_timeout_add_seconds(interval, timeout_cb, manager->loop);
	g_mutex_unlock(&manager->timeout_mutex);
	_I("Add loop timeout(%d)", interval);
}

void manager_remove_timeout(Manager *manager)
{
	g_mutex_lock(&manager->timeout_mutex);
	if (manager->timeout_id) {
		g_source_remove(manager->timeout_id);
		manager->timeout_id = 0;
	}
	g_mutex_unlock(&manager->timeout_mutex);
	_I("Remove loop timeout");
}

Manager *manager_new(void)
{
	return (Manager *)calloc(1, sizeof(Manager));
}

void manager_init(Manager *manager)
{
	g_mutex_init(&manager->working_mutex);
	g_mutex_init(&manager->timeout_mutex);
	manager->loop = g_main_loop_new(NULL, false);
}

void manager_config(Manager *manager)
{
	int ret;
	struct crash_config *conf;

	conf = &(manager->conf);
	/* init default value */
	conf->run_timeout_sec = DEF_RUN_TIMEOUT_SEC;
	conf->system_max_use = DEF_MAX_USE_UPPER;
	conf->system_keep_free = DEF_KEEP_FREE_UPPER;
	conf->max_retention_sec = DEF_MAX_RETENTION_SEC;
	conf->max_crash_dump = DEF_MAX_CRASH_DUMP;
	conf->max_crash_report = DEF_MAX_CRASH_REPORT;
	conf->max_concurrent_job = DEF_MAX_CONCUR_JOB;
	conf->allow_popup = DEF_ALLOW_POPUP;
	conf->allow_zip = DEF_ALLOW_ZIP;
	/* load configutation */
	ret = config_parse(CRASH_CONF_FILE,
			load_config, conf);
	if (ret < 0)
		_W("Failed to load %s, %d Use default value!",
				CRASH_CONF_FILE, ret);
}

int manager_init_noti(Manager *manager)
{
	const int listening = 1;
	int fd;

	if (sd_listen_fds(1) == 1) {
		fd = SD_LISTEN_FDS_START + 0;
		if (sd_is_socket_unix(fd, SOCK_STREAM, listening, CRASH_SOCKET, 0) > 0)
			manager->noti_fd = fd;
		return 0;
	} else {
		union {
			struct sockaddr sa;
			struct sockaddr_un un;
		} sa;
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0) {
			_E("Failed to socket()");
			return -1;
		}
		memset(&sa, 0, sizeof(sa));
		sa.un.sun_family = AF_UNIX;
		strncpy(sa.un.sun_path, CRASH_SOCKET, sizeof(sa.un.sun_path));

		if (bind(fd, &sa.sa, sizeof(sa)) < 0) {
			_E("Failed to bind()");
			close(fd);
			return -1;
		}

		if (listen(fd, SOMAXCONN) < 0) {
			_E("Failed to listen()");
			close(fd);
			return -1;
		}
		manager->noti_fd = fd;
	}
	return 0;
}

void manager_run(Manager *manager)
{
	_I("Crash-manager main loop begin");
	g_main_loop_run(manager->loop);
}

void manager_exit(Manager *manager)
{
	if (!manager)
		return;
	g_main_loop_unref(manager->loop);
	g_mutex_clear(&manager->timeout_mutex);
	g_mutex_clear(&manager->working_mutex);
	if (manager->working_list)
		g_free(manager->working_list);
	free(manager);
}
