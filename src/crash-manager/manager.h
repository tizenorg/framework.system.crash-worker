/*
 * crash-manager
 *
 * Copyright (c) 2011 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/**
 * @file	manager.h
 * @brief	manager header file
 */
#ifndef __MANAGER_H__
#define __MANAGER_H__
#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>

/*
 * @brief Configuration structure
 */
struct crash_config {
	int run_timeout_sec;
	int system_max_use;
	int system_keep_free;
	int max_retention_sec;
	int max_crash_dump;
	int max_crash_report;
	int max_concurrent_job;
	int allow_popup;
	int allow_zip;
};

typedef struct crash_manager {
	/* configuration */
	int                 debug_mode;
	struct crash_config conf;
	/* main loop */
	GMainLoop           *loop;
	/* crash notification */
	gint                noti_fd;
	GIOChannel          *noti_channel;
	/* main loop timer */
	guint               timeout_id;
	GMutex              timeout_mutex;
	/* gdbus */
	GDBusConnection     *conn;
	GDBusNodeInfo       *introspection_data;
	guint               owner_id;
	/* crash work list */
	GList               *working_list;
	GMutex              working_mutex;
	GThreadPool         *work_pool;
} Manager;

Manager *manager_new(void);
void manager_init(Manager *manager);
void manager_config(Manager *manager);
void manager_run(Manager *manager);
void manager_exit(Manager *manager);
int manager_init_noti(Manager *manager);
void manager_add_noti_watch(Manager *manager);
void manager_add_timeout(Manager *manager, guint interval);
void manager_remove_timeout(Manager *manager);
/**
 * @}
 */

#endif
