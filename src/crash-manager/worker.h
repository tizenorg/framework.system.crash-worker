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
 * @file	worker.h
 * @brief	crash-worker header file
 */
#ifndef __WORKER_H__
#define __WORKER_H__

#include "manager.h"

#define CRASH_INFO_PATH             "/tmp/crash_info"
#define CRASH_COREDUMP_PATH         "/opt/usr/share/crash/core"
#define CRASH_DUMP_PATH             "/opt/usr/share/crash/dump"
#define CRASH_REPORT_PATH           "/opt/usr/share/crash/report"

enum {
	INIT = 0x6C,
	DELETED,
};

struct file_info {
	bool    isdir;
	int     state;
	int     size;
	time_t  mtime;
	char    *name;
};

struct work_data {
	Manager *manager;
	int     fd;
	char   *msg;
};

void worker_push_work(struct work_data *work);
void worker_close_work(struct work_data *work);
int worker_init(Manager *manger);
void worker_exit(Manager *manager);

#endif
