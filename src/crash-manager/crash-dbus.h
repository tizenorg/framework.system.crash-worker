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
 * @file	crash-dbus.h
 * @brief	crash-dbus header file
 */
#ifndef __CRASH_DBUS_H__
#define __CRASH_DBUS_H__

#include "manager.h"

void dbus_init(Manager *manager);
void dbus_exit(Manager *manager);
int dump_log(int type, const char *arg);
int delete_dump(void);
int request_crash_popup(GDBusConnection *conn, char *process_name, char *exepath);
void broadcast_crash(GDBusConnection *conn, char *process_name, char *exepath);
void request_pmqos_scenario(GDBusConnection *conn);

#endif
