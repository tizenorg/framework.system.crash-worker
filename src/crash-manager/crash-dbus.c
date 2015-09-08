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
 * @file    crash-dbus.c
 * @brief   crash dbus
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <gio/gio.h>

#include "shared/util.h"
#include "shared/launch.h"
#include "shared/log.h"
#include "worker.h"

/*
 * Deviced
*/
#define DEVICED_BUS_NAME            "org.tizen.system.deviced"
#define DEVICED_OBJECT_PATH         "/Org/Tizen/System/DeviceD"
#define DEVICED_INTERFACE_NAME      DEVICED_BUS_NAME
#define DEVICED_PATH_PMQOS          DEVICED_OBJECT_PATH"/PmQos"
#define DEVICED_INTERFACE_PMQOS     DEVICED_INTERFACE_NAME".PmQos"
/*
 * Telephony
*/
#define TELEPHONY_BUS_NAME          "org.projectx.telephony"
#define TELEPHONY_OBJECT_PATH       "/org/projectx/app"
#define TELEPHONY_INTERFACE_NAME    TELEPHONY_BUS_NAME
#define SERVICE_REQUEST             "service_request_sec"
#define TELEPHONY_PARAM1_KEY        39
#define TELEPHONY_PARAM2_KEY        1073751810
/*
 * Crash
*/
#define CRASH_BUS_NAME              "org.tizen.system.crash"
#define CRASH_OBJECT_PATH           "/Org/Tizen/System/Crash"
#define CRASH_INTERFACE_NAME        CRASH_BUS_NAME
#define CRASH_PATH_CRASH            CRASH_OBJECT_PATH"/Crash"
#define CRASH_INTERFACE_CRASH       CRASH_INTERFACE_NAME".Crash"
#define PROCESS_CRASHED             "ProcessCrashed"
#define DUMP_LOG                    "dump_log"
#define DELETE_DUMP                 "delete_dump"
/*
 * Popup launcher
*/
#define POPUP_BUS_NAME              "org.tizen.system.popup"
#define POPUP_OBJECT_PATH           "/Org/Tizen/System/Popup"
#define POPUP_INTERFACE_NAME        POPUP_BUS_NAME
#define POPUP_PATH_CRASH            POPUP_OBJECT_PATH"/Crash"
#define POPUP_INTERFACE_CRASH       POPUP_INTERFACE_NAME".Crash"
#define POPUP_METHOD_LAUNCH         "PopupLaunch"

#define RETRY_MAX                   10

enum dump_log_type {
	AP_DUMP = 0,    /**< Application logs dump */
	CP_DUMP = 1,    /**< Modem logs dump */
	ALL_DUMP = 2    /**< All logs dump - application and modem */
};

static const gchar introspection_xml[] =
"<node>"
"  <interface name='org.tizen.system.crash.Crash'>"
"    <method name='dump_log'>"
"      <arg type='i' name='type' direction='in'/>"
"      <arg type='s' name='arg' direction='in'/>"
"      <arg type='i' name='response' direction='out'/>"
"    </method>"
"    <method name='delete_dump'>"
"      <arg type='i' name='type' direction='in'/>"
"      <arg type='s' name='arg' direction='in'/>"
"      <arg type='i' name='response' direction='out'/>"
"    </method>"
"  </interface>"
"</node>";

void broadcast_crash(GDBusConnection *conn, char *process_name, char *exepath)
{
	if (!conn) {
		_E("connection is null");
		return;
	}
	if (!process_name || !exepath)
		return;

	g_dbus_connection_emit_signal(conn, NULL, CRASH_PATH_CRASH,
					CRASH_INTERFACE_CRASH, PROCESS_CRASHED,
					g_variant_new("(ss)", process_name, exepath),
					NULL);
	_I("broadcast_crash!");
}

void request_pmqos_scenario(GDBusConnection *conn)
{
	if (!conn) {
		_E("connection is null");
		return;
	}
	g_dbus_connection_call(conn, DEVICED_BUS_NAME,
					DEVICED_PATH_PMQOS, DEVICED_INTERFACE_PMQOS,
					PROCESS_CRASHED, g_variant_new("(i)", 3000),
					NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
	_I("request_pmqos_scenario!");
}

int request_crash_popup(GDBusConnection *conn, char *process_name, char *exepath)
{
	int ret = 0;
	GVariant *reply;
	GError *error = NULL;

	if (!conn) {
		_E("connection is null");
		return -EINVAL;
	}
	if (!process_name || !exepath)
		return -EINVAL;
	reply = g_dbus_connection_call_sync(conn, POPUP_BUS_NAME, POPUP_PATH_CRASH,
					POPUP_INTERFACE_CRASH, POPUP_METHOD_LAUNCH,
					g_variant_new("(ssss)", "_PROCESS_NAME_", process_name,
					"_EXEPATH_", exepath),
					G_VARIANT_TYPE("(i)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (reply == NULL) {
		_E("Failed to request_crash_popup: %s", error->message);
		g_error_free(error);
		return -EPERM;
	} else {
		g_variant_get(reply, "(i)", &ret);
		g_variant_unref(reply);
		if (ret)
			_I("Crash_popup is launched: (%d)", ret);
		return ret;
	}
}

static int dump_ap_log(const char *arg)
{
	char buf[PATH_MAX];
	GError *error = NULL;

	snprintf(buf, sizeof(buf), "/bin/sh %s %s", "/usr/bin/all_log_dump.sh", arg);
	if (!g_spawn_command_line_sync(buf, NULL, NULL, NULL, &error)) {
			_E("Error!: %s", error->message);
			g_error_free(error);
			return -EPERM;
	}
	_I("dump_ap_log!: buf %s", buf);

	return 0;
}

static void cp_dump_done(GDBusConnection *conn,
				GAsyncResult *res, gpointer user_data)
{
	_I("dump_cp_log done!");
}

static int dump_cp_log(GDBusConnection *conn)
{
	GVariantBuilder builder;

	char param3[4];
	char param4[1];
	char param5[1];
	char param6[1];

	if (!conn) {
		_E("connection is null");
		return -EINVAL;
	}
	memset(param3, 0x0, sizeof(param3));
	memset(param4, 0x0, sizeof(param4));
	memset(param5, 0x0, sizeof(param5));
	memset(param6, 0x0, sizeof(param6));

	g_variant_builder_init(&builder, G_VARIANT_TYPE("(iiayayayay)"));
	g_variant_builder_add(&builder, "i", TELEPHONY_PARAM1_KEY);
	g_variant_builder_add(&builder, "i", TELEPHONY_PARAM2_KEY);
	g_variant_builder_add(&builder, "@ay",
					g_variant_new_from_data(G_VARIANT_TYPE("ay"),
					param3, sizeof(param3), TRUE, NULL, NULL));
	g_variant_builder_add(&builder, "@ay",
					g_variant_new_from_data(G_VARIANT_TYPE("ay"),
					param4,	sizeof(param4), TRUE, NULL, NULL));
	g_variant_builder_add(&builder, "@ay",
					g_variant_new_from_data(G_VARIANT_TYPE("ay"),
					param5,	sizeof(param5), TRUE, NULL, NULL));
	g_variant_builder_add(&builder, "@ay",
					g_variant_new_from_data(G_VARIANT_TYPE("ay"),
					param6,	sizeof(param6), TRUE, NULL, NULL));

	g_dbus_connection_call(conn, TELEPHONY_BUS_NAME, TELEPHONY_OBJECT_PATH,
					TELEPHONY_INTERFACE_NAME, SERVICE_REQUEST,
					g_variant_builder_end(&builder), NULL,
					G_DBUS_CALL_FLAGS_NONE, -1,	NULL,
					(GAsyncReadyCallback)cp_dump_done, NULL);
	_I("dump_cp_log!");
	return 0;
}

int delete_dump(void)
{
	_I("delete_dump!");
	remove_dir(CRASH_COREDUMP_PATH, 0);
	remove_dir(CRASH_DUMP_PATH, 0);
	remove_dir(CRASH_REPORT_PATH, 0);

	return 0;
}

int dump_log(GDBusConnection *conn, int type, const char *arg)
{
	int ret = 0;

	if (type == AP_DUMP) {
		ret = dump_ap_log(arg);
	} else if (type == CP_DUMP) {
		ret = dump_cp_log(conn);
	} else {
		dump_cp_log(conn);
		ret = dump_ap_log(arg);
	}
	return ret;
}

static void method_call_handler(GDBusConnection *conn,
				const gchar *sender, const gchar *object_path,
				const gchar *iface_name, const gchar *method_name,
				GVariant *parameters, GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	int ret = 0;
	Manager *manager = (Manager *)user_data;
	if (!manager) {
		_E("manager is null");
		return;
	}
	manager_remove_timeout(manager);

	if (g_strcmp0(method_name, "dump_log") == 0) {
		const gchar *arg;
		gint32 type = ALL_DUMP;
		g_variant_get(parameters, "(i&s)", &type, &arg);
		ret = dump_log(conn, type, arg);
	} else if (g_strcmp0(method_name, "delete_dump") == 0) {
		ret = delete_dump();
	}
	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(i)", ret));

	manager_add_timeout(manager, manager->conf.run_timeout_sec);
}

static const GDBusInterfaceVTable interface_vtable =
{
	method_call_handler,
	NULL,
	NULL
};

static void on_bus_acquired(GDBusConnection *conn,
				const gchar *name,	gpointer user_data)
{
	guint registration_id;

	Manager *manager = (Manager *)user_data;
	if (!manager) {
		_E("manager is null");
		return;
	}
	if (!conn) {
		_E("connection is null");
		return;
	}
	registration_id = g_dbus_connection_register_object(conn,
					CRASH_PATH_CRASH, manager->introspection_data->interfaces[0],
					&interface_vtable, user_data, NULL, NULL);
	if (registration_id == 0)
		_E("Failed to g_dbus_connection_register_object");
}

static void on_name_acquired(GDBusConnection *conn,
				const gchar *name, gpointer user_data)
{
}

static void on_name_lost(GDBusConnection *conn,
				const gchar *name, gpointer user_data)
{
	_W("Dbus name is lost!");
}

void dbus_init(Manager *manager)
{
	GError *error;
	int retry;

	manager->introspection_data =
			g_dbus_node_info_new_for_xml(introspection_xml, NULL);
	if (manager->introspection_data == NULL) {
		_E("Failed to init g_dbus_node_info_new_for_xml");
		return;
	}
	error = NULL;
	retry = 0;

	do {
		manager->conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
		if (manager->conn)
			break;
		if (++retry == RETRY_MAX) {
			_E("Failed to get dbus");
			return;
		}
	} while (retry <= RETRY_MAX);

	if (error == NULL) {
		manager->owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM, CRASH_BUS_NAME,
						G_BUS_NAME_OWNER_FLAGS_NONE, on_bus_acquired,
						on_name_acquired, on_name_lost, (gpointer)manager, NULL);
	} else {
		_E("Failed to get dbus");
		g_error_free(error);
	}
}

void dbus_exit(Manager *manager)
{
	if (manager->owner_id != 0)
		g_bus_unown_name(manager->owner_id);

	if (manager->introspection_data)
		g_dbus_node_info_unref(manager->introspection_data);
}
