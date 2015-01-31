/*
 * crashctl
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include <dlog.h>
#undef LOG_TAG
#define LOG_TAG "CRASHCTL"
/*
 * crashctl [command] [arg]
 * ex> crashctl dump_log [normal|hardkey|dfms]
 *     crashctl delete_dump
 */
#define DBUS_REPLY_TIMEOUT      (120000)
#define ARRAY_SIZE(name) (sizeof(name)/sizeof(name[0]))
#define CRASH_BUS_NAME "org.tizen.system.crash"

enum command_type {
	DUMP_LOG,
	DELETE_DUMP,
};

static enum command_type command_id;

struct dbus_byte {
	const char *data;
	int size;
};

static const struct commands {
	const enum command_type id;
	const char *name;
	const char *path;
	const char *iface;
} command[] = {
	{ DUMP_LOG,    "dump_log",    "/Org/Tizen/System/Crash/Crash", "org.tizen.system.crash.Crash"},
	{ DELETE_DUMP, "delete_dump", "/Org/Tizen/System/Crash/Crash", "org.tizen.system.crash.Crash"},
};

static inline void usage()
{
	printf("[usage] crashctl <command> <arg>\n");
	printf("Please use option --help to check options\n");
}

int append_variant(DBusMessageIter *iter, const char *sig, char *param[])
{
	char *ch;
	int i;
	int int_type;
	dbus_bool_t bool_type;
	uint64_t int64_type;
	DBusMessageIter arr;
	struct dbus_byte *byte;

	if (!sig || !param)
		return 0;

	for (ch = (char*)sig, i = 0; *ch != '\0'; ++i, ++ch) {
		switch (*ch) {
		case 'b':
			bool_type = (atoi(param[i])) ? TRUE:FALSE;
			dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &bool_type);
			break;
		case 'i':
			int_type = atoi(param[i]);
			dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &int_type);
			break;
		case 'u':
			int_type = strtoul(param[i], NULL, 10);
			dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &int_type);
			break;
		case 't':
			int64_type = atoll(param[i]);
			dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT64, &int64_type);
			break;
		case 's':
			dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &param[i]);
			break;
		case 'a':
			++i, ++ch;
		switch (*ch) {
		case 'y':
			dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING, &arr);
			byte = (struct dbus_byte*)param[i];
			dbus_message_iter_append_fixed_array(&arr, DBUS_TYPE_BYTE, &(byte->data), byte->size);
			dbus_message_iter_close_container(iter, &arr);
			break;
		default:
			break;
		}
		break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

DBusMessage *dbus_method_sync_with_reply(const char *dest, const char *path,
		const char *interface, const char *method,
		const char *sig, char *param[])
{
	DBusConnection *conn;
	DBusMessage *msg;
	DBusMessageIter iter;
	DBusMessage *reply;
	DBusError err;
	int r;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		LOGE("dbus_bus_get error");
		return NULL;
	}

	msg = dbus_message_new_method_call(dest, path, interface, method);
	if (!msg) {
		LOGE("dbus_message_new_method_call(%s:%s-%s)",
				path, interface, method);
		return NULL;
	}

	dbus_message_iter_init_append(msg, &iter);
	r = append_variant(&iter, sig, param);
	if (r < 0) {
		LOGE("append_variant error(%d) %s %s:%s-%s",
				r, dest, path, interface, method);
		dbus_message_unref(msg);
		return NULL;
	}

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, DBUS_REPLY_TIMEOUT, &err);
	if (!reply) {
		LOGE("dbus_connection_send error(No reply) %s %s:%s-%s",
				dest, path, interface, method);
	}

	if (dbus_error_is_set(&err)) {
		LOGE("dbus_connection_send error(%s:%s) %s %s:%s-%s",
				err.name, err.message, dest, path, interface, method);
		dbus_error_free(&err);
		reply = NULL;
	}

	dbus_message_unref(msg);
	return reply;
}

static int dump_log(char **args)
{
	DBusError err;
	DBusMessage *msg;
	int ret, val;
	char *arr[2];

	if (!args[1] || !args[2])
		return -EINVAL;

	if (strcmp("dfms", args[2]) && strcmp("hardkey", args[2]) && strcmp("normal", args[2])) {
		usage();
		return -EINVAL;
	}

	printf("%s %s!\n", args[1], args[2]);

	arr[0] = "0";
	arr[1] = args[2];
	msg = dbus_method_sync_with_reply(CRASH_BUS_NAME,
		    command[command_id].path, command[command_id].iface,
		    "dump_log", "is", arr);
	if (!msg)
		return -EBADMSG;

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &val, DBUS_TYPE_INVALID);
	if (!ret) {
		printf("no message : [%s:%s]", err.name, err.message);
		dbus_error_free(&err);
		val = -ENOMSG;
	}

	dbus_message_unref(msg);
	return val;
}

static int delete_dump(char **args)
{
	DBusError err;
	DBusMessage *msg;
	int ret, val;
	char *arr[2];

	if (!args[1])
		return -EINVAL;

	printf("%s!\n", args[1]);

	arr[0] = "0";
	arr[1] = "normal";
	msg = dbus_method_sync_with_reply(CRASH_BUS_NAME,
		    command[command_id].path, command[command_id].iface,
		    "delete_dump", "is", arr);
	if (!msg)
		return -EBADMSG;

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &val, DBUS_TYPE_INVALID);
	if (!ret) {
		printf("no message : [%s:%s]", err.name, err.message);
		dbus_error_free(&err);
		val = -ENOMSG;
	}

	dbus_message_unref(msg);
	return val;
}

static const struct action {
	const enum command_type id;
	const int argc;
	int (* const func)(char **args);
	const char *option;
} actions[] = {
	{ DUMP_LOG,    3, dump_log,    "[normal|dfms|hardkey]"},
	{ DELETE_DUMP, 2, delete_dump, ""},
};

static void help()
{
	int i;

	printf("[usage] crashctl <command> <arg>\n");
	printf("command name & arg\n");
	for (i = 0; i < ARRAY_SIZE(actions); i++) {
		printf("    %s %s\n", command[actions[i].id].name,
			actions[i].option);
	}
}

int main(int argc, char *argv[])
{
	int i;
	if (argc == 1 || ((argc == 2) && !strcmp(argv[1], "--help"))) {
		help();
		return 0;
	}

	if (argc < 2) {
		usage();
		return -EINVAL;
	}

	for (i = 0; i < argc; i++)
		if (argv[i] == NULL) {
			usage();
			return -EINVAL;
		}

	for (i = 0; i < ARRAY_SIZE(command); i++)
		if (!strcmp(argv[1], command[i].name))
			break;

	if (i >= ARRAY_SIZE(command)) {
		printf("invalid command name! %s\n", argv[1]);
		usage();
		return -EINVAL;
	}

	command_id = command[i].id;

	if (actions[i].argc != argc) {
		printf("invalid arg count!\n");
		usage();
		return -EINVAL;
	}

	return actions[i].func(argv);
}

