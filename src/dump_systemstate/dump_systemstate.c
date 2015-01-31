/*
 * dump_systemstate
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
 * @file    dump_systemstate.c
 * @brief   dump system states.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "shared/util.h"

#define FILE_PERM (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
static struct dump_item {
	const char *title;
	const char *path;
} dump_item[] = {
	{"==== Binary version "            , "/etc/info.ini"},
	{"==== Tizen version "             , "/etc/tizen-release"},
	{"==== Kernel version "            , "/proc/version"},
	{"==== Boot arguments "            , "/proc/cmdline"},
	{"==== CPU & system architecture " , "/proc/cpuinfo"},
	{"==== System uptime "             , "/proc/uptime"},
	{"==== System statistics "         , "/proc/stat"},
	{"==== System memory usage "       , "/proc/meminfo"},
	{"==== Device major numbers "      , "/proc/devices"},
	{"==== System disk I/O satistics " , "/proc/diskstats"},
};

static void usage() {
	fprintf(stderr, "usage: dump_systemstate [-k] [-d] [-f file]\n"
			"  -f: write to file (instead of stdout)\n"
			"  -k: dump kernel messages (only root)\n"
			"  -d: dump dlog messages\n"
	   );
}

/* get disk used percentage */
static int get_disk_used_percent(const char *path)
{
	struct statfs lstatfs;
	int percent;

	if (!path)
		return -1;

	if (statfs(path, &lstatfs) < 0)
		return -1;
	percent = (((lstatfs.f_blocks - lstatfs.f_bfree) * 1000) / (lstatfs.f_blocks)) + 9;
	percent = percent/10;
	return percent;
}

int main(int argc, char *argv[]) {
	int c, ret, i, is_root, dpercent;
	const char *arg_file = NULL;
	int out_fd = -1;
	bool arg_dlog = false;
	bool arg_dmesg = false;
	char timestr[80];
	time_t cur_time;
	struct tm gm_tm;
	struct tm loc_tm;

	while ((c = getopt(argc, argv, "hf:kd")) != -1) {
		switch (c) {
		case 'd':
			arg_dlog = true;
			break;
		case 'k':
			arg_dmesg = true;
			break;
		case 'f':
			arg_file = optarg;
			break;
		case '?': printf("\n");
		case 'h':
			usage();
			ret = 0;
			goto exit;
		}
	}
	ret = 0;
	cur_time = time(NULL);
	gmtime_r(&cur_time, &gm_tm);
	localtime_r(&cur_time, &loc_tm);
	is_root = !(geteuid());

	/* open output file */
	if (arg_file == NULL) {
		out_fd = STDOUT_FILENO;
	} else {
		out_fd = open(arg_file, O_WRONLY | O_TRUNC | O_CREAT, FILE_PERM);
		if (out_fd < 0) {
			perror ("couldn't open output file");
			ret = out_fd;
			goto exit;
		}
	}
	/* print timestamp */
	strftime(timestr, sizeof(timestr),
					"%Y-%m-%d %H:%M:%S%z", &loc_tm);
	fprintf_fd(out_fd, "dump_systemstate: %s\n", timestr);

	for (i = 0; i < ARRAY_SIZE(dump_item); i++) {
		fsync(out_fd);
		fprintf_fd(out_fd, "\n%s(%s)\n",
						dump_item[i].title, dump_item[i].path);
		ret = dump_file_write_fd((char *)dump_item[i].path, out_fd);
		if (ret < 0)
			goto exit_close;
	}
	fprintf_fd(out_fd, "\n");

	fprintf_fd(out_fd, "\n==== System disk space usage (/bin/df -h)\n");
	ret = run_command_write_fd("/bin/df -h", out_fd);
	if (ret < 0)
		goto exit_close;

	dpercent = get_disk_used_percent("/opt");
	if (90 < dpercent) {
		fprintf_fd(out_fd, "\n==== System disk space usage detail - %d\% (/bin/du -ah /opt)\n", dpercent);
		ret = run_command_write_fd("/usr/bin/du -ah /opt --exclude=/opt/usr", out_fd);
		if (ret < 0)
			goto exit_close;
	}
	fprintf_fd(out_fd, "\n==== System timezone (ls -al /opt/etc/localtime)\n");
	ret = run_command_write_fd("ls -al /opt/etc/localtime", out_fd);
	if (ret < 0)
		goto exit_close;

	fprintf_fd(out_fd, "\n==== System summary (/usr/bin/top -bcH -n 1)\n");
	ret = run_command_write_fd("COLUMNS=200 /usr/bin/top -bcH -n 1", out_fd);
	if (ret < 0)
		goto exit_close;

	fprintf_fd(out_fd, "\n==== Current processes (/bin/ps auxfw)\n");
	ret = run_command_write_fd("/bin/ps auxfw", out_fd);
	if (ret < 0)
		goto exit_close;

	if (is_root) {
		fprintf_fd(out_fd, "\n==== System memory statistics (/usr/bin/memps -v)\n");
		ret = run_command_write_fd("/usr/bin/memps -v", out_fd);
		if (ret < 0)
			goto exit_close;

		fprintf_fd(out_fd, "\n==== System configuration (/usr/bin/vconftool get memory, db, file)\n");
		ret = run_command_write_fd("/usr/bin/vconftool get memory/ -r", out_fd);
		if (ret < 0)
			goto exit_close;

		ret = run_command_write_fd("/usr/bin/vconftool get db/ -r", out_fd);
		if (ret < 0)
			goto exit_close;

		ret = run_command_write_fd("/usr/bin/vconftool get file/ -r", out_fd);
		if (ret < 0)
			goto exit_close;
	}

	if (arg_dmesg && is_root) {
		fprintf_fd(out_fd, "\n==== Kernel messages (TZ=UTC /bin/dmesg -T)\n");
		ret = run_command_write_fd("TZ=UTC /bin/dmesg -T", out_fd);
		if (ret < 0)
			goto exit_close;
	}

	if (arg_dlog) {
		fprintf_fd(out_fd, "\n==== main log messages (/dev/log_main)\n");
		ret = run_command_write_fd("/usr/bin/dlogutil -d -v dump -b main", out_fd);
		if (ret < 0)
			goto exit_close;

		if(is_root) {
			fprintf_fd(out_fd, "\n==== system log messages (/dev/log_system)\n");
			ret = run_command_write_fd("/usr/bin/dlogutil -d -v dump -b system", out_fd);
			if (ret < 0)
				goto exit_close;

			fprintf_fd(out_fd, "\n==== radio log messages (/dev/log_radio)\n");
			ret = run_command_write_fd("/usr/bin/dlogutil -d -v dump -b radio", out_fd);
			if (ret < 0)
				goto exit_close;
		}
	}

exit_close:
	if (arg_file)
		close(out_fd);
exit:
	return ret;
}
