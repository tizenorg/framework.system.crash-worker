/*
 * crash-manager
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <wait.h>
#include <ctype.h>
#include <grp.h>

#include "util.h"
#include "log.h"

int system_command(char *command)
{
	int pid = 0,
		status = 0;
	const char *environ[] = { NULL };

	if (command == NULL)
		return -1;
	pid = fork();
	if (pid == -1)
		return -1;
	if (pid == 0) {
		char *argv[4];
		argv[0] = "sh";
		argv[1] = "-c";
		argv[2] = (char *)command;
		argv[3] = 0;
		execve("/bin/sh", argv, (char **)environ);
		exit(127);
	}
	do {
		if (waitpid(pid, &status, 0) == -1) {
			if (errno != EINTR)
				return -1;
		} else {
			if (WIFEXITED(status)) {
				return WEXITSTATUS(status);
			} else if (WIFSIGNALED(status)) {
				return WTERMSIG(status);
			} else if (WIFSTOPPED(status)) {
				return WSTOPSIG(status);
			}
		}
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));

	return 0;
}

int system_command_with_timeout(int timeout_seconds, char *command)
{
	const char *environ[] = { NULL };

	if (command == NULL)
		return -1;
	clock_t start = clock();
	pid_t pid = fork();
	/* handle error case */
	if (pid < 0) {
		_E("fork: %s\n", strerror(errno));
		return pid;
	}
	/* handle child case */
	if (pid == 0) {
		char *argv[4];
		argv[0] = "sh";
		argv[1] = "-c";
		argv[2] = (char *)command;
		argv[3] = 0;

		execve("/bin/sh", argv, (char **)environ);
		_SI("exec(%s): %s\n", command, strerror(errno));
		_exit(-1);
	}
	/* handle parent case */
	for (;;) {
		int status;
		pid_t p = waitpid(pid, &status, WNOHANG);
		float elapsed = (float) (clock() - start) / CLOCKS_PER_SEC;
		if (p == pid) {
			if (WIFSIGNALED(status))
				_SI("%s: Killed by signal %d\n", command, WTERMSIG(status));
			else if (WIFEXITED(status) && WEXITSTATUS(status) > 0)
				_SI("%s: Exit code %d\n", command, WEXITSTATUS(status));
			return WEXITSTATUS(status);
		}
		if (timeout_seconds && elapsed > timeout_seconds) {
			_SI("%s: Timed out after %.1fs (killing pid %d)\n",
					command, elapsed, pid);
			kill(pid, SIGTERM);
			return -1;
		}
		/* poll every 0.1 sec */
		usleep(100000);
	}
}

/* WARNING : formatted string buffer is limited to 1024 byte */
int fprintf_fd(int fd, const char *fmt, ...)
{
	int n;
	int ret;
	char buff[1024];
	va_list args;

	va_start(args, fmt);
	n = vsnprintf(buff, 1024 - 1, fmt, args);
	ret = write(fd, buff, n);
	va_end(args);
	return ret;
}

int file_exist(const char *file)
{
	FILE *fp;

	fp = fopen(file, "r");
	if (fp == NULL)
		return -1;
	fclose(fp);
	return 1;
}

int write_fd(int fd, const void *buf, int len)
{
	int count;
	int total;
	total = 0;
	while (len) {
		count = write(fd, buf, len);
		if (count < 0) {
			if (total)
				return total;
			return count;
		}
		total += count;
		buf = ((const char *)buf) + count;
		len -= count;
	}
	return total;
}

int copy_file(char *src, char *dst)
{
	int sfd;
	int dfd;
	char buf[PIPE_BUF];

	if(!src || !dst) {
		_E("Invalid argument\n");
		return -1;
	}
	sfd = open(src, O_RDONLY);
	if (sfd < 0) {
		_E("Failed to open (%s)\n", src);
		return -1;
	}
	dfd = open(dst, O_WRONLY|O_CREAT|O_EXCL, 0644);
	if (dfd < 0) {
		close(sfd);
		_SE("Failed to open (%s)\n", dst);
		return -1;
	}
	for (;;) {
		int ret = read(sfd, buf, sizeof(buf));
		if (ret > 0)
			ret = write_fd(dfd, buf, ret);
		if (ret <= 0)
			break;
	}
	close(sfd);
	close(dfd);
	return 1;
}

int cat_file(char *src, char *dst)
{
	int sfd;
	int dfd;
	char buf[PIPE_BUF];

	if(!src || !dst) {
		_E("Invalid argument\n");
		return -1;
	}
	sfd = open(src, O_RDONLY);
	if (sfd < 0) {
		_SE("Failed to open (%s)\n", src);
		return -1;
	}
	dfd = open(dst, O_WRONLY|O_APPEND);
	if (dfd < 0) {
		close(sfd);
		_SE("Failed to open (%s)\n", dst);
		return -1;
	}
	for (;;) {
		int ret = read(sfd, buf, sizeof(buf));
		if (ret > 0)
			ret = write_fd(dfd, buf, ret);
		if (ret <= 0)
			break;
	}
	close(sfd);
	close(dfd);
	return 1;
}

int move_file(char *src, char *dst)
{
	if (copy_file(src, dst) < 0)
		return -1;
	if (unlink(src) < 0)
		return -1;
	return 1;
}

int dump_file_write_fd(char *src, int dfd)
{
	int sfd;
	char buf[PIPE_BUF];

	if(!src) {
		_E("Invalid argument\n");
		return -1;
	}
	sfd = open(src, O_RDONLY);
	if (sfd < 0) {
		_SE("Failed to open (%s)\n", src);
		return -1;
	}
	for (;;) {
		int ret = read(sfd, buf, sizeof(buf));
		if (ret > 0)
			ret = write_fd(dfd, buf, ret);
		if (ret <= 0)
			break;
	}
	close(sfd);
	return 1;
}

int run_command_write_fd(char *cmd, int dfd)
{
	FILE *fp;
	char buff[PIPE_BUF];
	int ret;

	if (!cmd) {
		_E("Invalid argument\n");
		return -1;
	}

	fp = popen(cmd, "r");
	if (fp == NULL) {
		_E("Failed to popen\n");
		return -1;
	}
	while(fgets(buff, PIPE_BUF, fp) != NULL) {
		write_fd(dfd, buff, strlen(buff));
	}
	ret = pclose(fp);
	return ret;
}

static int remove_dir_internal(int fd)
{
	DIR *dir;
	struct dirent *de;
	int subfd, ret = 0;

	dir = fdopendir(fd);
	if (!dir)
		return -1;
	while ((de = readdir(dir))) {
		if (de->d_type == DT_DIR) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			subfd = openat(fd, de->d_name, O_RDONLY | O_DIRECTORY);
			if (subfd < 0) {
				_SE("Couldn't openat %s: %s\n", de->d_name, strerror(errno));
				ret = -1;
				continue;
			}
			if (remove_dir_internal(subfd)) {
				ret = -1;
			}
			close(subfd);
			if (unlinkat(fd, de->d_name, AT_REMOVEDIR) < 0) {
				_SE("Couldn't unlinkat %s: %s\n", de->d_name, strerror(errno));
				ret = -1;
			}
		} else {
			if (unlinkat(fd, de->d_name, 0) < 0) {
				_SE("Couldn't unlinkat %s: %s\n", de->d_name, strerror(errno));
				ret = -1;
			}
		}
	}
	closedir(dir);
	return ret;
}

int remove_dir(const char *path, int del_dir)
{
	int fd, ret = 0;

	if (!path)
		return -1;
	fd = open(path, O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		_SE("Couldn't opendir %s: %s\n", path, strerror(errno));
		return -errno;
	}
	ret = remove_dir_internal(fd);
	close(fd);

	if (del_dir) {
		if (rmdir(path)) {
			_SE("Couldn't rmdir %s: %s\n", path, strerror(errno));
			ret = -1;
		}
	}
	return ret;
}

int make_dir(const char *path, mode_t mode, const char *grname)
{
	mode_t old_mask;
	struct group *group_entry;
	int ret;

	if (!grname || !path)
		return -1;
	if (access(path, F_OK) == 0)
		return 0;
	old_mask = umask(002);
	ret = mkdir(path, mode);
	if (ret < 0)
		return -1;
	group_entry = getgrnam(grname);
	if (group_entry == NULL) {
		umask(old_mask);
		return -1;
	}
	if (chown(path, 0, group_entry->gr_gid) < 0)
		_SW("can't chown (%s)\n", path);
	umask(old_mask);

	return 0;
}

int get_exec_pid(const char *execpath)
{
	DIR *dp;
	struct dirent *dentry;
	int pid = -1, fd;
	int ret;
	char buf[PATH_MAX];
	char buf2[PATH_MAX];

	dp = opendir("/proc");
	if (!dp) {
		_E("FAIL: open /proc");
		return -1;
	}

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		pid = atoi(dentry->d_name);

		snprintf(buf, PATH_MAX, "/proc/%d/cmdline", pid);
		fd = open(buf, O_RDONLY);
		if (fd < 0)
			continue;
		ret = read(fd, buf2, PATH_MAX);
		close(fd);

		if (ret < 0 || ret >= PATH_MAX)
			continue;

		buf2[ret] = '\0';

		if (!strcmp(buf2, execpath)) {
			closedir(dp);
			return pid;
		}
	}

	errno = ESRCH;
	closedir(dp);
	return -1;
}

int get_file_count(char *path)
{
	DIR *dir;
	struct dirent *dp;
	int count = 0;

	dir = opendir(path);
	if (!dir)
		return 0;
	while ((dp = readdir(dir)) != NULL) {
		const char *name = dp->d_name;
		/* always skip "." and ".." */
		if (name[0] == '.') {
			if (name[1] == 0)
				continue;
			if ((name[1] == '.') && (name[2] == 0))
				continue;
		}
		count++;
	}
	closedir(dir);
	return count;
}

int get_directory_usage(char *path)
{
	DIR *dir;
	struct dirent *de;
	struct stat st;
	size_t usage = 0;
	int fd = -1;

	fd = open(path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
	if (fd < 0)
		return -1;
	dir = fdopendir(fd);
	if (!dir) {
		close(fd);
		return -1;
	}
	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
			_SE("Failed to fstatat  %s: %s\n", de->d_name, strerror(errno));
			continue;
		}
		usage += st.st_size;
	}
	closedir(dir);
	close(fd);
	return usage;
}


int validate_env_name(char *name, int len)
{
	char *p;

	if (len <= 0)
		return -1;

	if (len > NAME_MAX)
		return -1;

	if (name[0] >= '0' && name[0] <= '9')
		return -1;

	for (p = name; p < name + len; p++)
		if (!((*p >= 'A' && *p <= 'Z') ||
				(*p >= '0' && *p <= '9') ||
					*p == '_'))
			return -1;
	return 0;
}

int validate_file_name(char *name, int len)
{
	char *p;

	if (len <= 0)
		return -1;

	if (len > NAME_MAX)
		return -1;

	if ((name[0] == '-') || (name[0] >= '0' && name[0] <= '9'))
		return -1;

	for (p = name; p < name + len; p++)
		if (!((*p >= 0x07 && *p <= 0x0C) ||
				(*p >= 0x20 && *p <= 0x7E)))
		return -1;

	return 0;
}
/**
 * @}
 */
