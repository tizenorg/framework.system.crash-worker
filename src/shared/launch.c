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


#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#include "log.h"
#include "launch.h"
#include "util.h"

#define APP_NAME "app"
#define APP_DEF_UID 5000
#define APP_DEF_GID 5000
#define APP_DEF_HOME "/opt/home/app"
#define APP_ENV_FILE "/run/tizen-mobile-env"

#define MAX_ARGS 255
#define LINE_MAX 1024
#define _S(str) ((str == NULL) ? "" : str)

extern char *trim_str(char *s);
static int setenv_file(const char *file_name)
{
	FILE *f = NULL;
	char line[LINE_MAX];
	char *start, *end, *name, *value;
	char *env_name, *env_value;
	int lineno = 0, ret = 0;

	if (!file_name) {
		ret = -1;
		goto error;
	}
	/* open file */
	f = fopen(file_name, "r");
	if (!f) {
		_E("Failed to open file %s", file_name);
		ret = -1;
		goto error;
	}
	/* parsing line by line */
	while (fgets(line, LINE_MAX, f) != NULL) {
		lineno++;
		start = line;
		start[strcspn(start, "\n\r")] = '\0';
		start = trim_str(start);

		if (*start) {
			/* parse name & value */
			end = strchr(start, '=');
			if (!end || *end != '=') {
				ret = -1;
				goto error;
			}
			*end = '\0';
			name = trim_str(start);
			value = trim_str(end + 1);
			env_name = strdup(name);
			if (!env_name)
				continue;
			env_value = strdup(value);
			if (!env_value) {
				free(env_name);
				continue;
			}
			if (validate_env_name(env_name, strlen(env_name)) < 0) {
				free(env_name);
				free(env_value);
				continue;
			}
			/* set env */
			_D("setenv %s=%s", env_name, env_value);
			ret = setenv(env_name, env_value, 1);
			free(env_name);
			free(env_value);
			if (ret < 0) {
				ret = -1;
				goto error;
			}
		}
	}
	_I("Success to setenv %s", file_name);
	fclose(f);
	return 0;

error:
	if (f)
		fclose(f);
	_E("Failed to read %s:%d!", file_name, lineno);
	return ret;
}

static void prepare_exec(const char *username)
{
	int i;
	int maxfd;
	uid_t uid;
	gid_t gid;
	struct passwd *pwd;

	if (username) {
		pwd = getpwnam(username);
		if (pwd) {
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
		} else {
			username = APP_NAME;
			uid = APP_DEF_UID;
			gid = APP_DEF_GID;
		}
		if (setenv("HOME", APP_DEF_HOME, 1) < 0)
			_E("failed setenv HOME");
		if (setenv_file(APP_ENV_FILE) < 0)
			_E("failed setenv_file");
		if (setregid(gid, gid) < 0)
			_E("failed setregid");
		if (initgroups(username, gid) < 0)
			_E("failed initgroups");
		if (setreuid(uid, uid) < 0)
			_E("failed setreuid");
	}
	maxfd = getdtablesize();
	for (i = 3; i < maxfd; i++)
		close(i);

	for (i = 0; i < _NSIG; i++)
		signal(i, SIG_DFL);
}

static int parse_cmd(const char *cmdline, char **argv, int max_args)
{
	const char *p;
	char *buf, *bufp;
	int nargs = 0;
	int escape = 0, squote = 0, dquote = 0;
	int bufsize;

	if (cmdline == NULL || cmdline[0] == '\0')
		return -1;
	bufsize = strlen(cmdline)+1;
	bufp = buf = malloc(bufsize);
	if (bufp == NULL || buf == NULL)
		return -1;
	memset(buf, 0, bufsize);
	p = cmdline;

	while (*p) {
		if (escape) {
			*bufp++ = *p;
			escape = 0;
		} else {
			switch (*p) {
				case '\\':
					escape = 1;
					break;
				case '"':
					if (squote)
						*bufp++ = *p;
					else
						dquote = !dquote;
					break;
				case '\'':
					if (dquote)
						*bufp++ = *p;
					else
						squote = !squote;
					break;
				case ' ':
					if (!squote && !dquote) {
						*bufp = '\0';
						if (nargs < max_args)
							argv[nargs++] = strdup(buf);
						bufp = buf;
						break;
					}
				default:
					*bufp++ = *p;
					break;
			}
		}
		p++;
	}

	if (bufp != buf) {
		*bufp = '\0';
		if (nargs < max_args)
			argv[nargs++] = strdup(buf);
	}

	argv[nargs++] = NULL;

	free(buf);
	return nargs;
}

int launch_app_with_nice(const char *file, char *const argv[], pid_t *pid, int _nice)
{
	int ret;
	int _pid;

	if (file == NULL || access(file, X_OK) != 0) {
		_E("launch app error: Invalid input");
		errno = EINVAL;
		return -1;
	}

	if (pid && (*pid > 0 && kill(*pid, 0) != -1))
		return *pid;

	_pid = fork();

	if (_pid == -1) {
		_E("fork error: %s", strerror(errno));
		/* keep errno */
		return -1;
	}

	if (_pid > 0) {     /* parent */
		if (pid)
			*pid = _pid;
		return _pid;
	}

	/* child */
	prepare_exec(APP_NAME);

	ret = nice(_nice);

	if (ret == -1 && errno != 0)
		_E("nice error: %s", strerror(errno));

	ret = execvp(file, argv);

	/* If failed... */
	_E("exec. error: %s", strerror(errno));
	return -2;
}

int launch_app_cmd_with_nice(const char *cmdline, int _nice)
{
	int i;
	int nargs;
	int ret;
	char *argv[MAX_ARGS + 1];

	nargs = parse_cmd(cmdline, argv, MAX_ARGS + 1);
	if (nargs == -1) {
		_E("launch app error: Invalid input");
		errno = EINVAL;
		return -1;
	}

	ret = launch_app_with_nice(argv[0], argv, NULL, _nice);

	for (i = 0; i < nargs; i++)
		free(argv[i]);

	return ret;
}

int launch_app_cmd(const char *cmdline)
{
	return launch_app_cmd_with_nice(cmdline, 0);
}

int launch_with_nice(const char *file, char *const argv[], pid_t *pid, int _nice)
{
	int ret;
	int _pid;

	if (file == NULL || access(file, X_OK) != 0) {
		_E("launch app error: Invalid input");
		errno = EINVAL;
		return -1;
	}

	if (pid && (*pid > 0 && kill(*pid, 0) != -1))
		return *pid;

	_pid = fork();

	if (_pid == -1) {
		_E("fork error: %s", strerror(errno));
		/* keep errno */
		return -1;
	}

	if (_pid > 0) {     /* parent */
		if (pid)
			*pid = _pid;
		return _pid;
	}

	/* child */
	prepare_exec(NULL);

	ret = nice(_nice);

	if (ret == -1 && errno != 0)
		_E("nice error: %s", strerror(errno));

	ret = execvp(file, argv);

	/* If failed... */
	_E("exec. error: %s", strerror(errno));
	return -2;
}

int launch_cmd_with_nice(const char *cmdline, int _nice)
{
	int i;
	int nargs;
	int ret;
	char *argv[MAX_ARGS + 1];

	nargs = parse_cmd(cmdline, argv, MAX_ARGS + 1);
	if (nargs == -1) {
		_E("launch app error: Invalid input");
		errno = EINVAL;
		return -1;
	}

	ret = launch_with_nice(argv[0], argv, NULL, _nice);

	for (i = 0; i < nargs; i++)
		free(argv[i]);

	return ret;
}

int launch_cmd(const char *cmdline)
{
	return launch_cmd_with_nice(cmdline, 0);
}

int launch_if_noexist(const char *execpath, const char *arg, ...)
{
	char *buf;
	int pid;
	int nice_value = 0;
	int flag = 0;
	int buf_size = -1;
	va_list argptr;

	if (execpath == NULL) {
		errno = EINVAL;
		return -1;
	}
	pid = get_exec_pid(execpath);
	if (pid > 0)
		return pid;

	va_start(argptr, arg);
	flag = va_arg(argptr, int);

	if (flag & LAUNCH_NICE)
		nice_value = va_arg(argptr, int);

	va_end(argptr);

	arg = _S(arg);

	buf_size = strlen(execpath) + strlen(arg) + 10;
	buf = malloc(buf_size);
	if (buf == NULL) {
		/* Do something for not enought memory error */
		_E("Malloc failed");
		return -1;
	}

	snprintf(buf, buf_size, "%s %s", execpath, arg);
	pid = launch_cmd_with_nice(buf, nice_value);
	if (pid == -2)
		exit(EXIT_FAILURE);
	free(buf);

	return pid;
}

int launch_evenif_exist(const char *execpath, const char *arg, ...)
{
	char *buf;
	int pid;
	int nice_value = 0;
	int flag = 0;
	int buf_size = -1;

	va_list argptr;

	if (execpath == NULL) {
		errno = EINVAL;
		return -1;
	}

	va_start(argptr, arg);
	flag = va_arg(argptr, int);

	if (flag & LAUNCH_NICE)
		nice_value = va_arg(argptr, int);

	va_end(argptr);

	arg = _S(arg);

	buf_size = strlen(execpath) + strlen(arg) + 10;
	buf = malloc(buf_size);
	if (buf == NULL) {
		// Do something for not enought memory error
		_E("Malloc failed");
		return -1;
	}

	snprintf(buf, buf_size, "%s %s", execpath, arg);
	pid = launch_cmd_with_nice(buf, nice_value);
	if (pid == -2)
		exit(EXIT_FAILURE);
	free(buf);

	return pid;
}

int launch_after_kill_if_exist(const char *execpath, const char *arg, ...)
{
	char *buf;
	int pid;
	int flag;
	int buf_size;
	int exist_pid;
	va_list argptr;
	int nice_value = 0;

	if (execpath == NULL) {
		errno = EINVAL;
		return -1;
	}

	if ((exist_pid = get_exec_pid(execpath)) > 0)
		kill(exist_pid, SIGTERM);

	va_start(argptr, arg);
	flag = va_arg(argptr, int);

	if (flag & LAUNCH_NICE)
		nice_value = va_arg(argptr, int);

	va_end(argptr);

	arg = _S(arg);

	buf_size = strlen(execpath) + strlen(arg) + 10;
	buf = malloc(buf_size);
	if (buf == NULL) {
		/* Do something for not enought memory error */
		_E("Malloc Failed");
		return -1;
	}

	snprintf(buf, buf_size, "%s %s", execpath, arg);
	pid = launch_cmd_with_nice(buf, nice_value);
	if (pid == -2)		/* It means that the 'execvp' return -1 */
		exit(EXIT_FAILURE);
	free(buf);

	return pid;

}
