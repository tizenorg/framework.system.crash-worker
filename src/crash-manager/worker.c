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
 * @file    worker.c
 * @brief   crash worker
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <grp.h>
#include <dirent.h>
#include <vconf.h>
#include <pkgmgr-info.h>
#include <system_info.h>
#include <pwd.h>
#include <systemd/sd-journal.h>

#include "shared/util.h"
#include "shared/launch.h"
#include "shared/log.h"
#include "crash-dbus.h"
#include "worker.h"

#define CRASH_REPORT_EXTENSION      ".cs"
#define CORE_DUMP_EXTENSION         ".core"
#define CORE_RETENTION_TIME         (60 * 60 * 24 * 2)
#define CRASH_USERNAME              "crash"
#define CRASH_GID                   6828
#define CRASH_DELIMITER             "|"
#define DM_BUF_SIZE                 (1024 * 48)
#define SIG_STR_MAX                 3
#define PID_STR_MAX                 6
#define PROCESSNAME_MAX             NAME_MAX
#define EXEPATH_MAX                 PATH_MAX
#define TIME_STR_MAX                65
#define CRASHID_MAX                 24
#define MESSAGE_MAX                 (SIG_STR_MAX) + (PID_STR_MAX) + (NAME_MAX) + \
                                    (PATH_MAX) + (CRASHID_MAX) + (TIME_STR_MAX)
#define TIZEN_DEBUG_MODE_FILE       "/opt/etc/.debugmode"
#define CRASH_PATH                  "/opt/usr/share/crash"
#define CRASH_CHECK_DISK_PATH       "/opt/usr"
#define CRASH_POPUP_PATH            "/usr/apps/org.tizen.crash-popup/bin/crash-popup"
#define CRASH_CRASHINFO_TITLE       "Crash Information"
#define CRASH_DLOG_TITLE            "Latest Debug Message Information"
#define CRASH_DLOG_TITLE_E          "End of latest debug message"
#define CRASH_PACKAGEINFO_TITLE     "Package Information"
#define CRASH_SW_VERSIONINFO_TITLE  "S/W Version Information"

static uid_t crash_gid;
struct crash_info
{
	int isappid;
	int isdumpdlog;
	int signum;
	int pid;
	struct tm crash_tm;
	char timesec[TIME_STR_MAX];
	char processname[PROCESSNAME_MAX];
	char exepath[EXEPATH_MAX];
	char crashid[CRASHID_MAX];
	char timestr[TIME_STR_MAX];
	char app_id[PROCESSNAME_MAX];
	char dumppath[PATH_MAX];
	char reportfile[NAME_MAX];
	char reportdestfile[NAME_MAX];
	char infofile[NAME_MAX];
};

static int mkdir_path(const char *path)
{
    return make_dir(path, 0775, "crash");
}

static void check_debugmode(Manager *manager)
{
	if (access(TIZEN_DEBUG_MODE_FILE, F_OK) == 0) {
		manager->debug_mode = 1;
		manager->conf.allow_popup = 1;
		_D("debug mode on");
	} else {
		manager->debug_mode = 0;
		manager->conf.allow_popup = 0;
		_D("debug mode off");
	}
}

/* check disk available size */
static int check_disk_available(const char *path, int check_size)
{
	struct statfs lstatfs;
	int avail_size = 0;

	if (!path)
		return -1;

	if (statfs(path, &lstatfs) < 0)
		return -1;
	avail_size = (int)(lstatfs.f_bavail * (lstatfs.f_bsize/1024));

	if (check_size > avail_size) {
		_W("avail_size is (%d)", avail_size);
		return -1;
	}
	return 0;
}

static int g_spawn_command(char *command) {
    GError *error;

   if (command == NULL)
		return -1;
	if (!g_spawn_command_line_sync(command, NULL, NULL, NULL, &error)) {
		_E("Error!: %s", error->message);
		g_error_free(error);
		return -1;
	}
	return 0;
};

static int parse_crash_info(char *msg, struct crash_info *info)
{
	int len;
	char *ptr = NULL;
	char buffer[NAME_MAX];
	time_t crash_time;
	time_t cur_time;
	struct tm cur_tm;

	if (msg == NULL || info == NULL) {
		_E("Error! Invalid arguments");
		return -1;
	}
	len = strlen(msg);
	if (len <= 0 || MESSAGE_MAX < len) {
		_E("Error! Invalid arguments");
		return -1;
	}
	ptr = strtok(msg, CRASH_DELIMITER);
	if (ptr == NULL) {
		_SE("Failed to strtok msg ptr(%s)", msg);
		return -1;
	}
	snprintf(buffer, NAME_MAX, "%s", ptr);
	info->signum = atoi(buffer);
	ptr = strtok(NULL, CRASH_DELIMITER);
	if (ptr == NULL) {
		_SE("Failed to strtok msg ptr(%s)", msg);
		return -1;
	}
	snprintf(buffer, NAME_MAX, "%s", ptr);
	info->pid = atoi(buffer);

	ptr = strtok(NULL, CRASH_DELIMITER);
	if (ptr == NULL) {
		_SE("Failed to strtok msg ptr(%s)", msg);
		return -1;
	}
	snprintf(info->timesec, TIME_STR_MAX, "%s", ptr);
	crash_time = atol(info->timesec);
	localtime_r(&crash_time, &(info->crash_tm));

	cur_time = time(NULL);
	localtime_r(&cur_time, &cur_tm);
	strftime(info->timestr, sizeof(info->timestr), "%Y%m%d%H%M%S", &cur_tm);

	ptr = strtok(NULL, CRASH_DELIMITER);
	if (ptr == NULL) {
		_SE("Failed to strtok msg ptr(%s)", msg);
		return -1;
	}
	snprintf(info->processname, PROCESSNAME_MAX, "%s",  ptr);
	ptr = strtok(NULL, CRASH_DELIMITER);
	if (ptr == NULL) {
		_SE("Failed to strtok msg ptr(%s)", msg);
		return -1;
	}
	snprintf(info->exepath, EXEPATH_MAX, "%s", ptr);
	ptr = strtok(NULL, CRASH_DELIMITER);
	if (ptr == NULL) {
		_SE("Failed to strtok msg ptr(%s)", msg);
		return -1;
	}
	snprintf(info->crashid, CRASHID_MAX, "%s", ptr);
	if (strstr(info->crashid, info->timesec))
		return 0;
	else
		return -1;
}

static int is_running_process(pid_t pid)
{
	char buf[PATH_MAX + 1];

	snprintf(buf, sizeof(buf), "/proc/%d", pid);
	if (!access(buf, R_OK))
		return 1;
	return 0;
}

static int launch_crash_popup(Manager *manager, struct crash_info *cinfo)
{
	static int popup_pid = 0;
	int buf_size;
	int ret, val;
	char *buf;

	if (manager == NULL || cinfo == NULL)
		return -1;

	if (vconf_get_int(VCONFKEY_SYSMAN_POWER_OFF_STATUS, &val) == 0) {
		if (val == VCONFKEY_SYSMAN_POWER_OFF_DIRECT ||
				val == VCONFKEY_SYSMAN_POWER_OFF_RESTART)
			return -1;
	}

	if (is_running_process(popup_pid)) {
		_I("popup is running(%d)", popup_pid);
		return 0;
	}

	ret = request_crash_popup(manager->conn, cinfo->processname, cinfo->exepath);
	if (ret < 0) {
		buf_size = sizeof(CRASH_POPUP_PATH) + strlen(cinfo->processname) + strlen(cinfo->exepath) + 3;
		buf = malloc(buf_size);
		if (!buf)
			goto exit;
		snprintf(buf, buf_size, "%s %s %s", CRASH_POPUP_PATH, cinfo->processname, cinfo->exepath);
		_E("Failed to launch syspopup so launch again directly");
		ret = launch_app_cmd(buf);
		free(buf);
	}
	popup_pid = ret;

	if (popup_pid < 0)
		return -1;
	_SI("Crash-popup is launched - process(%s), popup pid(%d)", cinfo->processname, popup_pid);
	return 0;

exit:
	return -1;
}

/* make dump directory */
static int make_dump_dir(struct crash_info *cinfo)
{
	if (cinfo == NULL)
		return -1;
	snprintf(cinfo->dumppath, sizeof(cinfo->dumppath),
			"%s/%s_%d_%s", CRASH_DUMP_PATH,
			cinfo->processname, cinfo->pid, cinfo->timestr);
	/* make debug directory if  absent */
	if (mkdir_path(CRASH_PATH) < 0)
		return -1;
	if (mkdir_path(cinfo->dumppath) < 0)
		return -1;
	_SD("dump dir(%s)", cinfo->dumppath);
	return 1;
}

static int category_func(const char *name, void *user_data)
{
	static int i = 0;
	FILE *fp = (FILE *)user_data;

	if (i)
		fprintf(fp, ", ");
	fprintf(fp, "%s", name);
	i = 1;
	return 0;
}

/* ail filter list function for getting package information */
static int appinfo_list_func(const pkgmgrinfo_appinfo_h apphandle, void *user_data)
{
	char *str = NULL, *pkgid = NULL;
	pkgmgrinfo_pkginfo_h pkghandle;
	FILE *fp = (FILE *)user_data;

	pkgmgrinfo_appinfo_get_pkgname(apphandle, &str);
	fprintf(fp, "Package Name: %s\n", str);

	pkgmgrinfo_appinfo_get_pkgid(apphandle, &pkgid);
	fprintf(fp, "Package ID : %s\n", pkgid);

	pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);

	pkgmgrinfo_pkginfo_get_version(pkghandle, &str);
	fprintf(fp, "Version: %s\n", str);

	pkgmgrinfo_pkginfo_get_type(pkghandle, &str);
	fprintf(fp, "Package Type: %s\n", str);

	pkgmgrinfo_appinfo_get_label(apphandle, &str);
	fprintf(fp, "App Name: %s\n", str);

	pkgmgrinfo_appinfo_get_appid(apphandle, &str);
	fprintf(fp, "App ID: %s\n", str);

	pkgmgrinfo_appinfo_get_apptype(apphandle, &str);
	fprintf(fp, "Type: %s\n", str);
	fprintf(fp, "Categories: ");
	pkgmgrinfo_appinfo_foreach_category(apphandle, category_func, fp);
	fprintf(fp, "\n");

	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
	return 0;
}

/* pkgmgrinfo filter list function for getting application ID */
static int appinfo_get_appid_func(pkgmgrinfo_appinfo_h handle,
		void *user_data)
{
	char *str = NULL;
	int ret = PMINFO_R_ERROR;

	pkgmgrinfo_appinfo_get_appid(handle, &str);
	if (str) {
		(*(char **)user_data) = strdup(str);
		if (user_data)
			ret = PMINFO_R_OK;
	}
	return ret;
}

/* get application ID by ail filter */
static int get_app_id(char *exepath, char *app_id, int len)
{
	pkgmgrinfo_appinfo_filter_h handle = NULL;
	int count, ret = 0;
	char *appid = NULL;

	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	if (ret != PMINFO_R_OK) {
		ret = -1;
		goto out;
	}

	ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_EXEC, exepath);
	if (ret != PMINFO_R_OK) {
		ret = -1;
		goto out_free;
	}

	ret = pkgmgrinfo_appinfo_filter_count(handle, &count);
	if (ret != PMINFO_R_OK) {
		ret = -1;
		goto out_free;
	}

	if (count < 1) {
		ret = -1;
		goto out_free;
	} else {
		ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(handle, appinfo_get_appid_func, &appid);
		if (ret != PMINFO_R_OK) {
			ret = -1;
			goto out_free;
		}
		if (appid) {
			snprintf(app_id, len, "%s", appid);
			_SI("appid (%s)", app_id);
			ret = 0;
			free(appid);
		}
	}

out_free:
	pkgmgrinfo_appinfo_filter_destroy(handle);
out:
	return ret;
}

static int create_report_file(struct crash_info *cinfo)
{
	int csfd;
	int ret;

	if (cinfo == NULL || cinfo->reportfile == NULL)
		return -1;

	if (access(cinfo->reportfile, F_OK) == 0) {
		ret = unlink(cinfo->reportfile);
		if (ret < 0) {
			ret = -errno;
			_SE("Failed to remove(file:%s, errno:%d)", cinfo->reportfile, ret);
			return ret;
		}
	}

	csfd = creat(cinfo->reportfile,
			(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH));
	if (csfd < 0) {
		_SW("Failed to create %s. errno = %s\n",
				cinfo->reportfile, strerror(errno));
		return -1;
	}
	if (chown(cinfo->reportfile, -1, crash_gid) < 0)
		_SW("Failed to chown (%s)", cinfo->reportfile);
	if (chmod(cinfo->reportfile, 0766) < 0)
		_SW("Failed to chmod (%s)", cinfo->reportfile);
	close(csfd);
	return 0;
}

/* write crash base information at crash report file */
static int write_crash_base_info(struct crash_info *cinfo)
{
	char timestr[64];
	char *p_exepath = NULL;
	FILE *csfp;

	if (cinfo == NULL)
		return -1;
	csfp = fopen(cinfo->reportfile, "a+");
	if (!csfp) {
		_SE("Failed to open (%s)\n", cinfo->reportfile);
		return -1;
	}
	/* print version info */
	fprintf(csfp, "\n%s\n", CRASH_CRASHINFO_TITLE);
	p_exepath = strrchr(cinfo->exepath, '/');
	if (p_exepath != NULL && p_exepath[1] != '\0')
		fprintf(csfp,
				"Process Name: %s\n", p_exepath + 1);
	else
		fprintf(csfp,
				"Process Name: %s\n", cinfo->processname);
	fprintf(csfp, "PID: %d\n", cinfo->pid);
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S%z", &(cinfo->crash_tm));
	fprintf(csfp, "Date: %s\n", timestr);
	fclose(csfp);
	sd_journal_print(LOG_INFO,
				"%s=Process Name: %s, PID: %d, Date: %s, Exec : %s, Signal: %d",
				CRASH_CRASHINFO_TITLE, cinfo->processname,
				cinfo->pid, timestr, cinfo->exepath, cinfo->signum);
	return 0;
}

/* write system version information at crash report file */
static int write_version_info(struct crash_info *cinfo)
{
	int ret;
	FILE *csfp = NULL;
	char *tizenversion = NULL;
	char *model = NULL;
	char *buildstring = NULL;
	char *builddate = NULL;
	char *buildtime = NULL;

	if (cinfo == NULL)
		return -1;
	csfp = fopen(cinfo->reportfile, "a+");
	if (!csfp) {
		_SE("Failed to open (%s)\n", cinfo->reportfile);
		return -1;
	}
	/* print version info */
	fprintf(csfp, "%s\n", CRASH_SW_VERSIONINFO_TITLE);
	if (system_info_get_platform_string("http://tizen.org/system/model_name", &model) < 0) {
		ret = -1;
		goto exit;
	}
	if (model) {
		fprintf(csfp, "Model: %s\n", model);
		free(model);
	}
	if (system_info_get_platform_string("http://tizen.org/feature/platform.version",
				&tizenversion) < 0) {
		ret = -1;
		goto exit;
	}
	if (tizenversion) {
		fprintf(csfp, "Tizen-Version: %s\n", tizenversion);
		free(tizenversion);
	}
	if (system_info_get_platform_string("http://tizen.org/system/build.string",
				&buildstring) < 0) {
		ret = -1;
		goto exit;
	}
	if (buildstring) {
		fprintf(csfp, "Build-Number: %s\n", buildstring);
		free(buildstring);
	}
	if (system_info_get_platform_string("http://tizen.org/system/build.date",
				&builddate) < 0) {
		ret = -1;
		goto exit;
	}
	if (system_info_get_platform_string("http://tizen.org/system/build.time",
				&buildtime) < 0) {
		ret = -1;
		goto exit;
	}
	if (builddate && buildtime)
		fprintf(csfp, "Build-Date: %s %s\n", builddate, buildtime);

	if (builddate)
		free(builddate);

	if (buildtime)
		free(buildtime);

	ret = 0;

exit:
	fclose(csfp);
	return ret;
}

/* write dlogdump at crash report file */
static int write_dlogdump(struct crash_info *cinfo)
{
	int readnum;
	int pos = 0;
	FILE *mfp;
	FILE *csfp;
	char *tbuf;
	char fbuf[PATH_MAX] = {0, };
	char cbuf[PATH_MAX] = {0, };

	if (cinfo == NULL)
		return -1;
	if (!cinfo->isdumpdlog)
		return -1;
	csfp = fopen(cinfo->reportfile, "a+");
	if (!csfp) {
		_SE("Failed to open (%s)", cinfo->reportfile);
		return -1;
	}
	tbuf = (char *)malloc(DM_BUF_SIZE);
	if (tbuf == NULL) {
		fclose(csfp);
		return -1;
	}
	fprintf(csfp, "\n%s\n", CRASH_DLOG_TITLE);
	snprintf(fbuf, sizeof(fbuf), "%s/%s_%d_%s_main.dlogdump", cinfo->dumppath,
			cinfo->processname, cinfo->pid, cinfo->timestr);
	mfp = fopen(fbuf, "r");
	if (mfp == NULL) {
		_SE("Failed to open %s", fbuf);
		fclose(csfp);
		free(tbuf);
		return -1;
	}
	while (fgets(cbuf, PATH_MAX, mfp)) {
		int len = strlen(cbuf);
		if (!len)
			continue;
		cbuf[len] = '\0';
		if (strstr(cbuf, cinfo->crashid) != NULL)
			pos = ftell(mfp);
	}
	/* check data size from end postion */
	if (fseek(mfp, (pos - DM_BUF_SIZE - 1), SEEK_SET) < 0) {
		fseek(mfp, 0L, SEEK_SET);
		readnum = fread(tbuf, 1, DM_BUF_SIZE - 1, mfp);
	} else {
		readnum = fread(tbuf, 1, DM_BUF_SIZE - 1, mfp);
	}
	tbuf[readnum] = '\0';
	fprintf(csfp, "--------- beginning of /dev/log_main\n");
	fprintf(csfp, "%s\n", tbuf);
	fclose(csfp);
	fclose(mfp);
	free(tbuf);
	if (unlink(fbuf) < 0)
		_SE("Failed to unlink (%s)", fbuf);
	return 0;
}

/* dump /dev/log_main*/
static int dump_dlog(struct crash_info *cinfo)
{
	int ret = 0;
	char cbuf[PATH_MAX] = {0, };  /* commad buff */
	char buf[NAME_MAX] = {0, };  /* buffer */

	if (cinfo == NULL)
		return -1;
	cinfo->isdumpdlog = 0;
	snprintf(buf, sizeof(buf), "%s/%s_%d_%s_main.dlogdump", cinfo->dumppath,
			cinfo->processname, cinfo->pid, cinfo->timestr);
	_SD("make main log file in %s", buf);
	snprintf(cbuf, sizeof(cbuf), "/usr/bin/dlogutil -b main -v time -d -r 3072 -n 1 -f %s", buf);
	ret = g_spawn_command(cbuf);
	if (0 <= ret)
		cinfo->isdumpdlog = 1;
	return 0;
}

/* get pakage information from ail */
static int write_package_info(struct crash_info *cinfo)
{
	FILE *fp;
	pkgmgrinfo_appinfo_filter_h handle = NULL;
	int ret = 0;

	if (cinfo == NULL)
		return -1;
	if (!cinfo->isappid)
		return 0;

	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	if (ret != PMINFO_R_OK) {
		return -1;
	}

	ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_EXEC, cinfo->exepath);
	if (ret != PMINFO_R_OK) {
		ret = -1;
		goto out_free;
	}
	fp = fopen(cinfo->reportfile, "a+");
	if(fp == NULL) {
		ret = -1;
		goto out_free;
	}
	fseek(fp, 0L, SEEK_END);
	fprintf(fp, "\n%s\n", CRASH_PACKAGEINFO_TITLE);
	ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(handle, appinfo_list_func, (void *)fp);
	if (ret != PMINFO_R_OK) {
		ret = -1;
	}
	fclose(fp);
out_free:
	pkgmgrinfo_appinfo_filter_destroy(handle);
	return ret;
}

static int write_crash_info(struct crash_info *cinfo)
{
	if (cinfo == NULL)
		return -1;
	snprintf(cinfo->infofile, sizeof(cinfo->infofile),
			"%s/%s.info", CRASH_INFO_PATH,
			cinfo->crashid);
	if (access(cinfo->infofile, R_OK) != -1) {
		if (cat_file(cinfo->infofile, cinfo->reportfile) < 0)
			_W("Failed to cat libsys info file");
	}
	return 0;
}

/* move core dump file */
static int gather_coredump(struct crash_info *cinfo, int zip)
{
	DIR * dir = NULL;
	struct dirent *de = NULL;
	bool found = false;
	char buf[NAME_MAX] = {0, };
	char sbuf[NAME_MAX] = {0, };
	char dbuf[NAME_MAX] = {0, };
	char cmdb[PATH_MAX] = {0, };

	if (cinfo == NULL)
		return -1;
	/* search core file */
	if ((dir = opendir(CRASH_COREDUMP_PATH)) == NULL) {
		_W("Failed to opendir CRASH_COREDUMP_PATH");
		return -1;
	}
	snprintf(buf, sizeof(buf), "%d_%d", cinfo->pid, cinfo->signum);

	while ((de = readdir(dir)) != NULL) {
		 if (de->d_type == DT_DIR)
			continue;
		if (strstr(de->d_name, buf)) {
			snprintf(sbuf, sizeof(sbuf), "%s/%s",
			CRASH_COREDUMP_PATH, de->d_name);
			_I("Found core dump! %s", sbuf);
			found = true;
			break;
		}
	}
	closedir(dir);

	if (found != true) {
		_I("Failed to found core dump!");
		return -1;
	}

	snprintf(dbuf, sizeof(dbuf), "%s/%s_%s.coredump",
			cinfo->dumppath, cinfo->processname, cinfo->timestr);

	/* move core file */
	if (move_file(sbuf, dbuf) < 0)
		_W("Failed to move_file from %s to %s", sbuf, dbuf);

	if (chown(dbuf, -1, crash_gid) < 0)
		_SW("Failed to chown (%s)\n", dbuf);

	if (zip && (access(dbuf, F_OK) == 0)) {
		if (chdir(cinfo->dumppath) < 0)
			_W("Failed to chdir");
		snprintf(cmdb, sizeof(cmdb), "/usr/bin/gzip %s", dbuf);
		if (g_spawn_command(cmdb) < 0) {
			_W("Failed to %s", cmdb);
			return -1;
		}
	}
	return 0;
}

/* dump system state */
static int dump_system_state(struct crash_info *cinfo, int zip)
{
	char cbuf[PATH_MAX] = {0, };
	char cmdb[PATH_MAX] = {0, };

	if (cinfo == NULL)
		return -1;
	snprintf(cbuf, sizeof(cbuf), "%s/dump_systemstate_%s.log",
			cinfo->dumppath, cinfo->timestr);
	snprintf(cmdb, sizeof(cmdb), "/usr/bin/dump_systemstate -d -k -f %s",
			cbuf);
	g_spawn_command(cmdb);
	_SD("dump_systemstate (%s)", cmdb);

	if (chown(cbuf, -1, crash_gid) < 0)
		_SW("Failed to chown (%s)\n", cbuf);

	if (zip && (access(cbuf, F_OK) == 0)) {
		if (chdir(cinfo->dumppath) < 0)
			_W("Failed to chdir");
		snprintf(cmdb, sizeof(cmdb), "/usr/bin/gzip %s", cbuf);
		if (g_spawn_command(cmdb) < 0) {
			_W("Failed to %s", cmdb);
			return -1;
		}
	}
	return 0;
}

/* create and write report file */
static int write_report(struct crash_info *cinfo)
{
	if (cinfo == NULL)
		return -1;
	if (get_app_id(cinfo->exepath, cinfo->app_id, sizeof(cinfo->app_id)) < 0) {
		snprintf(cinfo->app_id, sizeof(cinfo->app_id),
				"%s", cinfo->processname);
		cinfo->isappid = 0;
	} else
		cinfo->isappid = 1;

	snprintf(cinfo->reportfile, sizeof(cinfo->reportfile),
			"%s/%s_%s.cs", cinfo->dumppath,
			cinfo->app_id, cinfo->timestr);

	_SI("crash report file is %s", cinfo->reportfile);
	if (create_report_file(cinfo) < 0) {
		_E("Failed to create report file");
		return -1;
	}
	/* create cs file */
	if (write_version_info(cinfo) < 0)
		_W("Failed to write version info");
	if (write_crash_base_info(cinfo) < 0)
		_W("Failed to write base info\n");
	if (write_crash_info(cinfo) < 0)
		_W("Failed to write crash info");
	if (write_package_info(cinfo) < 0)
		_W("Failed to write_package_info");
	if (dump_dlog(cinfo) < 0)
		_W("Failed to dump_dlog");
	if (write_dlogdump(cinfo) < 0)
		_W("Failed to write dlogdump");
	return 0;
}

static int publish_report(struct crash_info *cinfo)
{
	if (cinfo == NULL)
		return -1;
	snprintf(cinfo->reportdestfile, sizeof(cinfo->reportdestfile),
			"%s/%s_%s.cs", CRASH_REPORT_PATH,
			cinfo->app_id, cinfo->timestr);

	if (mkdir_path(CRASH_REPORT_PATH) < 0)
		return -1;

	if (copy_file(cinfo->reportfile, cinfo->reportdestfile) < 0) {
		_E("Failed to copy_file(%s)", cinfo->reportdestfile);
		return -1;
	}
	_I("Publish report file (%s)", cinfo->reportdestfile);
	if (chown(cinfo->reportdestfile, -1, crash_gid) < 0)
		_SW("Failed to chown (%s)", cinfo->reportdestfile);
	return 0;
}

static int check_working_list(Manager *manager, char *name)
{
	GList *list =
			g_list_find_custom(manager->working_list, name, (GCompareFunc)strcmp);
	if (!list)
		return 0;
	return 1;
}

int mtime_cmp(const void *_a, const void *_b) {
	const struct file_info *a = _a, *b = _b;

	if (a->mtime < b->mtime)
		return -1;
	if (a->mtime > b->mtime)
		return 1;
	return 0;
}

static int dump_filter(const struct dirent *de)
{
	if ((strcmp(de->d_name, ".") == 0) ||
		(strcmp(de->d_name, "..") == 0))
		return 0;
	if (de->d_type == DT_DIR)
		return 1;
	return 0;
}

static int report_filter(const struct dirent *de)
{
	if ((strncmp(de->d_name, ".", de->d_reclen) == 0) ||
		(strncmp(de->d_name, "..", de->d_reclen) == 0))
		return 0;
	if (de->d_type == DT_REG && strstr(de->d_name, CRASH_REPORT_EXTENSION))
		return 1;
	else
		return 0;
}

static int core_filter(const struct dirent *de)
{
	if ((strcmp(de->d_name, ".") == 0) ||
		(strcmp(de->d_name, "..") == 0))
		return 0;
	if (de->d_type == DT_REG && strstr(de->d_name, CORE_DUMP_EXTENSION))
		return 1;
	else
		return 0;
}

static int scandir_fileinfo(const char *path, struct file_info **list,
		int (*filter)(const struct dirent *))
{
	struct dirent **dir_list = NULL;
	struct file_info *temp_list = NULL;
	int i, scan_num, item_num;
	struct stat st;
	int fd = -1;

	fd = open(path,
				O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
	if (fd < 0)
		return -1;

	item_num = 0;
	scan_num = scandir(path, &dir_list, filter, NULL);
	if (scan_num <= 0)
		goto close_exit;
	temp_list = (struct file_info *)calloc(scan_num, sizeof(struct file_info));
	if (!temp_list) {
		_E("Failed to calloc");
		goto free_dir_list_exit;
	}
	for (i = 0; i < scan_num; i++) {
		if (fstatat(fd, dir_list[i]->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
			_E("Failed to fstatat");
			continue;
		}
		if (asprintf(&(temp_list[item_num].name), "%s/%s", path, dir_list[i]->d_name) < 0) {
			_E("Failed to asprintf");
			continue;
		}
		if (dir_list[i]->d_type == DT_DIR) {
			temp_list[item_num].isdir = 1;
			temp_list[item_num].size = get_directory_usage(temp_list[item_num].name);
		} else {
			temp_list[item_num].isdir = 0;
			temp_list[item_num].size = st.st_size;
		}
		temp_list[item_num].mtime = st.st_mtime;
		temp_list[item_num].state = INIT;
		_D("[%d] name: %s(%s), size: %d kb", item_num, temp_list[item_num].name, temp_list[item_num].isdir?"DIR":"FILE", temp_list[item_num].size/1024);
		item_num++;
	}
	if (item_num <= 0) {
		free(temp_list);
		goto free_dir_list_exit;
	}
	if (item_num != scan_num)
		temp_list = (struct file_info *)realloc(temp_list, item_num * sizeof(struct file_info));

	if (!temp_list) {
		item_num = 0;
		goto free_dir_list_exit;
	}

	qsort(temp_list, item_num, sizeof(struct file_info), mtime_cmp);

	*list = temp_list;
free_dir_list_exit:
	for (i = 0; i < scan_num; i++)
		free(dir_list[i]);
	free(dir_list);
close_exit:
	close(fd);
	return item_num;
}

static void clean_core(Manager *manager)
{
	int i, scan_num, core_num;
	size_t usage = 0;
	struct file_info *core_list = NULL;
	time_t cur_time;

	cur_time = time(NULL);
	scan_num = scandir_fileinfo(CRASH_COREDUMP_PATH, &core_list, &core_filter);
	if (scan_num <= 0)
		return;
	core_num = scan_num;
	/* remove when file is old */
	for (i = 0; i < scan_num; i++) {
		if (core_list[i].state == INIT) {
			   if (core_list[i].mtime > 0 &&
					(core_list[i].mtime) +
					(CORE_RETENTION_TIME) <
					(cur_time)) {
			if (unlink(core_list[i].name) < 0) {
				_E("Failed to unlink %s", core_list[i].name);
				continue;
			}
			core_list[i].state = DELETED;
			core_num--;
			_W("Missing core file reached the maximum core retention time 2days, so unlink (%s)",
						core_list[i].name);
			   } else {
				usage += core_list[i].size;
			}
		}
	}
	/* remove when reach the max number of core file */
	if (0 <= core_num && manager->conf.max_crash_dump < core_num) {
		for (i = 0; i < scan_num; i++) {
			if (core_list[i].state == INIT) {
				if (unlink(core_list[i].name) < 0) {
					_E("Failed to unlink %s", core_list[i].name);
					continue;
				}
				_W("Missing core file reached the maximum number of dump %d/%d byte, so unlink (%s)",
							core_num, manager->conf.max_crash_dump,
										core_list[i].name);
				core_list[i].state = DELETED;
				usage -= core_list[i].size;
				if (core_num-- <= 0 || core_num <= manager->conf.max_crash_dump)
					break;
			}
		}
	}
	for (i = 0; i < scan_num; i++)
		free(core_list[i].name);
	free(core_list);
}

static void clean_report(Manager *manager)
{
	int i, scan_num, report_num;
	size_t usage = 0;
	struct file_info *report_list = NULL;
	time_t cur_time;

	cur_time = time(NULL);
	scan_num = scandir_fileinfo(CRASH_REPORT_PATH, &report_list, &report_filter);
	if (scan_num <= 0)
		return;
	report_num = scan_num;
	/* remove when file is old */
	for (i = 0; i < scan_num; i++) {
		if (report_list[i].state == INIT) {
			   if (report_list[i].mtime > 0 &&
					(report_list[i].mtime) +
					(manager->conf.max_retention_sec) <
					(cur_time)) {
			if (unlink(report_list[i].name) < 0) {
				_E("Failed to unlink %s", report_list[i].name);
				continue;
			}
			report_list[i].state = DELETED;
			report_num--;
			_W("Reached the maximum retention time %d, so unlink (%s)",
						manager->conf.max_retention_sec,
						report_list[i].name);
			   } else {
				usage += report_list[i].size;
			}
		}
	}
	/* remove when reach the max number of report file */
	if (0 < report_num && manager->conf.max_crash_report < report_num) {
		for (i = 0; i < scan_num; i++) {
			if (report_list[i].state == INIT) {
				if (unlink(report_list[i].name) < 0) {
					_E("Failed to unlink %s", report_list[i].name);
					continue;
				}
				_W("Reached the maximum number of report %d/%d, so unlink (%s)",
							report_num, manager->conf.max_crash_report,
										report_list[i].name);
				report_list[i].state = DELETED;
				usage -= report_list[i].size;
				if (report_num-- <= 0 || report_num <= manager->conf.max_crash_report)
					break;
			}
		}
	}
	for (i = 0; i < scan_num; i++)
		free(report_list[i].name);
	free(report_list);
}

static void clean_dump(Manager *manager)
{
	int i, scan_num, dump_num;
	size_t usage = 0;
	struct file_info *dump_list = NULL;
	time_t cur_time;

	cur_time = time(NULL);
	scan_num = scandir_fileinfo(CRASH_DUMP_PATH, &dump_list, &dump_filter);
	if (scan_num <= 0)
		return;
	dump_num = scan_num;
	/* remove dumps when file is old */
	for (i = 0; i < scan_num; i++) {
		if (dump_list[i].state == INIT) {
			   if (dump_list[i].mtime > 0 &&
					(dump_list[i].mtime) +
					(manager->conf.max_retention_sec) <
					(cur_time)) {
			if (check_working_list(manager, dump_list[i].name)) {
				_D("found in workinglist %s", dump_list[i].name);
				continue;
			}
			if (dump_list[i].isdir) {
				if (remove_dir(dump_list[i].name, 1) < 0) {
					_E("Failed to remove_dir %s", dump_list[i].name);
					continue;
				}
			} else {
				if (unlink(dump_list[i].name) < 0) {
					_E("Failed to unlink %s", dump_list[i].name);
					continue;
				}
			}
			dump_list[i].state = DELETED;
			dump_num--;
			_W("Reached the maximum retention time %d, so unlink (%s)",
						manager->conf.max_retention_sec,
						dump_list[i].name);
			   } else {
				usage += dump_list[i].size;
			}
		}
	}
	/* remove dumps when reach the max number of dump file */
	if (manager->conf.max_crash_dump &&
			0 < dump_num && manager->conf.max_crash_dump < dump_num) {
		for (i = 0; i < scan_num; i++) {
			if (dump_list[i].state == INIT) {
				if (check_working_list(manager, dump_list[i].name)) {
					_D("found in workinglist %s", dump_list[i].name);
					continue;
				}
				if (dump_list[i].isdir) {
					if (remove_dir(dump_list[i].name, 1) < 0) {
						_E("Failed to remove_dir %s", dump_list[i].name);
						continue;
					}
				} else {
					if (unlink(dump_list[i].name) < 0) {
						_E("Failed to unlink %s", dump_list[i].name);
						continue;
					}
				}
				_W("Reached the maximum number of dump %d/%d, so unlink (%s)",
							dump_num, manager->conf.max_crash_dump,
							dump_list[i].name);
				dump_list[i].state = DELETED;
				usage -= dump_list[i].size;
				if (dump_num-- <= 0 || dump_num <= manager->conf.max_crash_dump)
					break;
			}
		}
	}
	/* remove dumps when reach the max system use size */
	if (manager->conf.system_max_use &&
			0 < dump_num && manager->conf.system_max_use < usage/1024) {
		for (i = 0; i < scan_num; i++) {
			if (dump_list[i].state == INIT) {
				if (check_working_list(manager, dump_list[i].name)) {
					_D("found in workinglist %s", dump_list[i].name);
					continue;
				}
				if (dump_list[i].isdir) {
					if (remove_dir(dump_list[i].name, 1) < 0) {
						_E("Failed to remove_dir %s", dump_list[i].name);
						continue;
					}
				} else {
					if (unlink(dump_list[i].name) < 0) {
						_E("Failed to unlink %s", dump_list[i].name);
						continue;
					}
				}
				_W("Reached the maximum disk usage %d/%d kb, so unlink (%s)",
							usage/1024, manager->conf.system_max_use,
							dump_list[i].name);
				dump_list[i].state = DELETED;
				usage -= dump_list[i].size;
				if (dump_num-- <= 0 || (usage/1024) <= manager->conf.system_max_use)
					break;
			}
		}
	}
	/* remove when reach the upper bound of disk space keep free size */
	if (manager->conf.system_keep_free &&
			check_disk_available(CRASH_CHECK_DISK_PATH, manager->conf.system_keep_free) < 0) {
		_W("disk is not available!, so set the maximum number of dump to 1");
		manager->conf.max_crash_dump = 1;
	}

	for (i = 0; i < scan_num; i++)
		free(dump_list[i].name);
	free(dump_list);
}

static int clean_work(Manager *manager)
{
	clean_report(manager);
	clean_dump(manager);
	if (manager->debug_mode) {
		clean_core(manager);
	} else  {
		remove_dir(CRASH_COREDUMP_PATH, 0);
	}
	return 0;
}

static void worker_job(gpointer data, gpointer user_data)
{
	int ret;
	Manager *manager;
	struct work_data *work;
	struct crash_info *cinfo;

	work = (struct work_data *)data;
	if (!work || !work->msg || !work->manager) {
		_E("Error! Invalid arguments");
		return;
	}

	_SI("Work start!(%s)", work->msg);
	manager = work->manager;
	cinfo = (struct crash_info *)malloc(sizeof(struct crash_info));
	if (!cinfo) {
		_E("Failed to malloc crash info");
		return;
	}
	if (parse_crash_info(work->msg, cinfo) < 0) {
		_E("Failed to parse crash info");
		goto exit_free;
	}

	LOGW("%s", cinfo->crashid);

	make_dump_dir(cinfo);

	g_mutex_lock(&manager->working_mutex);
	manager->working_list =  g_list_append(manager->working_list, cinfo->dumppath);
	g_mutex_unlock(&manager->working_mutex);

	if (dump_system_state(cinfo, manager->conf.allow_zip) < 0)
		_W("Failed to dump_system_state");

	write_report(cinfo);

	if (manager->conf.allow_popup) {
		ret = launch_crash_popup(manager, cinfo);
		if (ret < 0)
			_E("Failed to launch popup");
	}

	if (gather_coredump(cinfo, manager->conf.allow_zip) < 0) {
		_W("Failed to gather_coredump");
	}

	publish_report(cinfo);

	broadcast_crash(manager->conn, cinfo->processname, cinfo->exepath);

	if (unlink(cinfo->infofile) < 0)
		_W("Failed to unlink (%s)", cinfo->infofile);

	clean_dump(manager);

	g_mutex_lock(&manager->working_mutex);
	manager->working_list =	g_list_remove(manager->working_list, cinfo->dumppath);
	g_mutex_unlock(&manager->working_mutex);
	_I("Work done!(%s)", cinfo->crashid);
	 manager_add_timeout(work->manager, work->manager->conf.run_timeout_sec);
exit_free:
	free(cinfo);
	worker_close_work(work);
}

void worker_push_work(struct work_data *work)
{
	if (!work)
		return;
	g_thread_pool_push(work->manager->work_pool, (void *)work, NULL);
}

void worker_close_work(struct work_data *work)
{
	close(work->fd);
	if (work->msg)
		g_free(work->msg);
	free(work);
}

int worker_init(Manager *manager)
{
	struct passwd *pwd;
	GError *error;

	error = NULL;
	pwd = getpwnam(CRASH_USERNAME);
	if (pwd)
		crash_gid = pwd->pw_gid;
	else
		crash_gid = CRASH_GID;

	check_debugmode(manager);

	manager->work_pool = g_thread_pool_new(worker_job, NULL, manager->conf.max_concurrent_job, TRUE, &error);
	if (error) {
		_E("Error %s", error->message);
		g_error_free(error);
		return -1;
	}
	return 0;
}

void worker_exit(Manager *manager)
{
	clean_work(manager);
	g_thread_pool_stop_unused_threads();
	g_usleep(G_USEC_PER_SEC);
	g_thread_pool_free(manager->work_pool, FALSE, TRUE);
}
