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
#ifndef __DEF_UTIL_H__
#define __DEF_UTIL_H__

#define ARRAY_SIZE(name) (sizeof(name)/sizeof(name[0]))

#ifndef __CONSTRUCTOR__
#define __CONSTRUCTOR__ __attribute__ ((constructor))
#endif

int system_command(char *command);

int system_command_with_timeout(int timeout_seconds, char *command);

int fprintf_fd(int fd, const char *fmt, ...);

int write_fd(int fd, const void *buf, int len);

int copy_file(char *src, char *dst);

int cat_file(char *src, char *dst);

int move_file(char *src, char *dst);

int dump_file_write_fd(char *src, int dfd);

int run_command_write_fd(char *cmd, int dfd);

int make_dir(const char *path, mode_t mode, const char *grname);

int remove_dir(const char *path, int del_dir);

int get_exec_pid(const char *execpath);

int get_file_count(char *path);

int get_directory_usage(char *path);

int validate_env_name(char *name, int len);

int validate_file_name(char *name, int len);
/**
 * @}
 */
#endif
