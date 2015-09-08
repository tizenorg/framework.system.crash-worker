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


#ifndef __LAUNCH_H__
#define __LAUNCH_H__

#define LAUNCH_NICE          0x0002

int launch_if_noexist(const char *execpath, const char *arg, ...);
int launch_evenif_exist(const char *execpath, const char *arg, ...);
int launch_after_kill_if_exist(const char *execpath, const char *arg, ...);
int launch_app_cmd(const char *cmdline);

#endif /* __LAUNCH_H__ */
