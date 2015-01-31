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



#ifndef __CRASH_LOG_H__
#define __CRASH_LOG_H__

#ifndef LOG_TAG
#define LOG_TAG "CRASH_MANAGER"
#endif
#include <dlog.h>

#define _D(fmt, arg...) SLOGD(fmt, ##arg)
#define _I(fmt, arg...) SLOGI(fmt, ##arg)
#define _W(fmt, arg...) SLOGW(fmt, ##arg)
#define _E(fmt, arg...) SLOGE(fmt, ##arg)
#define _SD(fmt, arg...) SECURE_SLOGD(fmt, ##arg)
#define _SI(fmt, arg...) SECURE_SLOGI(fmt, ##arg)
#define _SW(fmt, arg...) SECURE_SLOGW(fmt, ##arg)
#define _SE(fmt, arg...) SECURE_SLOGE(fmt, ##arg)

#endif
/* __CRASH_LOG_H__ */
