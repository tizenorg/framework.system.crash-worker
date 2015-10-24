CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(crash-manager C)
SET(CRASH_NAME crash-manager)
SET(VERSION 0.1.0)
SET(CRASH_INCLUDEDIR src/crash-manager)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src)

SET(CRASH_SRCS
	core.c
	crash-dbus.c
	worker.c
	manager.c
	${CMAKE_SOURCE_DIR}/src/shared/util.c
	${CMAKE_SOURCE_DIR}/src/shared/config-parser.c
	${CMAKE_SOURCE_DIR}/src/shared/launch.c
)

INCLUDE(FindPkgConfig)
pkg_check_modules(crash-manager_pkgs REQUIRED
		glib-2.0
		gio-2.0
		libsystemd-daemon
		libsystemd-journal
		vconf
		dlog
		pkgmgr-info
		capi-system-info
)

FOREACH(flag ${crash-manager_pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -fno-omit-frame-pointer -finstrument-functions")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIE")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed -pie")
MESSAGE("FLAGS: ${CMAKE_C_FLAGS}")

IF("$ENV{CFLAGS}" MATCHES "-DMICRO_DD")
	OPTION(USE_MICRO_DD "Use Micro DD" ON)
ENDIF()
IF("$ENV{CFLAGS}" MATCHES "-DTIZEN_ENGINEER_MODE")
	OPTION(USE_DEBUG_CONF "Use DEBUG CONF" ON)
ENDIF()
IF("$ENV{CFLAGS}" MATCHES "-DTIZEN_DEBUG_ENABLE")
	OPTION(USE_DEBUG_CONF "Use DEBUG CONF" ON)
ENDIF()

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")

ADD_EXECUTABLE(${PROJECT_NAME} ${CRASH_SRCS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${crash-manager_pkgs_LDFLAGS})

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/org.tizen.system.crash.service DESTINATION /usr/share/dbus-1/system-services)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/crash-manager.socket DESTINATION /usr/lib/systemd/system)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/crash-manager.service DESTINATION /usr/lib/systemd/system)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/crash-env.service DESTINATION /usr/lib/systemd/system)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/crash_env.sh DESTINATION /usr/bin)

IF(USE_MICRO_DD)
	IF(USE_DEBUG_CONF)
		INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/crash-manager-micro-debug.conf.in DESTINATION /etc/crash RENAME crash-manager.conf)
	ELSE()
		INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/crash-manager-micro.conf.in DESTINATION /etc/crash RENAME crash-manager.conf)
	ENDIF(USE_DEBUG_CONF)
ELSE()
	IF(USE_DEBUG_CONF)
		INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/crash-manager-debug.conf.in DESTINATION /etc/crash RENAME crash-manager.conf)
	ELSE()
		INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/crash-manager.conf.in DESTINATION /etc/crash RENAME crash-manager.conf)
	ENDIF(USE_DEBUG_CONF)
ENDIF(USE_MICRO_DD)
