####### crash-worker #############
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(crash-worker C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")

# Sub modules
ADD_SUBDIRECTORY(src/crashctl)
ADD_SUBDIRECTORY(src/crash-manager)
ADD_SUBDIRECTORY(src/all_log_dump)
ADD_SUBDIRECTORY(src/dump_systemstate)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE DESTINATION /usr/share/license RENAME crash-worker)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/packaging/${PROJECT_NAME}.efl DESTINATION /etc/smack/accesses.d)
############## END ##############

