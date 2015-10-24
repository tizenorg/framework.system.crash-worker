#!/bin/sh

PARAM1=$1

mkdir_function()
{
	if [ ! -e $1 ]; then
	/bin/mkdir -p "$1"
	/bin/echo mkdir -p "$1"
	/bin/chown app:app -R "$1"
	/bin/echo /bin/chown app:app -R "$1"
	fi
}

#--------------------------------------
#    Setup log dump path
#--------------------------------------
TIMESTAMP=`date +%Y%m%d%H%M%S`
LOG_DST_DIR_BASE=/opt/usr/media/SLP_debug
if [ "$PARAM1" = "dfms" ]; then
	LOG_DIR=factory_dumpstate${TIMESTAMP}
else
	LOG_DIR=log_dump_${TIMESTAMP}
fi
LOG_DST_DIR=${LOG_DST_DIR_BASE}/${LOG_DIR}
SCAN_IGNORE=${LOG_DST_DIR_BASE}/.scan_ignore

/bin/echo all_log_dump.sh start

#--------------------------------------
#	check disk available (/opt, /opt/usr)
#--------------------------------------
use=$(/bin/df -h /opt | /bin/grep '^/' | /usr/bin/awk '{print $5}' | /usr/bin/awk -F '%' '{print $1}')
limit=90
if [ "$use" -gt "$limit" ] ; then
	available=$(/bin/df /opt | /bin/grep '^/' | /usr/bin/awk '{print $4}')
	/bin/echo "/opt available size(${available})"
	/usr/bin/du -ah /opt --exclude=/opt/usr > /tmp/opt_diskusage.log
fi

use=$(/bin/df -h /opt/usr | /bin/grep '^/' | /usr/bin/awk '{print $5}' | /usr/bin/awk -F '%' '{print $1}')
limit=80
if [ "$use" -gt "$limit" ] ; then
	available=$(/bin/df /opt/usr | /bin/grep '^/' | /usr/bin/awk '{print $4}')
	crash_size=$(/usr/bin/du -s /opt/usr/share/crash | /usr/bin/awk '{print $1}')
	var_size=$(/usr/bin/du -s /var/log | /usr/bin/awk '{print $1}')
	dump_size=$(($crash_size + $var_size + 100000))
	if [ "$dump_size" -gt "$available" ] ; then
		/bin/echo -e "/opt/usr available size($available) < dump size($dump_size)"
		/bin/echo -e /bin/rm -rf ${LOG_DST_DIR_BASE} for available disk space.
		/bin/rm -rf ${LOG_DST_DIR_BASE}
		available=$(/bin/df /opt/usr | /bin/grep '^/' | /usr/bin/awk '{print $4}')
		if [ "$dump_size" -gt "$available" ] ; then
			/bin/echo -e "/opt/usr available size($available) < dump size($dump_size)"
			/bin/echo -e "/opt/usr is not available for dump!"
			exit -1
		fi
	fi
fi

mkdir_function ${LOG_DST_DIR_BASE}
if [ ! -e ${SCAN_IGNORE} ]; then
    /bin/touch ${SCAN_IGNORE}
fi

/bin/chown app:app -R ${LOG_DST_DIR_BASE}

if [ "${PARAM1}" = "zip" ]; then
	LOG_ZIP_DIR=${LOG_DST_DIR_BASE}/zip
	mkdir_function ${LOG_ZIP_DIR}
else
	LOG_ZIP_DIR=${LOG_DST_DIR_BASE}
fi

if [ "${PARAM1}" = "hardkey" ]; then
	/usr/bin/devicectl led dumpmode on &
	# change uart path
	if [ "${HW_NAME}" = "U1SLP" ] || [ "${HW_NAME}" = "U1HD" ] || [ "${HW_NAME}" = "TRATS" ]; then
		/bin/echo AP > /sys/devices/platform/uart-select/path
	else
		/bin/echo AP > /sys/devices/virtual/sec/switch/uart_sel
	fi
	# change atd to console mode
	/usr/bin/pkill -SIGUSR1 atd-server
	# blink led to notify
fi

#--------------------------------------
#	display control dumpmode on
#--------------------------------------
/usr/bin/devicectl display dumpmode on &
mkdir_function ${LOG_DST_DIR}
/usr/bin/dump_systemstate -d -k -f ${LOG_DST_DIR}/dump_systemstate_${TIMESTAMP}.log 2>&1
/usr/bin/dump_log.sh ${LOG_DST_DIR} 2>&1
if [ -e /tmp/opt_diskusage.log ]; then
    /bin/cp -rf /tmp/opt_diskusage.log ${LOG_DST_DIR}/
fi

#-------------------------------------
# remove ap log dump
#-------------------------------------
/bin/rm -rf /tmp/crach_info/*.info
/bin/rm -rf /opt/usr/share/crash/core/*
/bin/rm -rf /opt/usr/share/crash/dump/*

#--------------------------------------
# log dump zip
#--------------------------------------
LOG_ZIP_DST_FILE_NAME=${LOG_ZIP_DIR}/${LOG_DIR}.tar.gz
/bin/tar zcf ${LOG_ZIP_DST_FILE_NAME} -C ${LOG_DST_DIR_BASE} ${LOG_DIR}
/bin/chown app:app ${LOG_ZIP_DST_FILE_NAME}
/bin/rm -rf ${LOG_DST_DIR}
/bin/echo tar zcf ${LOG_ZIP_DST_FILE_NAME} -C ${LOG_DST_DIR_BASE} ${LOG_DIR}
/bin/echo /bin/rm -rf ${LOG_DST_DIR}
/bin/sync
#--------------------------------------
#	display control dumpmode off
#--------------------------------------
/usr/bin/devicectl display dumpmode off &
if [ "${PARAM1}" = "hardkey" ]; then
	/usr/bin/devicectl led dumpmode off &
#--------------------------------------
# enable sdb
#--------------------------------------
	/usr/bin/direct_set_debug.sh --sdb-set
fi

/bin/echo all_log_dump.sh done
