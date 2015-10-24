#!/bin/sh

PARAM1=$1

mkdir_function()
{
	if [ ! -e $1 ]; then
	/bin/mkdir -p "$1"
	/bin/echo mkdir -p "$1"
	/bin/chown app:app -R "$1"
	/bin/echo chown app:app -R "$1"
	fi
}

if [ -z "$PARAM1" ]; then
/bin/echo "dump_log.sh <directory full path>"
exit
else
LOG_DST_DIR=$PARAM1
if [ -e "$PARAM1" ]; then
mkdir_function "${LOG_DST_DIR}"
fi
fi

#--------------------------------------
#    last kmsg - /proc/last_kmsg
#--------------------------------------
LAST_KMSG=/proc/last_kmsg
LAST_KMSG_FILE=/opt/var/log/last_kmsg.log
if [ -r ${LAST_KMSG} ]; then
/bin/cat ${LAST_KMSG} > ${LAST_KMSG_FILE}
fi
#--------------------------------------
#    var logs - /opt/var/log
#--------------------------------------
VAR_LOG_DIR=${LOG_DST_DIR}/var_log
mkdir_function "${VAR_LOG_DIR}"
/bin/cp -fr /opt/var/log/* ${VAR_LOG_DIR}

#--------------------------------------
#    check size of var log - /opt/var/log
#--------------------------------------
use=$(/bin/df -h /opt | /bin/grep '^/' | /usr/bin/awk '{print $5}' | /usr/bin/awk -F '%' '{print $1}')
limit=90
if [ "$use" -gt "$limit" ] ; then
	/bin/rm -rf /opt/var/log/*
fi

MOD_LOG_DIR=${LOG_DST_DIR}/module_log
mkdir_function ${MOD_LOG_DIR}
#--------------------------------------
#   run the /opt/etc/dump.d/module.d/* dump scripts
#--------------------------------------
for i in /opt/etc/dump.d/module.d/*; do
	$i ${MOD_LOG_DIR}
done

#-------------------------------------
# ap log dump copy
#-------------------------------------
AP_LOG_DIR=${LOG_DST_DIR}/ap_log
mkdir_function ${AP_LOG_DIR}
/bin/cp -rf /tmp/crach_info/*.info ${AP_LOG_DIR}
/bin/cp -rf /opt/usr/share/crash/core/* ${AP_LOG_DIR}
/bin/cp -rf /opt/usr/share/crash/dump/* ${AP_LOG_DIR}
/bin/cp -rf /opt/usr/share/crash/report/* ${AP_LOG_DIR}

#-------------------------------------
#   dump log done
#-------------------------------------
# change owner so that dump can by read by PC via MTP
cd /opt/usr/media
/bin/chown app:app -R ${LOG_DST_DIR}

/bin/echo dump_log.sh done
