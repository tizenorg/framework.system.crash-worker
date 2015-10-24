#!/bin/sh

/bin/mkdir -p /tmp/crash_info
ret=$?
if [ "$ret" -ne 0 ]
then
	echo "Failed to create directory /tmp/crash_info($ret)"
	exit "$ret"
fi

chmod 777 /tmp/crash_info
ret=$?
if [ "$ret" -ne 0 ]
then
	echo "Failed to change permission to 777($ret)"
	exit "$ret"
fi

chown system:system /tmp/crash_info
ret=$?
if [ "$ret" -ne 0 ]
then
	echo "Failed to change owner to system($ret)"
	exit "$ret"
fi
