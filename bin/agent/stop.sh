#!/bin/sh
RUN_NAME="icnm-agent-release.jar"
export LANG="en_US.UTF-8"
PRG=$0
APPDIRFILE=`dirname "$PRG"`
echo $APPDIRFILE/$RUN_NAME
PID=`ps -ef|grep $RUN_NAME|grep -v grep|awk '{printf $2}'`
echo $PID
if [ ! -n "$PID" ];
then
   echo "icnm-agent程序未启动"
else
   echo "已杀掉进程"
   echo $PID
   kill -9 $PID
fi
