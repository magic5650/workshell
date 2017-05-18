#!/bin/bash

# file="/home/fanweirui/test.txt"
file="/usr/local/virus/iptables/iptables_office.add"
day=$(date +"%Y.%m.%d")
addday="##$day"
rule="iptables -j ACCEPT -I INPUT -p all  -s 58.248.229.128/26"
if [ -s "$file" ];then
	sed -i '$ a\'"$addday"'' "$file"
	sed -i '$ a\'"$rule"'' "$file"
	tail -4 "$file"
else
	echo "文件${file}不存在或为空"
	exit 0
fi