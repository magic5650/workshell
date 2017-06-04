#!/bin/bash
#set -x
#set -e
queue="server_info"
server_info_file="/home/dspeak/yyms/hostinfo"
if [ -s "$server_info_file" ];then
	server_json=$(cat "$server_info_file")
else
	server_json="{\"responsibleAdmin_dw\": \"业务运维\"}"
fi

curl -m 3 "http://183.136.136.18:1218/?name=${queue}&opt=reset&auth=yysec123456" > /dev/null 2>&1
curl -m 3 --data-urlencode "data=${server_json}"  "http://183.136.136.18:1218/?name=${queue}&opt=put&auth=yysec123456" > /dev/null 2>&1

# curl -m 3 http://183.136.136.18:1218/?charset=utf-8&name=${queue}&opt=get&auth=yysec123456

echo "$server_json"