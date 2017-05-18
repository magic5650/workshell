#!/bin/bash
#调用工具系统工具并获取结果的示例脚本,使用jq解析json
#set -x
#set -e

#下载jq,解析json
function wgetjq(){
	if [ ! -f "/usr/bin/jq" ];then
		sudo wget -O /tmp/jq -q http://bigdragon.yy.com/dragon/jq-linux64
		sudo chmod +x /tmp/jq
		sudo cp /tmp/jq /usr/bin/
	fi
}
#执行任务，并获取返回的任务ID @params IP params
function GetTaskIdValue()
{
	#注意url参数中是否有+、空格、=、%、&、#等特殊符号
	local IP="$1"
	local params="$2"
	#要执行的脚本ID
	local shellId="89009"
	local URL="http://ido.sysop.duowan.com/intf/exeShellIntf.jsp"
	local queryData="pass=c5d2fe07e5460ed18d96379d420b8c38&dwName=dw_fanweirui&params=${params}&shellId=${shellId}&ips=${IP}&taskName=${IP}"
	local curldata=$(curl -s -m 6 --retry 1 "${URL}?${queryData}" 2>/dev/null);
	local getstatus=$(echo "$curldata"|jq .success)
	if [ "$getstatus" = "true" ];then
		taskid=$(echo "$curldata"|jq .taskId)
		echo "$taskid"
	fi
}
#根据任务ID，获取返回结果，并返回成功的结果记录至$resultfile,失败的结果记录到$failedip
function GetTaskResult()
{
	local ID=$1
	local url="http://ido.sysop.duowan.com/intf/getShellResultsIntf.jsp?pass=c5d2fe07e5460ed18d96379d420b8c38&dwName=dw_yaokangjun&taskId=${ID}"
	local getjson=$(curl -s -m 6 --retry 1 "$url" 2>/dev/null)
	if [[ -n "$getjson" ]];then
		getstatus=$(echo "$getjson"|jq .success)
		getip=$(echo "$getjson"|jq .objects[0].ip|sed 's!"!!g')
		getfinish=$(echo "$getjson"|jq .finished)
		getcode=$(echo "$getjson"|jq .objects[0].code)
		if [[ $getstatus = "true" ]];then
			if [[ $getfinish = "true" ]];then
				if [[ $getcode = "200" ]];then
					getresult=$(echo "$getjson"|jq .objects[0].result|sed 's!^\"!!'|sed 's!\"$!!')
					echo "${getip} ${getresult}" >> "$resultfile"
				fi
			else
				echo "$getip" "$ID" "nofinish" >> "$failedip"
			fi
		else
			echo "$getip" "$ID" "failed" >> "$failedip"
		fi
	else
		echo "$ID" "noreturn" >> "$failedip"
	fi
}
#根据taskids，并行执行GetTaskResult,获取任务结果
function getresult(){
	if [ ${#taskids[@]} -gt 1 ];then
		for id in ${taskids[*]}
		do
		{
			GetTaskResult "$id" 2>/dev/null
		}&
		done
		wait
	fi
}
#执行任务并获取结果主函数
function main() {
	#发送任务
	for IP in $iplist
	do
		id=$(GetTaskIdValue "$IP" "$params")
		[ -n "$id" ] && taskids=("${taskids[*]}" "$id")
	done

	[ "${#taskids[@]}" -eq 0 ] && echo "未执行任何任务" && exit 1

	#获取任务结果
	for (( i=0; i<5; i=i+1 ))
	do
		sleep 5
		getresult
		nofinishs=$(grep -E "nofinish" "$failedip"|wc -l)
		if [ "$nofinishs" -eq 0  ];then
			break
		else
			taskids=($(grep -E "nofinish" "$failedip"|awk '{print $1}'))
			cat /dev/null > "$failedip"
		fi
	done
}

wgetjq
[ ! -f "/usr/bin/jq" ] && echo "command jq no found" && exit 1

resultfile=$(mktemp);failedip=$(mktemp)
#传递参数时,用的是json,json的{}、""、等在shell中属于特殊字符,注意用反斜杠转义
params="\{\"ipport\":\"101.226.20.88:3660\"\}"
taskids=()
iplist="106.38.200.176 106.38.200.148 106.120.184.116 101.226.23.104"

main

cat "$resultfile" && rm -f "$resultfile"
cat "$failedip" && rm -f "$failedip"