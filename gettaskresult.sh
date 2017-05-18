#!/bin/bash
#调用工具系统工具并获取结果的示例脚本
#set -x
set -e

#执行任务，并获取返回的任务ID @params IP params
function GetTaskIdValue()
{
	#注意url参数中是否有+、空格、=、%、&、#等特殊符号
	local IP="$1"
	local params="$2"
	#要执行的脚本ID
	local shellId="89009"
	URL="http://ido.sysop.duowan.com/intf/exeShellIntf.jsp"
	queryData="pass=c5d2fe07e5460ed18d96379d420b8c38&dwName=dw_fanweirui&params=${params}&shellId=${shellId}&ips=${IP}&taskName=${IP}"
	#curldata=$(curl -X GET -s -m 6 --retry 1 --data-urlencode "$queryData" "$URL" 2>/dev/null);
	curldata=$(curl -s -m 6 --retry 1 "${URL}?${queryData}" 2>/dev/null);
	get_taskid=$(echo "$curldata"|awk -F ","  '{print $2}' |cut -d ":" -f2)
	echo "$get_taskid"
}

#根据任务ID，获取返回结果，并返回成功的结果记录至$resultfile,失败的结果记录到$failedip
function GetTaskResult()
{
	ID=$1
	local url="http://ido.sysop.duowan.com/intf/getShellResultsIntf.jsp?pass=c5d2fe07e5460ed18d96379d420b8c38&dwName=dw_yaokangjun&taskId=${ID}"
	local cur_status=$(curl -s -m 6 --retry 1 "$url" 2>/dev/null)
	if [[ -n "$cur_status" ]];then
		getsuccess=$(echo ${cur_status}|awk -F  "," '{print $1}'|cut -d ":" -f2)
		getip=$(echo ${cur_status}|awk -F ","  '{print $(NF-1)}'|cut -d ":" -f2|awk -F "\"" '{print $2}')
		if [[ $getsuccess = "true" ]];then
			getfinish=$(echo ${cur_status}|awk -F  "," '{print $2}' |cut -d ":" -f2)
			if [[ $getfinish = "true" ]];then
				getcode=$(echo ${cur_status}|awk -F ","  '{print $3}'|cut -d ":" -f3)
				if [[ $getcode = "200" ]];then
					getresult=$(echo ${cur_status}|awk -F ","  '{print $5}'|cut -d ":" -f2|awk -F "\"" '{print $2}')
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
		sleep 30
		getresult
		nofinishs=$(grep -E "nofinish" "$failedip"|wc -l)
		if [ "$nofinishs" -eq 0  ];then
			break
		else
			cat /dev/null > "$resultfile";cat /dev/null > "$failedip"
		fi
	done
}

resultfile=$(mktemp);failedip=$(mktemp)
#传递参数时,用的是json,json的{}、""、等在shell中属于特殊字符,注意用反斜杠转义
params="\{\"ipport\":\"101.226.20.88:3660\"\}"
taskids=()
iplist="106.38.200.176 106.38.200.148 106.120.184.116 101.226.23.104"

#执行任务并获取结果
main

cat "$resultfile" && rm -f "$resultfile"
cat "$failedip" && rm -f "$failedip"