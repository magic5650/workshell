#!/bin/bash
#set -x
set -e
if [ $# -eq 1 ]
then
	nowdate=$1
	last_date=$(date -d"yesterday $1" +%Y-%m-%d)
else
	nowdate=$(date +%Y-%m-%d)
	last_date=$(date --date="-1 day" +%Y-%m-%d)
fi

date +"%Y-%m-%d %H:%M:%S %Z"
datafile=$(mktemp);failedip=$(mktemp)
start_total=0;start_times=0;grab_total=0;grab_times=0
phone_grab_total=0;phone_grab_times=0

function GetTaskIdValue()
{
	local IP="$1"
	local nowdate="$2"
	url="http://ido.sysop.duowan.com/intf/exeShellIntf.jsp?pass=c5d2fe07e5460ed18d96379d420b8c38&dwName=dw_fanweirui&params=\{%22nowdate%22:%22$nowdate%22\}&shellId=90001&ips=${IP}&taskName=${IP}"
	curl_url=$(curl -s -m 5 --retry 1 "$url" 2>/dev/null)
	get_taskid=$(echo "$curl_url"|awk -F ","  '{print $2}' |cut -d ":" -f2)
	echo "$get_taskid"
}

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
					echo "${getip} ${getresult}" >> "$datafile"
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

function getresult(){
	if [ ${#taskids[@]} -gt 1 ];then
		for id in ${taskids[*]}
		do
		{
			GetTaskResult "$id"
		}&
		done
		wait
	fi
}

taskids=()
cd /home/liaosimin
for ip in $(./dumps2server appGrabBench|cut -d',' -f3|cut -d'=' -f2|sort -u)
do
	id=$(GetTaskIdValue ${ip} ${nowdate}) 
	taskids=("${taskids[*]}" "$id")
done

function main() {
	[ ${#taskids[@]} -eq 0 ] && echo "未dumps任何appGrabBench实例" && exit 1
	for (( i=0; i<5; i=i+1 ))
	do
		sleep 60
		getresult
		nofinishs=$(grep -E "[nofinish]" "$failedip"|wc -l)
		if [ "$nofinishs" -eq 0  ];then
			break
		else
			cat /dev/null > "$datafile"
			cat /dev/null > "$failedip"
		fi
	done

	failcount=$(grep -E "[failed|noreturn|nofinish]" "$failedip"|wc -l)
	datafail=$(grep "failed" "$datafile"|wc -l)
	if [ "$failcount" -eq 0 ];then
		if [ "$datafail" -eq 0 ];then
			start_total=$(awk 'BEGIN{a=0}{a=a+$3}END{print a}' "$datafile")
			start_times=$(awk 'BEGIN{a=0}{a=a+$4}END{print a}' "$datafile")
			grab_total=$(awk 'BEGIN{a=0}{a=a+$5}END{print a}' "$datafile")
			grab_times=$(awk 'BEGIN{a=0}{a=a+$6}END{print a}' "$datafile")
			phone_grab_total=$(awk 'BEGIN{a=0}{a=a+$7}END{print a}' "$datafile")
			phone_grab_times=$(awk 'BEGIN{a=0}{a=a+$8}END{print a}' "$datafile")
		else
			echo "last_date="$last_date
			echo "某些IP返回结果为failed"
			grep "failed" "$datafile"
			echo ""
		fi
	else
		echo "last_date="$last_date
		echo "获取某些IP的执行结果失败或超时"
		grep -E "[failed|noreturn|nofinish]" "$failedip"
		echo ""
	fi

	if [ -n "$start_total" ];then
		echo "last_date="$last_date
		echo "start_total="$start_total
		echo "start_times="$start_times
		echo "grab_total="$grab_total
		echo "grab_times="$grab_times
		echo "phone_grab_total="$phone_grab_total
		echo "phone_grab_times="$phone_grab_times
		echo ""
		/usr/bin/mysql -h101.226.20.108 -P6305 -uyyMusicAct -pOM49.2WJ8k act --default-character-set=utf8 -e"insert ignore into grabBench_statistics (create_date,start_total,start_times,grab_total,grab_times,mob_grab_total,mob_grab_times) values ('$last_date',$start_total,$start_times,$grab_total,$grab_times,$phone_grab_total,$phone_grab_times);"
	fi
}

main

rm -f "$datafile" "$failedip"