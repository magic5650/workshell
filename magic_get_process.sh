#!/bin/bash
#set -x
#set -e
[ -z "$ipport" ] && ipport="$1"
[ -z "$ipport" ] && echo "" && exit 0

function sspids(){
	#使用指定dport+dst参数查询监听端口，当dport+dst个数大于7时会查询失败，必须分割成几次查询
	iplist=$(echo "$ipport"|cut -d ":" -f1|sed 's!(!!g'|sed 's!)!!g'|sed 's!|! !g')
	ipargs=$(echo "$iplist"|sed 's! ! or dst !g'|sed 's!^!dst !')
	ports=$(echo "$ipport"|cut -d ":" -f2|sed 's!(!!g'|sed 's!)!!g'|sed 's!|! !g')
	portcount=$(echo "$ports"|awk '{print NF}')
	Xcount=$(( $portcount / 4 ))
	maxcount=$(( $Xcount + 1 ))
	for (( i = 1; i <= $maxcount; i++ )); do
		if [ ! "X$ports" = "X" ];then
			port14=$(echo $ports|awk '{for(i=1;i<=4;i++){print $i}}'|sed '/^$/d')
			portargs=$(echo $port14|sed "s/ / or dport eq :/g"|sed "s/^/dport eq :/")
			pidargs=$(ss -n4p -o state established \( "$ipargs" \) \( "$portargs" \)|awk '{print $NF}'|awk -F "," '!a[$1]++{print $2}'|sed '/^$/d')
			[ "$i" -eq 1 ] && pids="$pidargs" || pids="${pids} ${pidargs}"
			ports=$(echo $ports|awk '{for(i=5;i<=NF;i++){print $i}}')
		fi
	done
	echo -e "search pids used by ss func sspids2."
}

function sspids2(){
	#使用指定dport+dst参数查询监听端口，当dport+dst个数大于7时会查询失败，必须分割成几次查询
	iplist=$(echo "$ipport"|cut -d ":" -f1|sed 's!(!!g'|sed 's!)!!g'|sed 's!|! !g')
	ipargs=$(echo "$iplist"|sed 's! ! or dst !g'|sed 's!^!dst !')
	ports=$(echo "$ipport"|cut -d ":" -f2)
	pids=$(ss -n4p -o state established \( "$ipargs" \)|grep -E ":${ports} "|awk '{print $NF}'|awk -F "," '!a[$1]++{print $2}'|sed '/^$/d')
	echo -e "search pids used by ss func sspids2."
}

function getprocess(){
	for pid in $pids
	do
		if [ "$pid" -gt 0 ] 2>/dev/null ;then
			LPACK=""
			PACK_F=`sudo readlink -ef /proc/${pid}/exe |awk -F'/' 'BEGIN{OFS="/"}{print $1,$2,$3,$4"/admin/pkg.pkgName"}' `
			if [[ -s $PACK_F ]] && [[ $PACK_F != "" ]];then
				LPACK=`cat $PACK_F `
			fi
			#
			LVER=""
			VER_F=`sudo readlink -ef /proc/${pid}/exe |awk -F'/' 'BEGIN{OFS="/"}{print $1,$2,$3,$4"/admin/pkg.verName"}' `
			if [[ -s $VER_F ]] && [[ $VER_F != "" ]];then
				LVER=`cat $VER_F `
			fi
			if [[ $LPACK != "" ]] && [[ $LVER != "" ]];then
				proc="${LPACK}*${LVER}"
				if [[ $LPACK == "java" ]];then
					bizName_projName=$(ps -p "$pid" --no-headers -opid,cmd|grep -E -o "bizName.projName=.{3,50} "|cut -d "=" -f2)
					[ "X${bizName_projName}" == "X" ] && proc="${LPACK}*unknow" || proc="${LPACK}*${bizName_projName}"
					process="${proc}\n${process}"
				else
					process="${proc}\n${process}"
				fi
			else
				name=$(ps -p "$pid" --no-headers -opid,cmd|awk '{print $2}'|sed 's!\./!!'|awk -F "." '{print $1}')
				packagedir=$(ls /data/services|grep "${name}-")
				if [[ -n "$packagedir" ]];then
					for dir in $packagedir
					do
						LPACK=$(cat "/data/services/${dir}/admin/pkg.pkgName")
						LVER=$(cat "/data/services/${dir}/admin/pkg.verName")
						proc="${LPACK}*${LVER}"
						process="${proc}\n${process}"
						break
					done
				else
					name=$(ps -p "$pid" --no-headers -opid,cmd|awk '{print $2}'|sed 's!\./!!')
					proc="${name}*unknow"
					process="${proc}\n${process}"
				fi
			fi
		else
			process="${process}"
		fi
	done
}

process=""
pids=""

time1=$(date +%s)
kernel=$(uname -r|cut -d "-" -f1)
if [[ $kernel > 3.2.0 ]] || [[ $kernel = 3.2.0 ]];then
	sspids2 1>&2
else
	sspids 1>&2
fi
getprocess 1>&2
time2=$(date +%s)
executetime=$(($time2-$time1))
echo "脚本执行时间为 ${executetime}s" 1>&2
if [ "x$process" = "x" ];then
	echo "no process connect"
else
	processes=$(echo -e "$process"|sort|uniq|sed '/^$/d')
	echo $processes
fi