#!/bin/bash
#set -x
#set -e
[ -z "$ports" ] && ports="$1"
[ -z "$ports" ] && echo "" && exit 0

function sspids(){
	#使用指定sport参数查询监听端口，当sport个数大于7时会查询失败，必须分割成几次查询
	portcount=$(echo "$ports"|awk -F "a" '{print NF}')
	X7count=$(expr $portcount / 7)
	maxcount=$(( $X7count + 1 ))
	ports=$(echo "$ports"|sed 's/a/ /g')
	for (( i = 1; i <= $maxcount; i++ )); do
		if [ ! "X$ports" = "X" ];then
			port17=$(echo $ports|awk '{for(i=1;i<=7;i++){print $i}}'|sed '/^$/d')
			portargs=$(echo $port17|sed "s/ / or sport eq :/g"|sed "s/^/sport eq :/")
			pidargs=$(ss -lntp \( "$portargs" \)|grep -v "127.0.0.1"|awk '{print $NF}'|awk -F "," '!a[$1]++{print $2}'|sed '/^$/d')
			[ "$i" -eq 1 ] && pids="$pidargs" || pids="${pids} ${pidargs}"
			ports=$(echo $ports|awk '{for(i=8;i<=NF;i++){print $i}}')
		fi
	done
	echo -e "search pids used by ss. pids is \n$pids"
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

pids="";process=""
sspids 1>&2
getprocess 1>&2

if [ "x$process" = "x" ];then
	echo "no process connect"
else
	processes=$(echo -e "$process"|sort|uniq|sed '/^$/d')
	echo $processes
fi