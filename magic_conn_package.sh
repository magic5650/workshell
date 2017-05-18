#!/bin/bash
#set -x
#set -e
[ -z "$process" ] && process="$1"
[ -z "$process" ] && exit 1
process=$(echo ${process:0:13})


#下载jq,解析json
function wgetjq(){
	if [ ! -f "/usr/bin/jq" ];then
		sudo wget -O /tmp/jq -q http://bigdragon.yy.com/dragon/jq-linux64
		sudo chmod +x /tmp/jq
		sudo cp /tmp/jq /usr/bin/
	fi
}

#获取包信息
function GetPackageInfo()
{
	local package="$1";local version="$2"
	ipport=$(echo $ipport|sed 's/\[/\\\[/g'|sed 's/\]/\\\]/g')
	url="http://yydeploy1.sysop.duowan.com/webservice/package/getOwner.do?pkg=${package}&ver=${version}"
	curl_url=$(curl -s -m 5 --retry 1 "$url")
	success=$(echo "$curl_url"|awk -F ":" '{print $NF}'|sed 's!}!!')
	if [ "$success" = "true" ];then
		nickname=$(echo "$curl_url"|awk -F ","  '{print $4}' |cut -d ":" -f2|sed 's!"!!g')
	else
		nickname=""
	fi
	echo "$nickname"
}

#执行任务，并获取返回的任务ID @params IP params
function GetTaskIdValue()
{
	#注意url参数中是否有+、空格、=、%、&、#等特殊符号
	local IP="$1"
	local params="$2"
	#要执行的脚本ID
	local shellId="93006"
	local URL="http://ido.sysop.duowan.com/intf/exeShellIntf.jsp"
	local queryData="pass=c5d2fe07e5460ed18d96379d420b8c38&dwName=dw_fanweirui&params=${params}&shellId=${shellId}&ips=${IP}&taskName=${IP}"
	local getjson=$(curl -s -m 6 --retry 1 "${URL}?${queryData}" 2>/dev/null);
	local getsuccess=$(echo "$getjson"|jq .success)
	if [ "$getsuccess" = "true" ];then
		taskid=$(echo "$getjson"|jq .taskId)
		echo "$taskid"
	fi
}

#根据任务ID，获取返回结果，并返回成功的结果记录至$ipresult,失败的结果记录到$failedip
function GetTaskResult()
{
	local ID="$1"
	local url="http://ido.sysop.duowan.com/intf/getShellResultsIntf.jsp?pass=c5d2fe07e5460ed18d96379d420b8c38&dwName=dw_yaokangjun&taskId=${ID}"
	local getjson=$(curl -s -m 6 --retry 1 "$url" 2>/dev/null)
	if [[ -n "$getjson" ]];then
		getsuccess=$(echo "$getjson"|jq .success)
		if [[ "$getsuccess" == "true" ]];then
			getip=$(echo "$getjson"|jq .objects[0].ip|sed 's!"!!g')
			getfinish=$(echo "$getjson"|jq .finished)
			if [[ $getfinish == "true" ]];then
				getcode=$(echo "$getjson"|jq .objects[0].code)
				if [[ $getcode == "200" ]];then
					getresult=$(echo "$getjson"|jq .objects[0].result|sed 's!^\"!!'|sed 's!\"$!!')
					if [[ ! $getresult =~ "no process connect" ]];then
						echo "${getip} ${getresult}" >> "$ipresult"
					else
						echo "$getip $ID noconnect">> "$failedip"
					fi
				else
					echo "$getip" "$ID" "no200code" >> "$failedip"
				fi
			else
				echo "$getip" "$ID" "nofinish" >> "$nofiniship"
			fi
		else
			getmsg=$(echo "$getjson"|jq .msg|sed 's!"!!g')
			taskinfo=$(awk '$2=="'$ID'" {print $0}' $ipporttask)
			echo "${taskinfo} ${getmsg}" >> "$failedip"
		fi
	else
		taskinfo=$(sed -n "/$ID$/p" "$ipporttask")
		echo "${taskinfo} noreturn" >> "$failedip"
	fi
}

#执行任务并获取结果主函数
function main() {
	[ "$showip" == "yes" ] && isshowip="yes" || isshowip="no"

	timex1=$(date +%s)
	kernel=$(uname -r|cut -d "-" -f1)
	if [[ $kernel > 3.2.0 ]] || [[ $kernel = 3.2.0 ]];then
		listenports=$(ss -lntp|awk '{print $NF,$(NF-2)}'|grep -E "$process"|grep -v "127.0.0.1"|awk -F ":" '{print $3}'|sort -n)
		ss -4np -o state established|grep -E "$process"|awk '!a[$4]++{print $4,$3}'|awk '!a[$2]++{print $0}' > "$connfile"
		echo "使用ss查询"
	else
		listenports=$(ss -lntp|awk '{print $NF,$(NF-2)}'|grep -E "$process"|awk -F ":" '{print $3}'|sort -n)
		netstat -antp|grep -E "$process"|grep "ESTABLISHED"|awk '!a[$5]++{print $5,$4}'|awk '!a[$2]++{print $0}' > "$connfile"
		echo "使用netstat查询"
	fi
	match=$(echo "($listenports)");match=$(echo $match|sed 's/ /|/g')
	grep -E -v "${match}$" "$connfile"|awk '{print $1}' > "$connect"
	ipList=$(awk -F ":" '!a[$1]++{print $1}' "$connect"|grep -v "127.0.0.1")

	timex2=$(date +%s)
	#发送任务
	for IP in $ipList
	do
	{
		ports=$(awk -F ":" '$1=="'$IP'"{print $2}' "$connect")
		args=$(echo $ports|sed 's/ /a/g')
		params="\{\"ports\":\"$args\"\}"
		id=$(GetTaskIdValue "$IP" "$params")
		[ -n "$id"  ] && echo "$IP $id" >> "$ipporttask"
	}&
	done
	wait

	taskids=($(cat "$ipporttask"|awk '{print $2}'))
	timex3=$(date +%s)
	if [ "${#taskids[@]}" -eq 0 ];then
		echo "未找到相关进程,未执行任何任务."
		echo "[\"\",\"\",\"\",\"未找到相关进程\"]" >> "$packageinfo"
		timex4=$(date +%s)
	else
		#获取任务结果
		for (( i=1; i<=4; i=i+1 ))
		do
			sleep $(( 5 - $i ))
			if [ ${#taskids[@]} -ge 1 ];then
				for id in ${taskids[*]}
				do
				{
					GetTaskResult "$id" 2>/dev/null
				}&
				done
				wait
			fi
			nofinishs=$(grep -Ec "nofinish" "$nofiniship")
			if [ "$nofinishs" -le 2 ];then
				break
			fi
			taskids=($(grep -E "nofinish" "$nofiniship"|awk '{print $2}'))
			[ "$i" -lt 4 ] && cat /dev/null > "$nofiniship"
		done
		echo -e "$(awk '{$1="";print $0}' "$ipresult")"|tr " " "\n"|sort|uniq|sed '/^$/d' >> "$packages"

		timex4=$(date +%s)
		#循环并行调用获取包信息结果接口
		for line in $(cat "$packages")
		do
		{
			pkg=$(echo $line|awk -F "*" '{print $1}')
			version=$(echo $line|awk -F "*" '{print $2}')
			if [ "$pkg" == "java" ];then
				bissName=$(echo "$version"|sed 's!____! !'|awk '{print $1}')
				projName=$(echo "$version"|sed 's!____! !'|awk '{print $2}')
				if [ "$isshowip" == "yes" ];then
					iplist=$(grep -E "${pkg}.${version} " "$ipresult"|awk '{print $1}'|sed 's!$!</br>!g'|sed '$s!</br>!!')
					iplist=$(echo $iplist|sed 's/ //g')
					tempvalue="[\"$bissName\",\"$projName\","",\"$iplist\"],"
				else
					tempvalue="[\"$bissName\",\"$projName\","",""],"
				fi
				echo "$tempvalue" >> "$packageinfo"
			else
				name=$(GetPackageInfo "$pkg" "$version")
				if [ ! "X$name" == "X" ];then
					if [ "$isshowip" == "yes" ];then
						iplist=$(grep -E "${pkg}.${version} " "$ipresult"|awk '{print $1}'|sed 's!$!</br>!g'|sed '$s!</br>!!')
						iplist=$(echo $iplist|sed 's/ //g')
						tempvalue="[\"$pkg\",\"$version\",\"$name\",\"$iplist\"],"
					else
						tempvalue="[\"$pkg\",\"$version\",\"$name\",""],"
					fi
					echo "$tempvalue" >> "$packageinfo"
				fi
			fi
		}&
		done
		wait
	fi
	timex5=$(date +%s)
	echo "step 1 time is $(($timex2-$timex1))"
	echo "step 2 time is $(($timex3-$timex2))"
	echo "step 3 time is $(($timex4-$timex3))"
	echo "step 4 time is $(($timex5-$timex4))"
}

####执行####
time1=$(date +%s)
wgetjq
[ ! -f "/usr/bin/jq" ] && echo "command jq no found" && exit 1

connfile=$(mktemp);connect=$(mktemp)
ipresult=$(mktemp);failedip=$(mktemp)
packages=$(mktemp);packageinfo=$(mktemp)
nofiniship=$(mktemp);ipporttask=$(mktemp)
#传递参数时,用的是json,json的{}、""、等在shell中属于特殊字符,注意用反斜杠转义

main 1>&2

values=$(cat "$packageinfo"|sed '/unknow/d'|sort -t ',' -k 3 -k 1)
values=$(echo $values|sed 's! !!g'|sed 's!,$!!')
#输出至错误流信息
function stderr(){
	echo "####未完成的任务####"
	cat "$nofiniship"
	echo "####失败的任务####"
	cat "$failedip"
	echo "####查无结果的包####"
	cat "$packageinfo"|sed -n '/unknow/p'
	echo "####################"
	count=$(wc -l "$ipporttask"|awk '{print $1}')
	echo "任务发布数量: $count"
	count=$(wc -l "$ipresult"|awk '{print $1}')
	echo "任务结果数量: $count"
	count=$(wc -l "$nofiniship"|awk '{print $1}')
	echo "任务未完成数量: $count"
	count=$(wc -l "$failedip"|awk '{print $1}')
	echo "任务失败数量: $count"
}
stderr 1>&2

rm -f "$connfile";rm -f "$connect"
rm -f "$ipresult";rm -f "$failedip"
rm -f "$packages";rm -f "$packageinfo"
rm -f "$nofiniship";rm -f "$ipporttask"

time2=$(date +%s)
executetime=$(($time2-$time1))
echo "脚本执行时间为 ${executetime}s" 1>&2
###打印结果json
echo -e "{
	\"success\":1,
	\"header\":[\"进程名(包名或潜龙业务名)\",\"版本(或潜龙项目名)\",\"包维护人\",\"IP地址列表\"],
	\"templateType\":1,
	\"values\":[${values}],
	\"desc\":\"success\"
}"