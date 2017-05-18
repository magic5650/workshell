#!/bin/bash
# Written by wuhaiting
# Date 2013-05-04

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
export LANG=C
isolate_lock="/usr/local/virus/iptables/.iptables_isolate_backup"

source /usr/local/i386/public_repos/initial_system/snmp/ext/tools_system/commonFunction.sh
IPADDR=$(/sbin/ifconfig|grep Bcast|grep -v -E "inet addr:192.168|inet addr:172.16|inet addr:10.0"|head -n 1|awk '{print $2}'|awk -F : '{print $2}')
EXIT_CODE="50"
tmp_file=`mktemp`
if [ $? -ne 0 ];then
	echo -e "Result\t$IPADDR\t根分区只读或没有空间"
	msg="根分区只读或没有空间"
	printResult "0" "$msg"
	exit 51
fi

apply_user=`awk -F '=' '{if($1 ~ /APPLY_USER/){print $2}}' para.config |sort -u|sed -e "s/dw_//g" -e "s/;/ /g"`
echo -e $apply_user > $tmp_file
apply_user=`cat $tmp_file| tr -s "\n" " "`
rm $tmp_file
apply_root=`awk -F '=' '{if($1 ~ /APPLY_ROOT/){print $2}}' para.config`
apply_time=`awk -F '=' '{if($1 ~ /APPLY_TIME/){print $2}}' para.config`
cur_user=`awk -F '=' '{if($1 ~ /cur_user/){print $2}}' para.config | sed -e "s/dw_//g"`

[ "$apply_root" == "" ] && apply_root=0
[ "$apply_time" == "" ] && apply_time=86400

apply_user_test=`echo $apply_user | tr -d ' '`
if [ -z "$apply_user_test" ];then
	msg="失败：申请用户为空"
	printResult "0" "$msg"
	exit 52
fi

#grep -qw "$cur_user" /usr/local/i386/public_repos/initial_system/user/sysop_admin.log
#if [ $? -ne 0 ];then
#	echo -e "Result\t$IPADDR\t非运维人员禁止添加权限"
#	msg="非运维人员禁止添加权限"
#	printResult "0" "$msg"
#	exit 0
#fi

#if [ -d /usr/local/i386/pure_db_repos/ ];then
#	if [ "$cur_user" != "zhongjianhui" ] && \
#		[ "$cur_user" != "lanzhaobao" ] && \
#		[ "$cur_user" != "zhaokeke" ] && \
#		[ "$cur_user" != "liuxingzhong" ] && \
#		[ "$cur_user" != "wuhaiting" ];then
#		echo -e "Result\t$IPADDR\t重要数据库服务器,不允许开通,如有需要请联系DBA"
#		msg="重要数据库服务器，不允许开通,如有需要请联系DBA"
#		printResult "0" "$msg"
#		exit 53
#	fi
#fi

#if grep -wq "$IPADDR" /usr/local/i386/public_repos/initial_system/user/add_ip_user_exclude_ip.log;then
#	error_msg=$(grep -m1 "$IPADDR" /usr/local/i386/public_repos/initial_system/user/add_ip_user_exclude_ip.log|awk '{print $2}')
#	msg="${error_msg},特殊服务器请联系吴海庭"
#	printResult "0" "$msg"
#	exit 0
#fi

script_count=$(ps aux |grep monitor_user_privileges.sh | grep -vE 'grep|ssh'|wc -l)
if [ $script_count -gt 0 ];then
	loop=10
	until [ $loop -eq 0 ];
	do
		((loop-=1))
		sleep 1
		script_count=$(ps aux |grep monitor_user_privileges.sh | grep -vE 'grep|ssh'|wc -l)
		[ $script_count -eq 0 ] && break;
	done
fi

DEAD_TIME=`expr $(date +%s) + $apply_time`
UTC_TIME=`date -d "1970-01-01 $DEAD_TIME sec UTC" "+%Y-%m-%d %H:%M:%S"`
DATE=$(date "+%Y-%m-%d %H:%M:%S")
echo -e "$DATE\t[TOOL_AGENT $cur_user] add $apply_user" >> /var/log/sysop_manager/user_privilege_change.log
/bin/bash /usr/local/i386/*/auto/monitor_user_privileges.sh adduser $apply_user > /dev/null

for which_user in $apply_user;
do
	id $which_user > /dev/null 2>&1
	if [ $? -eq 0 ];then

		if [ -f $isolate_lock ];then
			msg="服务器处于隔离中,禁止登陆,疑问联系系统管理员"
			echo -e "Result\t$IPADDR\t${msg}"
		else
			if [ -f /var/log/sysop_manager/start_user_privilege ];then
				msg="增加用户: $which_user 有效期至$UTC_TIME"
				echo -e "Result\t$IPADDR\t${msg}"
			else
				msg="增加永久用户: $which_user"
				echo -e "Result\t$IPADDR\t${msg}"
			fi
		fi

		grep -w "dw_${which_user}" /var/log/sysop_manager/user_privilege.log > /dev/null 2>&1
		if [ $? -ne 0 ];then
			sed -i "/$which_user:deluser/d" /var/log/sysop_manager/add_user_tmp.log
			echo "$which_user:deluser:$DEAD_TIME" >> /var/log/sysop_manager/add_user_tmp.log
		fi
		EXIT_CODE="0"
	else
		if grep -q "$which_user" /usr/local/i386/public_repos/initial_system/user/normal_user.log ; then
			msg="添加用户失败,联系管理与"
			echo -e "Result\t$IPADDR\t${msg}"
		else
			msg="${which_user} 公钥还没有入库，请到权限系统申请密钥"
			echo -e "Result\t$IPADDR\t${msg}"
		fi
	fi
done

if [ "$apply_root" == "1" ];then
	for which_user in $apply_user;
	do
		id $which_user > /dev/null 2>&1
		if [ $? -eq 0 ];then
			grep -qw "$which_user" /usr/local/i386/public_repos/initial_system/user/sysop_admin.log
			if [ $? -ne 0 ];then
				sed -i "/$which_user:delsudo/d" /var/log/sysop_manager/add_user_tmp.log
				echo "$which_user:delsudo:$DEAD_TIME" >> /var/log/sysop_manager/add_user_tmp.log
				usermod -G $which_user,execute $which_user
			fi
		fi
	done
fi

#if [ -f /var/log/sysop_manager/start_user_privilege ];then
	#msg="服务器已启用新权限系统"
#else
	#msg="成功"
#fi

printResult "$EXIT_CODE" "$msg"
exit $EXIT_CODE

