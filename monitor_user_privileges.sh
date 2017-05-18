#!/bin/bash
#DATE:2013-02-13
#Written by wuhaiting.
#Readme: 根据本地缓存MD5 变化来触发更新服务器用户权限.
#Readme: 从管理机获取的数据对象有3项，分别为sysop_users(运维)、teche_users(开发人员)、recover(1/0)
#Readme: sysop_users 加入 execute 组，teche_users 为普通用户.
#Readme: recover=1 时，回收所有人员权限，包括sysop_users,但排除超级管理员。
#DATE: 2014-12-09
#Readme: 用户超过有效期不再直接删掉home目录，防止潜在业务风险。除非离职人员
#Readme: 检查用户是否存在不合理部署进程

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
export LANG=C
export LC_ALL=C

LOG_DIR=/var/log/sysop_manager
LOG_FILE=$LOG_DIR/user_privilege_change.log
ADD_USER_TMP=$LOG_DIR/add_user_tmp.log
SHORT_NAME=user_privileges
BASENAME=$SHORT_NAME
TMP_USER_LOG=$LOG_DIR/user_privilege.log
WGET_USER_LOG=$LOG_DIR/user_privilege.log.tmp
USER_LOG=/var/log/user_process.log
OP_USER_TYPE=$1
NOLOGIN=$(which nologin)
HOSTFILE="/home/dspeak/yyms/hostinfo.ini"

# stop run configure
if [ -f $LOG_DIR/stop_run_$SHORT_NAME ] || \
	[ -f $LOG_DIR/stop_run_$BASENAME ] || \
	[ -f $LOG_DIR/stop_run_all ];then
	exit 1
fi

ps aux > /dev/.run_procsses && dump_procsses="yes"

script_num=$(grep monitor_user_privileges.sh /dev/.run_procsses| grep -vcE 'grep|ssh')
if [ $script_num -gt 3 ];then
	INSERT_MYSQL "script already running, num:$script_num "
	exit 1
fi

function dump_proc() {
	[ -n "$dump_procsses" ] && cat /dev/.run_procsses || ps aux
}

# repository path
REPOS_NAME=comm_repos
COMM_DIR=/usr/local/i386/$REPOS_NAME
PUBLIC_DIR=/usr/local/i386/public_repos
# 备用管理机地址
function backup_api_manager () {
	API_ADDRESS=$(awk '{if($0 ~ /manager.repos.yy.duowan.com/){print $1}}' /etc/hosts)
	API_HOSTNAME=$(awk -F ',' '{if($0 ~ /'$API_ADDRESS'/){print $4}}' $COMM_DIR/initial_system/repos_server.log)
	RANDOM_CHOICE=$(($RANDOM % 6))
	RANDOM_CHOICE=$(($RANDOM_CHOICE + 1))
	API_ADDRESS_API2=$(grep -v "$API_HOSTNAME" $COMM_DIR/initial_system/repos_server.log| \
		sed -n "${RANDOM_CHOICE}p"|awk '{print $1}')
}

# check if partition readonly, Abort.
touch $ADD_USER_TMP || exit 1
[ ! -d /home/backup ] && mkdir /home/backup
DATE=$(date "+%Y-%m-%d %H:%M:%S")
DATE_STRI=$(date +%s)

if [[ "$REPOS_NAME" == "db_repos" ]] || [[ "$REPOS_NAME" == "pure_db_repos" ]];then
	KEEP_USER="yuwanfu|wuhaiting|user_00|dspeak|backup|zhongjianhui|yymz|hadoop|hiido|hiidoagent|zhgame|mysql|storm"
else
	KEEP_USER="yuwanfu|wuhaiting|user_00|dspeak|backup|builder|noc|yymz|hadoop|hiido|hiidoagent|zhgame|mysql|storm"
fi

grep -qw "^execute" /etc/group || groupadd execute
grep -qw "^execute" /etc/group- || groupadd execute

# wget_action [md5/user_info] [server_id] [output file]
function wget_action () {

	wget "http://$4:63217/query_privileges_data_api.php?info_type=$1&server_id=$2" \
		--http-user=manifold --http-password=dw_manifold --timeout=4 --tries=2 -q -O $3
}

function INSERT_MYSQL_SYSOP () {
	/bin/bash $COMM_DIR/auto/insert_message.sh "$BASENAME" "$1" &
}

function INSERT_MYSQL () {
	echo -e "$DATE\t$1" >> $LOG_FILE
}

function user_canlogin () {
	local cuser=$1

	r=$(awk -F ':' '{if($1 == "'$cuser'" && $NF !~ /nologin/){print "yes";exit}}' /etc/passwd)
	if [ "x${r}" == "xyes" ] && [ ! -f /home/${cuser}/.lockuser ];then
		return 0
	else
		return 1
	fi
}

function ALLOC_USER_ID () {
	ALLOC_USER=$1
	export USER_ID_TMPFILE="$LOG_DIR/user_privilege_tmp_uid.log"

	ALLOC_USER_IDS=$(grep -w "ALLOC_USER" $USER_ID_TMPFILE|awk '{print $2;exit}')

	if [ -z "$ALLOC_USER_IDS" ];then
		TMP_USER_ID=$(awk -F ':' '{if($3 >= 9000 && $3 <= 10000){print $3}}' /etc/passwd \
						|sort -n| tail -n1)
		[ -z "$TMP_USER_ID" ] && TMP_USER_ID=9000
		ALLOC_USER_IDS=$((TMP_USER_ID+1))

		if grep -qw "^${ALLOC_USER}" $USER_ID_TMPFILE;then
			sed -i "/^${ALLOWC_USER}/d" $USER_ID_TMPFILE
		fi

		echo "$ALLOC_USER $ALLOC_USER_IDS" >> $USER_ID_TMPFILE
		echo "id:$ALLOC_USER_IDS"
	else
		echo "id:$ALLOC_USER_IDS"
	fi
}

# 删除用户之前,检查是否有以该用户的进程在跑,或者在crontab,或白名单中
function del_user_check () {
	local USER_CHECK=$1
	[ ! -f $PUBLIC_DIR/initial_system/user/business_user.log ] && return 2
	grep -wq "$USER_CHECK" $PUBLIC_DIR/initial_system/user/business_user.log && return 2
	local USER_CHECK_ID=$(id -u $USER_CHECK)
	[ "x${USER_CHECK_ID}" = "x" ] && return 2
	USER_ONLINE=$(dump_proc|grep -E "^$USER_CHECK|^$USER_CHECK_ID" |grep -vcE "grep");

	etc_cron_line=$(grep -vE "^#|^$" /etc/crontab | \
		awk '{print $6}' | grep -cw "$USER_CHECK")
	var_cron_line=$(crontab -u $USER_CHECK -l 2>/dev/null|grep -vcE '^#|^$')
	if [ "$USER_ONLINE" -ne 0 ] || \
		[ "$etc_cron_line" -ne 0 ] || \
		[ "$var_cron_line" -ne 0 ];then
		unset USER_ONLINE etc_cron_line var_cron_line MSG
		return 2
	fi
	return 0
}

# 检查用户是部署进程是否符合规范
function check_user_deploy_illegal() {
	local USER_CHECK=$1
	[ ! -f $PUBLIC_DIR/initial_system/user/business_user.log ] && return 2
	grep -w "$USER_CHECK" $PUBLIC_DIR/initial_system/user/business_user.log && return 2
	local USER_CHECK_ID=$(id -u $USER_CHECK)
	[ "x${USER_CHECK_ID}" = "x" ] && return 2
	USER_ONLINE=$(dump_proc|grep -E "^$USER_CHECK|^$USER_CHECK_ID|home/${USER_CHECK}"| \
		grep -vciwE "ssh|ssh-agent|sshd:|-bash|-sh|tail -f|grep|head");
	[ "$USER_ONLINE" -ne 0 ] && MSG="process"

	etc_cron_line=$(grep -vE "^#|^$" /etc/crontab | \
		awk '{print $6}' | grep -cw "$USER_CHECK")
	var_cron_line=$(crontab -u $USER_CHECK -l 2>/dev/null|grep -vcE '^#|^$')
	if [ "$etc_cron_line" -ne 0 ] || [ "$var_cron_line" -ne 0 ];then
		MSG="$MSG crontab"
	fi
	if [ "$USER_ONLINE" -ne 0 ] || \
		[ "$etc_cron_line" -ne 0 ] || \
		[ "$var_cron_line" -ne 0 ];then
		INSERT_MYSQL_SYSOP "USER_DEPLOY_ILLEGAL: $USER_CHECK: $MSG"
		echo "$DATE  user_deploy_illegal ${USER_CHECK}: $MSG" >> $USER_LOG
		if [ "$USER_ONLINE" -ne 0 ];then
			echo " alive_process(cmd: ps aux|grep -E \"^${USER_CHECK}|^$USER_CHECK_ID|home/${USER_CHECK}\" )" >> $USER_LOG
			dump_proc | grep -E "^${USER_CHECK}|^$USER_CHECK_ID|home/${USER_CHECK}" | \
			grep -viwE "ssh|ssh-agent|sshd:|-bash|-sh|tail -f|grep|head" | \
			sed "s/^/   \\\--- /g" >> $USER_LOG
		fi
		if [ "$etc_cron_line" -ne 0 ];then
			echo " exist_crontab(file: /etc/crontab)" >> $USER_LOG
			grep -vE "^#|^$" /etc/crontab|grep -cw "$USER_CHECK" | \
			sed "s/^/   \\\--- /g" >> $USER_LOG
		fi
		if [ "$var_cron_line" -ne 0 ];then
			echo " exist_crontab(cmd: crontab -u $USER_CHECK -l)" >> $USER_LOG
			crontab -u $USER_CHECK -l 2>/dev/null| grep -vE '^#|^$' | \
			sed "s/^/   \\\--- /g" >> $USER_LOG
		fi
		echo >> $USER_LOG
		unset USER_ONLINE etc_cron_line var_cron_line MSG
		return 2
	fi
	return 0
}

# 锁定用户账号
function user_del_privilege () {
	id $1 > /dev/null 2>&1 && DEL_USER=$1 || return 1
	[ -d /usr/local/i386/pure_db_repos ] && [ "$DEL_USER" = "zhongjianhui" ] && return 0
	[ ! -d /usr/local/i386/pure_db_repos ] && [ "$DEL_USER" = "yuwanfu" ] && return 0
	del_user_check $DEL_USER
	if [ $? -eq 0 ];then
		lockuser="/home/${DEL_USER}/.lockuser"
		if [ ! -s $lockuser ];then
			# 禁止用户登录隔离7天
			chsh "$DEL_USER" -s "$NOLOGIN"
			chmod 777 /home/${DEL_USER}/.ssh 2>/dev/null
			echo "lockuser_time=$DATE_STRI" > $lockuser
			INSERT_MYSQL "lock $DEL_USER, and set nologin"
		else
			source $lockuser
			if [ "$((${DATE_STRI}-${lockuser_time}))" -ge "604800" ];then
				userdel -f $DEL_USER > /dev/null 2>&1
        		if [ "$?" -eq 0 ];then
            		[ -d /home/backup/$DEL_USER ] && \
            		mv -f /home/backup/$DEL_USER /home/backup/${DEL_USER}_${DATE_STRI}
            		mv -f /home/$DEL_USER/ /home/backup/$DEL_USER

            		# 防止有些用户组没有在group里面删掉
            		sed -i "/^${DEL_USER}:/d" /etc/group
            		sed -i "/^${DEL_USER}:/d" /etc/group-
            		sed -i "/^${DEL_USER}:/d" /etc/gshadow
            		sed -i "/^${DEL_USER}:/d" /etc/gshadow-
            		INSERT_MYSQL "delete $DEL_USER, and home directory move it backup"
            	fi
			fi
			unset lockuser_time
		fi
	fi
}

# 强制删除用户,不管是否存在于白名单或其他形式
function force_del_privilege () {
	id $1 > /dev/null 2>&1 && DEL_USER=$1 || return 1
	[ -d /usr/local/i386/pure_db_repos ] && [ "$DEL_USER" = "zhongjianhui" ] && return 0
	[ ! -d /usr/local/i386/pure_db_repos ] && [ "$DEL_USER" = "yuwanfu" ] && return 0
	userdel -f $DEL_USER > /dev/null 2>&1
	if [ "$?" -eq 0 ];then
		[[ -d /home/backup/$DEL_USER ]] && mv -f /home/backup/$DEL_USER /home/backup/${DEL_USER}_${DATE_STRI} \
					&& INSERT_MYSQL "when $DEL_USER delete, /home/backup/$DEL_USER have exist, delete it."
		mv -f /home/$DEL_USER/ /home/backup/$DEL_USER

		# 防止有些用户组没有在group里面删掉
		sed -i "/^${DEL_USER}:/d" /etc/group
		sed -i "/^${DEL_USER}:/d" /etc/group-
		sed -i "/^${DEL_USER}:/d" /etc/gshadow
		sed -i "/^${DEL_USER}:/d" /etc/gshadow-
		INSERT_MYSQL "delete $DEL_USER, and home directory move it backup"
	fi
}

# 获取用户key
function get_user_pub_key () {
	[[ "$1" != "" ]] && GET_USER=$1

	wget "http://manager.repos.yy.duowan.com:63217/server_privileges_user_key.php?action=query&username=$GET_USER" \
		--http-user=manifold --http-password=dw_manifold --timeout=4 --tries=2 -q -O /tmp/get_key.${GET_USER}

	grep -qE "^ssh-dss|ssh-rsa|null" /tmp/get_key.${GET_USER}
	if [ "$?" -ne 0 ];then
		wget "http://$API_ADDRESS_API2:63217/server_privileges_user_key.php?action=query&username=$GET_USER" \
			--http-user=manifold --http-password=dw_manifold --timeout=4 --tries=2 -q -O /tmp/get_key.${GET_USER}
		if grep -qE "^ssh-dss|ssh-rsa|null" /tmp/get_key.${GET_USER} ; then
			GET_USER_KEY=`cat /tmp/get_key.${GET_USER}`
		else
			GET_USER_KEY=""
		fi
		rm -f /tmp/get_key.${GET_USER}
	else
		GET_USER_KEY=`cat /tmp/get_key.${GET_USER}`
		rm -f /tmp/get_key.${GET_USER}
	fi
}

# 用户不存在，增加用户账号
function user_add_privilege () {
	[[ $# -ge 1 ]] && ADD_USER=$1 || return 1;
	[ "$2" !=  "" ] && ADD_GROUP=$2 || ADD_GROUP=$1
	lockuser="/home/${ADD_USER}/.lockuser"

	# 获取用户key
	unset GET_USER_KEY
	get_user_pub_key $ADD_USER
	echo $GET_USER_KEY | grep -qE "^ssh-dss|ssh-rsa|null" || return 2;

	if [ ! -d /home/$ADD_USER/ ];then
		# 检查用户home目录之前是否已经存在于backup
		[[ -d /home/backup/$ADD_USER/ ]] && mv /home/backup/$ADD_USER/ /home/.
	fi

	user_id=$(grep -w $ADD_USER $PUBLIC_DIR/initial_system/user/normal_user.log| \
		awk '{print $2}'| head -n1)
	[ "x${user_id}" == "x" ] && return 1
	groupadd -g $user_id $ADD_USER > /dev/null 2>&1
	groupadd_status=$?
	if [ "$groupadd_status" == "4" ];then
		TMP_UER_ID=$(ALLOC_USER_ID $ADD_USER | awk -F ':' '{print $2;exit}')
		if [ "$TMP_UER_ID" -ge 9000 ] && [ "$TMP_UER_ID" -le 10000 ];then
			user_id=$TMP_UER_ID
			groupadd -g $user_id $ADD_USER > /dev/null 2>&1
		else
			return 1
		fi
	elif [ "$groupadd_status" == "9" ];then
		sed -i "/^$ADD_USER/d" /etc/group
        sed -i "/^$ADD_USER/d" /etc/group-
		groupadd -g $user_id $ADD_USER > /dev/null 2>&1
	fi

	[ -f $lockuser ] && rm -f $lockuser
	useradd -s /bin/bash -m -g $user_id -u $user_id $ADD_USER > /dev/null 2>&1
	useradd_status=$?
	if [ "$useradd_status" -eq 0 ];then
		[[ -d /home/$ADD_USER/.ssh ]] && rm -rf /home/$ADD_USER/.ssh
		mkdir /home/$ADD_USER/.ssh && chmod 700 /home/$ADD_USER/.ssh/
		echo $GET_USER_KEY > /home/$ADD_USER/.ssh/authorized_keys && chmod 600 /home/$ADD_USER/.ssh/authorized_keys
		chown -R $ADD_USER:$ADD_USER /home/$ADD_USER/
		usermod -G $ADD_GROUP $ADD_USER
		INSERT_MYSQL "add user $ADD_USER, group $ADD_GROUP."
		return 0
	elif [ "$useradd_status" == "4" ];then
		# bug
		return 1
	elif [ "$useradd_status" == "9" ];then
        sed -i "/$ADD_USER/d" /etc/group
        sed -i "/$ADD_USER/d" /etc/group-
	fi
}

# 用户存在，更换key
function user_init_home () {
	[[ $# -ge 1 ]] && ADD_USER=$1 || return 1;
	[ "$2" !=  "" ] && ADD_GROUP=$2 || ADD_GROUP=$1
	lockuser="/home/${ADD_USER}/.lockuser"

	# 获取用户key
	unset GET_USER_KEY
	get_user_pub_key $ADD_USER
	echo $GET_USER_KEY | grep -qE "^ssh-dss|ssh-rsa|null" || return 2;

	[ ! -d /home/$ADD_USER/.ssh ] && mkdir -p /home/$ADD_USER/.ssh && chmod 700 /home/$ADD_USER/.ssh/
	echo $GET_USER_KEY > /home/$ADD_USER/.ssh/authorized_keys && chmod 600 /home/$ADD_USER/.ssh/authorized_keys
	chown -R $ADD_USER:$ADD_USER /home/$ADD_USER/
	usermod -G $ADD_GROUP $ADD_USER
	chmod 755 /home/$ADD_USER
	chmod 700 /home/$ADD_USER/.ssh
	chsh $ADD_USER -s /bin/bash
	[ -f $lockuser ] && rm -f $lockuser
	INSERT_MYSQL "reinit user_key $ADD_USER, group $ADD_GROUP."
	[ $? -eq 0 ] && return 0
}

if [ "$OP_USER_TYPE" == "adduser" ] || [ "$OP_USER_TYPE" == "addusersudo" ];then
    backup_api_manager
	until [ -z "$2" ];do
		ADD_USER_LIST=$2
		grep -wq "$ADD_USER_LIST" $PUBLIC_DIR/initial_system/user/sysop_admin.log \
				&& USER_GROUP="${ADD_USER_LIST},execute" || USER_GROUP="${ADD_USER_LIST}"
		id $ADD_USER_LIST > /dev/null 2>&1
		if [ $? -ne 0 ];then
			user_add_privilege $ADD_USER_LIST $USER_GROUP
			add_status=$?
		else
			user_init_home $ADD_USER_LIST $USER_GROUP
			add_status=$?
		fi

		case $add_status in
		"1")
			echo -e "\033[31;40;1madd_user: $ADD_USER_LIST fail\033[0m";;
		"2")
			echo -e "\033[31;40;1madd_user: $ADD_USER_LIST user not found\033[0m";;
		*)
			if [ "$OP_USER_TYPE" == "addusersudo" ]; then
				if id $ADD_USER_LIST > /dev/null 2>&1; then
					usermod -G execute $ADD_USER_LIST
					sed -i "/${ADD_USER_LIST}:delsudo/d" $ADD_USER_TMP
					apply_time=`expr $(date +%s) + $(expr 30 \* 86400)`
					echo "$ADD_USER_LIST:delsudo:$apply_time" >> $ADD_USER_TMP
				fi
			fi
			echo -e "\033[32;40;1madd_user: $ADD_USER_LIST\033[0m";;
		esac

		unset ADD_USER_LIST USER_GROUP add_status
	shift
	done
	exit 0
elif [ "$OP_USER_TYPE" == "deluser" ];then
	until [ -z "$2" ];do
		DEL_USER=$2
		force_del_privilege $DEL_USER

		if ! id $DEL_USER > /dev/null 2>&1;then
			echo -e "\033[32;40;1mdel_user: $DEL_USER\033[0m"
		fi
	shift
	done
	exit 0
fi

# server_id 必须yyms先起来，否则/home/dspeak/yyms/hostinfo.ini为空
server_id=$(awk -F '=' '{if($1 ~ /server_id/){print $2}}' $HOSTFILE)
[ "x${server_id}" == "x" ] && exit 1

# 运营中：	1
# 库存：	2
# buff状态	3
# 已报修	4
# 已报废	5
# 迁移中	6
# 测试中	7
# 开发使用	8
# 需要排除状态为 测试中 和 开发使用中
server_status=$(awk -F '=' '{if($1 ~ /^status/){print $2}}' $HOSTFILE)
if [[ "$server_status" == "7" ]] || [[ "$server_status" == "8" ]];then
	SERVER_IS_TEST='yes'
fi

# 第三用户列表
ds_user=$(awk -F ':' '{if($1 ~ /ds_/){printf("%s ",$1)}}' /etc/passwd)

for ck in 'sysopResponsibleAdmin_dw' 'responsibleAdmin_dw';
do
	[ -f /etc/${ck} ] && continue
	m=$(grep -wE "${ck}" $HOSTFILE | awk -F '=' '{print $2}'|sed "s/dw_//g"| tr -s ',\n' ' ')
	machine_admin="${machine_admin} ${m}"
done

LOCATE_MD5=$(cat $LOG_DIR/user_privilege_md5)

# get remote server_id md5
wget_action md5 $server_id $LOG_DIR/user_privilege_md5 manager.repos.yy.duowan.com
REMOTE_MD5=$(cat $LOG_DIR/user_privilege_md5)
if [ "$REMOTE_MD5" == "" ] || [ "$REMOTE_MD5" == "null" ];then
	backup_api_manager
	wget_action md5 $server_id $LOG_DIR/user_privilege_md5 $API_ADDRESS_API2
	REMOTE_MD5=`cat $LOG_DIR/user_privilege_md5`
	if [ "$REMOTE_MD5" == "" ] || [ "$REMOTE_MD5" == "null" ];then
		INSERT_MYSQL "Get remote_MD5 fail, from $API_ADDRESS_API2"
		exit 1
	fi
fi

if [ "$LOCATE_MD5" == "$REMOTE_MD5" ];then
	TIME_MIN=$(($DATE_STRI/60%60))
	CHECK_TIME=$(($TIME_MIN % 5))
	[ "$TIME_MIN" -eq 0 ] && TIME_MIN=60
	DELTA_MIN=$(($TIME_MIN - $server_id % 60))
	[ "$DELTA_MIN" -ge 60 ] && DELTA_MIN=0
	[ "x${CHECK_TIME}" != "x0" ] && exit

	# check one time in every hour.
	if [ "$DELTA_MIN" -ge 0 ] && [ "$DELTA_MIN" -lt 10 ];then
		for ck_deploy_user in /home/*;do
			ck_user=${ck_deploy_user##*/}
			check_user_deploy_illegal "$ck_user"

			id $ck_user >/dev/null 2>&1 || continue
			if grep -wq "$ck_user" $PUBLIC_DIR/initial_system/user/dimission_user.log;then
				del_user_check "$ck_user" && \
				force_del_privilege "$ck_user" || \
				INSERT_MYSQL_SYSOP "dimission_user_delfail: $ck_user"
			fi
		done
	fi

	if [ -f $LOG_DIR/start_user_privilege ];then

		RECOVER=$(awk -F ':' '{if($1 ~ /^recover/){print $2}}' $TMP_USER_LOG)
		TECHE_USERS=$(awk -F ':' '{if($1 ~ /^teche_users/){print $2}}' $TMP_USER_LOG| \
			sed -e "s/dw_//g" -e "s/,/ /g")
		SYSOP_USERS=$(awk -F ':' '{if($1 ~ /^sysop_users/){print $2}}' $TMP_USER_LOG| \
			sed -e "s/dw_//g" -e "s/,/ /g")
		[ "x${TECHE_USERS}" == "x" ] && [ "x${SYSOP_USERS}" == "x" ] && exit 1

		if [ "x${SERVER_IS_TEST}" != "xyes" ];then
			# 检查账号是否超时需要回收
			for tmp_user_msg in $(grep -v '^#' $ADD_USER_TMP);
			do
				tmp_user="${tmp_user_msg%%:*}"
				tmp_user_op="${tmp_user_msg#*:}";tmp_user_op="${tmp_user_op%:*}"
				tmp_user_deadtime="${tmp_user_msg##*:}"
				if ! id $tmp_user > /dev/null 2>&1;then
					sed -i "/${tmp_user}:/d" $ADD_USER_TMP
					continue
				fi
				if [ $DATE_STRI -ge $tmp_user_deadtime ];then
					if [ "$tmp_user_op" == "deluser" ];then
						if echo "$SYSOP_USERS $TECHE_USERS $machine_admin"|grep -qw "$tmp_user";then
							del_record=yes
						else
							user_del_privilege $tmp_user
							user_canlogin $tmp_user || del_record=yes
						fi
					elif [ "$tmp_user_op" == "delsudo" ];then
						if echo "$SYSOP_USERS $machine_admin" | grep -qw "$tmp_user";then
							del_record="yes"
						else
							usermod -G $tmp_user $tmp_user && del_record=yes
							INSERT_MYSQL "delsudo $tmp_user."
						fi
					fi
					[ "$del_record" == "yes" ] && sed -i "/${tmp_user}:${tmp_user_op}/d" $ADD_USER_TMP
				fi
				[ "x${FILE_TMPUSER%%${tmp_user}}" == "x${FILE_TMPUSER}" ] && \
				FILE_TMPUSER="${FILE_TMPUSER} ${tmp_user}"
				unset del_record tmp_user tmp_user_op tmp_user_deadtime
			done

			# 检查是否有非法用户账号
			for which_user in `ls /home |grep -vwE "$KEEP_USER"`;do
				id $which_user >/dev/null 2>&1
				if [ "$?" -eq 0 ];then
					echo "${TECHE_USERS} ${SYSOP_USERS} ${machine_admin} ${FILE_TMPUSER} ${ds_user}"|grep -wq $which_user
					[ "$?" -ne 0 ] && user_del_privilege $which_user
				fi
			done
		fi

		#检查是否有合法用户添加不成功，或者被恶意删掉
		for which_user in $TECHE_USERS;
		do
			user_canlogin $which_user
			if [ $? -ne 0 ];then
				if id $which_user >/dev/null 2>&1;then
					user_init_home $which_user
				else
					user_add_privilege "$which_user" "${which_user}"
				fi
				echo "add user again, some user not found" > $LOG_DIR/user_privilege_md5
			fi
		done

		#检查是否有合法用户添加不成功，或者被恶意删掉
		for which_user in $SYSOP_USERS $machine_admin;
		do
			user_canlogin $which_user
			if [ $? -ne 0 ];then
				if id $which_user >/dev/null 2>&1;then
					user_init_home $which_user
				else
					user_add_privilege "$which_user" "${which_user},execute"
				fi
				echo "add user again, some user not found" > $LOG_DIR/user_privilege_md5
			fi

			#检测用户是否在execute组下
			id ${which_user} | grep -wq "execute" || usermod -G ${which_user},execute ${which_user}
		done

		#更新用户列表
		if ! grep -qE 'teche_users|sysop_users' $TMP_USER_LOG;then
			INSERT_MYSQL "empty user file list"
			echo "empty user file list" > $LOG_DIR/user_privilege_md5
		fi

	else
		for which_user in $machine_admin;
		do
			if ! id $which_user > /dev/null 2>&1;then
				grep -wq "$which_user" $PUBLIC_DIR/initial_system/user/normal_user.log || continue
				which_group="${which_user},execute"
				user_add_privilege "$which_user" "$which_group"
				INSERT_MYSQL "add user again, user:$which_user not found"
				echo "add user again, some user not found" > $LOG_DIR/user_privilege_md5
			fi
		done
	fi
	exit 0
else				# "$LOCATE_MD5" != "$REMOTE_MD5"
	# 两个MD5不一样，且不为空.
	wget_action user_info $server_id $WGET_USER_LOG manager.repos.yy.duowan.com
	if [ ! -s $WGET_USER_LOG ] || [ "$(cat $WGET_USER_LOG)" == "null" ];then
		[ "x${API_ADDRESS_API2}" = "x" ] && backup_api_manager
		wget_action user_info $server_id $WGET_USER_LOG $API_ADDRESS_API2
		if [ ! -s $WGET_USER_LOG ] || [ "$(cat $WGET_USER_LOG)" == "null" ];then
			INSERT_MYSQL "Get user_info null."
			exit 1
		fi
	fi

	if grep -qE "sysop_users|teche_users" $WGET_USER_LOG; then
		CUR_UPDATETIME=$(awk -F ':' '{if($1 ~ /^update_time/){print $2}}' $WGET_USER_LOG)
		OLD_UPDATETIME=$(awk -F ':' '{if($1 ~ /^update_time/){print $2}}' $TMP_USER_LOG)
		CUR_UPDATETIME="${CUR_UPDATETIME:-0}"
		OLD_UPDATETIME="${OLD_UPDATETIME:-0}"

		[ "$CUR_UPDATETIME" -ge "$OLD_UPDATETIME" ] && \
		cat $WGET_USER_LOG > $TMP_USER_LOG
	fi

	RECOVER=$(awk -F ':' '{if($1 ~ /^recover/){print $2}}' $TMP_USER_LOG)
	TECHE_USERS=$(awk -F ':' '{if($1 ~ /^teche_users/){print $2}}' $TMP_USER_LOG | \
		sed -e "s/dw_//g" -e "s/,/ /g")
	SYSOP_USERS=$(awk -F ':' '{if($1 ~ /^sysop_users/){print $2}}' $TMP_USER_LOG | \
		sed -e "s/dw_//g" -e "s/,/ /g")

	# 已经使用新的权限系统
	if [ "$RECOVER" == "1" ] && \
		[ -f $LOG_DIR/start_user_privilege ];then
		# 添加开发人员权限
		for which_user in $TECHE_USERS;do
			id $which_user > /dev/null 2>&1
			if [ "$?" -ne 0 ];then
				user_add_privilege "$which_user"
			else		# 转为普通用户权限
				if id $which_user | grep -Eq "execute|segroup";then
					echo "$SYSOP_USERS" | grep -wq "$which_user" && continue
					grep -qw "$which_user:delsudo" $LOG_DIR/add_user_tmp.log
					if [ $? -ne 0 ]; then
						INSERT_MYSQL "delsudo $which_user, tech_user illegal have root."
						usermod -G $which_user $which_user
					fi
				fi
				user_canlogin $which_user || user_init_home $which_user
			fi
		done

		# 添加运维人员权限
		for which_user in $SYSOP_USERS;do
			id $which_user > /dev/null 2>&1
			if [ "$?" -ne 0 ];then
				user_add_privilege "$which_user" "${which_user},execute"
			else		# 检查存在用户是否带sudo
				id $which_user | grep -Eq "execute|segroup"
				[ $? -ne 0 ] && usermod -G $which_user,execute $which_user
				user_canlogin $which_user || user_init_home $which_user
			fi
		done

	# 刚从旧权限系统切换到新的，初始化所有人员
	elif [ "$RECOVER" == "1" ] && [ ! -f $LOG_DIR/start_user_privilege ];then
		if [ "x${SERVER_IS_TEST}" != "xyes" ];then
			for which_user in `ls /home |grep -vwE "$KEEP_USER"`;do
				echo "${TECHE_USERS} ${SYSOP_USERS} ${machine_admin} ${ds_user}" | \
					grep -wq $which_user && continue
				if id $which_user > /dev/null 2>&1;then
					del_user_check $which_user	&& force_del_privilege $which_user
				fi
			done
		fi

		for which_user in $TECHE_USERS;do
			id $which_user > /dev/null 2>&1
			if [ "$?" -ne 0 ];then
				user_add_privilege "$which_user"
			else		# 转为普通用户权限
				if id $which_user | grep -Eq "execute|segroup";then
					echo "$SYSOP_USERS" | grep -wq "$which_user" && continue
					grep -qw "$which_user:delsudo" $LOG_DIR/add_user_tmp.log
					if [ $? -ne 0 ]; then
						INSERT_MYSQL "delsudo $which_user, tech_user illegal have root."
						usermod -G $which_user $which_user
					fi
				fi
			fi
		done
		for which_user in $SYSOP_USERS;do
			id $which_user > /dev/null 2>&1
			if [ "$?" -ne 0 ];then
				user_add_privilege "$which_user" "${which_user},execute"
			else		# 检查存在用户是否带sudo
				id $which_user | grep -Eq "execute|segroup"
				[[ $? -ne 0 ]] && usermod -G $which_user,execute $which_user
			fi
		done

		touch $LOG_DIR/start_user_privilege

		cat /dev/null > $ADD_USER_TMP

	# 关闭新的权限系统
	elif [ "$RECOVER" == "0" ];then
		[ -f $LOG_DIR/start_user_privilege ] && rm -f $LOG_DIR/start_user_privilege
	fi

	echo "$REMOTE_MD5" > $LOG_DIR/user_privilege_md5
fi

