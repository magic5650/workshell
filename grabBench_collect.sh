#!/bin/bash
#set -x
set -e
#[ -z "$nowdate" ] && nowdate=$1
if [ "x$nowdate" != "x" ]
then
	now_date="$nowdate"
	last_date=$(date -d "yesterday $nowdate" +%Y-%m-%d)
else
	now_date=$(date +%Y-%m-%d)
	last_date=$(date --date="-1 day" +%Y-%m-%d)
fi

now=$(date -d "$now_date 00:30:00" +%s)
last_day=$(date -d "$last_date 00:30:00" +%s)
cmd="stat /data/yy/log/music_grabBenchWP_m.*/music_grabBenchWP_m.* --printf='%Y %n\n'|awk '{if(($1>$last_day)&&($1<$now)) { print $2} }'"
cmd2="|xargs zgrep 'handleStratGrabReq success'"
cmd3="|wc -l"
cmd4="|grep -o 'uid=[0-9]*'|sort|uniq"
cmd5="|xargs zgrep 'handleGrabReq success'"
cmd_phone_total="|xargs zgrep 'PGrabRes'|grep 'result:0'|wc -l"
cmd_phone="|xargs zgrep 'PGrabRes'|grep 'result:0'|grep -o 'uid:[0-9]*'|sort|uniq|wc -l"


function getdata(){
	start_total=$(stat /data/yy/log/music_grabBenchWP_m.*/music_grabBenchWP_m.* --printf='%Y %n\n'|\
	awk '{if(($1>"'$last_day'")&&($1<"'$now'")) { print $2} }'|xargs zgrep 'handleStratGrabReq success'|wc -l)

	start_times=$(stat /data/yy/log/music_grabBenchWP_m.*/music_grabBenchWP_m.* --printf='%Y %n\n'|\
	awk '{if(($1>"'$last_day'")&&($1<"'$now'")) { print $2} }'|xargs zgrep 'handleStratGrabReq success'|\
	grep -o 'uid=[0-9]*'|sort|uniq|wc -l)

	grab_total=$(stat /data/yy/log/music_grabBenchWP_m.*/music_grabBenchWP_m.* --printf='%Y %n\n'|\
	awk '{if(($1>"'$last_day'")&&($1<"'$now'")) { print $2} }'|xargs zgrep 'handleGrabReq success'|wc -l)

	grab_times=$(stat /data/yy/log/music_grabBenchWP_m.*/music_grabBenchWP_m.* --printf='%Y %n\n'|\
	awk '{if(($1>"'$last_day'")&&($1<"'$now'")) { print $2} }'|xargs zgrep 'handleGrabReq success'|\
	grep -o 'uid=[0-9]*'|sort|uniq|wc -l)

	phone_grab_total=$(stat /data/yy/log/music_grabBenchWP_m.*/music_grabBenchWP_m.* --printf='%Y %n\n'|\
	awk '{if(($1>"'$last_day'")&&($1<"'$now'")) { print $2} }'|xargs zgrep 'PGrabRes'|grep 'result:0'|wc -l)

	phone_grab_times=$(stat /data/yy/log/music_grabBenchWP_m.*/music_grabBenchWP_m.* --printf='%Y %n\n'|\
	awk '{if(($1>"'$last_day'")&&($1<"'$now'")) { print $2} }'|xargs zgrep 'PGrabRes'|grep 'result:0'|\
	grep -o 'uid:[0-9]*'|sort|uniq|wc -l)
}

getdata > /dev/null 2>&1
if [ -n "$start_total" ];then
	echo "success $start_total $start_times $grab_total $grab_times $phone_grab_total $phone_grab_times"
else
	echo "failed"
fi