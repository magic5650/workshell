#!/bin/bash
# 清理/data/yy/log/ 目录下乱码目录

exec 200<>$0
flock -n -e 200 || { echo "already Running, exit!";exit 1; }

normal_file=$(mktemp)
normal_inode=$(mktemp)

trap 'rm -f ${normal_file} ${normal_inode} /tmp/error_inode.txt;exit' 0 1 2 3 15

cd /data/yy/log
ls -1 | egrep '^[A-Za-z0-9_.-]+$' |sed '/^$/d' > $normal_file

while read file_name
do
	stat "$file_name"|grep -Eo "Inode: [0-9]*"|grep -Eo "[0-9]*" >> $normal_inode
done < $normal_file

ls -i|sed '1d'|awk '{print $1}' >> /tmp/error_inode.txt

while read inode
do
	sed -i '/^'"$inode"'$/d' /tmp/error_inode.txt
done < $normal_inode


while read nodeid
do
	find ./ -maxdepth 1 -type d -inum "$nodeid" -print0|xargs -0  rm -rf
	find ./ -maxdepth 1 -inum "$nodeid" -delete
done < /tmp/error_inode.txt