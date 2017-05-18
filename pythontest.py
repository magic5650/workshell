#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from subprocess import Popen, PIPE


def check_args(args):
    black_list = ["|", "`", ";", "&"]
    for a in black_list:
        if a in args:
            print "参数\"" + args + "\"包含非法字符\"" + a + "\""
            sys.exit(1)


def is_set(v):
    try:
        type(eval(v))
    except NameError:
        return 1
    else:
        return 0


def command(cmd1, cmd2, cmd1args, cmd2args):
    p1 = Popen(cmd1 + " " + cmd1args, bufsize=-1, stdout=PIPE, stderr=PIPE, shell=True)
    out, err = p1.communicate()
    if err != '':
        print "命令执行失败"
        print err, out
        sys.exit(1)

    p3 = Popen(cmd1 + " " + cmd1args, bufsize=-1, stdout=PIPE, stderr=PIPE, shell=True)
    p2 = Popen(cmd2 + " " + cmd2args, bufsize=-1, stdin=p3.stdout, stdout=PIPE, stderr=PIPE, shell=True)
    p3.stdout.close()
    out, err = p2.communicate()

    if p2.returncode == 0:
        print out
    else:
        print "命令执行失败"
        print err


if __name__ == "__main__":
    # ssargs = ido_args()['ssargs']
    # grepargs = ido_args()['grepargs']
    if is_set('ssargs'):
        ssargs = sys.argv[1]
    if is_set('grepargs'):
        grepargs = sys.argv[2]
    check_args(ssargs)
    check_args(grepargs)
    print "ss " + ssargs + "|" + "grep " + grepargs
    command('ss', 'grep', ssargs, grepargs)
