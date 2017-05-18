#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
from subprocess import Popen, PIPE


def check_args(args):
    black_list = ["`", "&"]
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


def command(cmd):
    assert isinstance(cmd, str)
    p1 = Popen(cmd, bufsize=-1, stdout=PIPE, stderr=PIPE, shell=True)
    out, err = p1.communicate()
    if err != '':
        print "命令执行失败"
        print err
        print out
        sys.exit(1)
    if p1.returncode == 0:
        print out
    else:
        print "命令执行失败"
        print err


if __name__ == "__main__":
    # cmd = ido_args()['cmd']
    if is_set('cmd') == 1:
        cmd = sys.argv[1]

    print cmd
    check_args(cmd)
    command(cmd)
