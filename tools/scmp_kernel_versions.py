#!/usr/bin/env python

#
# Seccomp Library program to determine when a syscall was added to the kernel
#
# Copyright (c) 2025 Oracle and/or its affiliates.  All rights reserved.
# Author: Tom Hromatka <tom.hromatka@oracle.com>
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License as
# published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

import subprocess
import argparse
import datetime

kernel_version_dict = {
    'SCMP_KV_6_12': datetime.datetime(2024, 11, 17),
    'SCMP_KV_6_11': datetime.datetime(2024, 9, 15),
    'SCMP_KV_6_10': datetime.datetime(2024, 7, 14),
    'SCMP_KV_6_9': datetime.datetime(2024, 5, 12),
    'SCMP_KV_6_8': datetime.datetime(2024, 3, 10),
    'SCMP_KV_6_7': datetime.datetime(2024, 1, 8),
    'SCMP_KV_6_6': datetime.datetime(2023, 10, 30),
    'SCMP_KV_6_5': datetime.datetime(2023, 8, 27),
    'SCMP_KV_6_4': datetime.datetime(2023, 6, 25),
    'SCMP_KV_6_3': datetime.datetime(2023, 4, 23),
    'SCMP_KV_6_2': datetime.datetime(2023, 2, 19),
    'SCMP_KV_6_1': datetime.datetime(2022, 12, 11),
    'SCMP_KV_6_0': datetime.datetime(2022, 10, 2),
    'SCMP_KV_5_19': datetime.datetime(2022, 7, 31),
    'SCMP_KV_5_18': datetime.datetime(2022, 5, 22),
    'SCMP_KV_5_17': datetime.datetime(2022, 3, 20),
    'SCMP_KV_5_16': datetime.datetime(2022, 1, 9),
    'SCMP_KV_5_15': datetime.datetime(2021, 10, 31),
    'SCMP_KV_5_14': datetime.datetime(2021, 8, 29),
    'SCMP_KV_5_13': datetime.datetime(2021, 6, 27),
    'SCMP_KV_5_12': datetime.datetime(2021, 4, 25),
    'SCMP_KV_5_11': datetime.datetime(2021, 2, 14),
    'SCMP_KV_5_10': datetime.datetime(2020, 12, 13),
    'SCMP_KV_5_9': datetime.datetime(2020, 10, 11),
    'SCMP_KV_5_8': datetime.datetime(2020, 8, 2),
    'SCMP_KV_5_7': datetime.datetime(2020, 5, 31),
    'SCMP_KV_5_6': datetime.datetime(2020, 3, 29),
    'SCMP_KV_5_5': datetime.datetime(2020, 1, 26),
    'SCMP_KV_5_4': datetime.datetime(2019, 11, 24),
    'SCMP_KV_5_3': datetime.datetime(2019, 9, 15),
    'SCMP_KV_5_2': datetime.datetime(2019, 7, 7),
    'SCMP_KV_5_1': datetime.datetime(2019, 5, 5),
    'SCMP_KV_5_0': datetime.datetime(2019, 3, 3),
    'SCMP_KV_4_20': datetime.datetime(2018, 12, 23),
    'SCMP_KV_4_19': datetime.datetime(2018, 10, 22),
    'SCMP_KV_4_18': datetime.datetime(2018, 8, 12),
    'SCMP_KV_4_17': datetime.datetime(2018, 6, 3),
    'SCMP_KV_4_16': datetime.datetime(2018, 4, 1),
    'SCMP_KV_4_15': datetime.datetime(2018, 1, 28),
    'SCMP_KV_4_14': datetime.datetime(2017, 11, 12),
    'SCMP_KV_4_13': datetime.datetime(2017, 9, 3),
    'SCMP_KV_4_12': datetime.datetime(2017, 7, 2),
    'SCMP_KV_4_11': datetime.datetime(2017, 4, 30),
    'SCMP_KV_4_10': datetime.datetime(2017, 2, 19),
    'SCMP_KV_4_9': datetime.datetime(2016, 12, 11),
    'SCMP_KV_4_8': datetime.datetime(2016, 9, 25),
    'SCMP_KV_4_7': datetime.datetime(2016, 7, 24),
    'SCMP_KV_4_6': datetime.datetime(2016, 5, 15),
    'SCMP_KV_4_5': datetime.datetime(2016, 3, 13),
    'SCMP_KV_4_4': datetime.datetime(2016, 1, 10),
    'SCMP_KV_4_3': datetime.datetime(2015, 11, 1),
    'SCMP_KV_4_2': datetime.datetime(2015, 8, 30),
    'SCMP_KV_4_1': datetime.datetime(2015, 6, 22),
    'SCMP_KV_4_0': datetime.datetime(2015, 4, 12),
}

class RunError(Exception):
    def __init__(self, message, command, ret, stdout, stderr):
        super(RunError, self).__init__(message)

        self.command = command
        self.ret = ret
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        out_str = 'RunError:\n\tcommand = {}\n\tret = {}'.format(
                  self.command, self.ret)
        out_str += '\n\tstdout = {}\n\tstderr = {}'.format(self.stdout,
                                                           self.stderr)
        return out_str

def run(command, run_in_shell=False):
    if run_in_shell:
        if isinstance(command, str):
            # nothing to do.  command is already formatted as a string
            pass
        elif isinstance(command, list):
            command = ' '.join(command)
        else:
            raise ValueError('Unsupported command type')

    subproc = subprocess.Popen(command, shell=run_in_shell,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = subproc.communicate()
    ret = subproc.returncode

    out = out.strip().decode('UTF-8')
    err = err.strip().decode('UTF-8')

    if ret != 0 or len(err) > 0:
        raise RunError("Command '{}' failed".format(''.join(command)),
                       command, ret, out, err)

    return out

def parse_args():
    parser = argparse.ArgumentParser('Script to determine when a syscall was'
                                     ' added to the kernel for a given'
                                     ' architecture',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-k', '--kernelpath', required=True, type=str,
                        help='Path to the kernel source code')
    parser.add_argument('-a', '--arch', required=True, type=str,
                        help='Architecture')

    args = parser.parse_args()

    return args

def init_arch(args):
    """ Do what's necessary to initialize this script so that it can process
    the requested architecture

    Note that this function will add more members/settings to the args struct
    """
    if args.arch == 'x86':
        args.abi = ['i386']
        args.syscall_file = 'arch/x86/entry/syscalls/syscall_32.tbl'
    elif args.arch == 'x86_64':
        args.abi = ['common', '64']
        args.syscall_file = 'arch/x86/entry/syscalls/syscall_64.tbl'
    elif args.arch == 'x32':
        args.abi = ['common', 'x32']
        args.syscall_file = 'arch/x86/entry/syscalls/syscall_64.tbl'
    else:
        raise ValueError('Unsupported architecture: {}'.format(args.arch))

def get_commits(args):
    """ Get the commits (in reverse order) to the syscall_file

    Note that this function will add more members/settings to the args struct
    """
    cmd = 'pushd {} > /dev/null 2>&1 && ' \
          'git log --pretty=format:"%H" {};' \
          'popd > /dev/null 2>&1'.format(
          args.kernelpath, args.syscall_file)

    commit_str = run(cmd, True)
    args.commits = commit_str.split()

def get_kernel_version(date):
    """ Given a date, find the associated kernel version
    """
    for key in kernel_version_dict:
        if kernel_version_dict[key] < date:
            return key

    raise ValueError('Date is older than KV_4_0')

def populate_syscall_ver_dict(args, line, commit_date, syscall_ver_dict):
    # remove the leading "+"
    fields = line[1:].split()

    if len(fields) != 4:
        # this diff isn't for a syscall entry.  skip it
        return

    try:
        # simple sanity check to ensure that the first entry is the syscall
        # number
        syscall_num = int(fields[0])
    except ValueError:
        return

    for abi in args.abi:
        if abi == fields[1]:
            syscall_ver_dict[fields[2]] = get_kernel_version(commit_date)

def parse_diff(args, diff, syscall_ver_dict):
    month_dict = {
        'Jan': 1,
        'Feb': 2,
        'Mar': 3,
        'Apr': 4,
        'May': 5,
        'Jun': 6,
        'Jul': 7,
        'Aug': 8,
        'Sep': 9,
        'Oct': 10,
        'Nov': 11,
        'Dec': 12
    }
    in_syscall_diff = False
    commit_date = None

    for line in diff.splitlines():
        if line.startswith('CommitDate: '):
            commit_month = month_dict[line.split()[2]]
            commit_day = int(line.split()[3])
            commit_year = int(line.split()[5])

            commit_date = datetime.datetime(commit_year, commit_month, commit_day)

        if line.startswith('diff --git'):
            if line.split()[2] == 'a/{}'.format(args.syscall_file):
                in_syscall_diff = True
            else:
                in_syscall_diff = False

        if not in_syscall_diff:
            continue

        if line.startswith('+++ '):
            continue

        if line[0] != '+':
            continue

        populate_syscall_ver_dict(args, line, commit_date, syscall_ver_dict)

def walk_commits(args):
    syscall_ver_dict = dict()

    for commit in args.commits:
        cmd = 'pushd {} > /dev/null 2>&1 && ' \
              'git show {} {};' \
              'popd > /dev/null 2>&1'.format(
              args.kernelpath, commit, args.syscall_file)
        diff = run(cmd, True)

        parse_diff(args, diff, syscall_ver_dict)

    return syscall_ver_dict

def modify_syscall_csv(args, syscall_vers):
    ver_col = None

    dstf = open('../src/syscalls.csv.tmp', 'w')

    with open('../src/syscalls.csv', 'r') as srcf:
        for line_num, line in enumerate(srcf):
            if line_num == 0:
                fields = line.split(',')
                for field_num, field in enumerate(fields):
                    if field == args.arch:
                        ver_col = field_num + 1

            fields = line.split(',')
            if fields[0] in syscall_vers:
                fields[ver_col] = syscall_vers[fields[0]]

                line = ','.join(fields)

            dstf.write(line)

    dstf.close()

def main(args):
    init_arch(args)
    get_commits(args)
    syscall_vers = walk_commits(args)

    modify_syscall_csv(args, syscall_vers)

if __name__ == '__main__':
    args = parse_args()
    main(args)
