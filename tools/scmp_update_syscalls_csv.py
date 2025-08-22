#!/usr/bin/env python3

#
# Seccomp Library program to update the syscalls.csv file
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

import datetime
import argparse
import sys
import os

arch_list = [
    'i386', 'x86_64', 'x32', 'arm', 'arm64', 'loongarch64', 'm68k',
    'mipso32', 'mips64', 'mips64n32', 'parisc', 'parisc64', 'powerpc',
    'powerpc64', 'riscv64', 's390', 's390x', 'sh'
]

ignore_syscall_list = [
    'arc_gettls', 'arc_settls', 'arc_usr_cmpxchg', 'bfin_spinlock',
    'cache_sync', 'clone2', 'cmpxcg_badaddr', 'dipc', 'dma_memcpy',
    'exec_with_loader', 'execv', 'flush_cache', 'fp_udfiex_crtl',
    'getdomainname', 'getdtablesize', 'gethostname', 'getunwind', 'getxgid',
    'getxpid', 'getxuid', 'kern_features', 'llseek', 'madvise1',
    'memory_ordering', 'metag_get_tls', 'metag_set_fpu_flags', 'metag_set_tls',
    'metag_setglobalbit', 'mq_getsetaddr'
]

def parse_args():
    parser = argparse.ArgumentParser('Script to update the syscalls.csv kernel versions',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-d', '--datapath', required=True, type=str, default=None,
                        help="Path to the directory where @hrw's"
                        'syscalls-table tool output the version data')
    parser.add_argument('-k', '--kernelpath', required=True, type=str, default=None,
                        help="Path to the kernel source directory")
    parser.add_argument('-c', '--csv', required=False, type=str,
                        default='src/syscalls.csv',
                        help='Path to the the syscalls csv file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show verbose warnings')
    parser.add_argument('-a', '--add', action='store_true',
                        help='Add new syscalls to the csv')

    args = parser.parse_args()

    return args

def get_kernel_ver(args):
    makefile = os.path.join(args.kernelpath, 'Makefile')

    with open(makefile, 'r') as mkf:
        for line in mkf:

            if line.startswith('VERSION'):
                maj = int(line.split('=')[1].strip())
            elif line.startswith('PATCHLEVEL'):
                mnr = int(line.split('=')[1].strip())
            elif line.startswith('SUBLEVEL'):
                sub = int(line.split('=')[1].strip())
            elif line.startswith('EXTRAVERSION'):
                xtr = line.split('=')[1].strip()

    return maj, mnr, sub, xtr

def build_header(args, columns):
    maj, mnr, sub, xtr = get_kernel_ver(args)
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    header = '#syscall (v{}.{}.{}{} {})'.format(maj, mnr, sub, xtr, date)

    for col in columns:
        header = header + ',{}'.format(col)

    return header

def parse_syscalls_csv(args):
    column_order = list()
    syscalls = dict()

    with open(args.csv, 'r') as csvf:
        for line_idx, line in enumerate(csvf):
            if line_idx == 0:
                for col_idx, col_name in enumerate(line.split(',')):
                    if col_idx == 0:
                        continue
                    else:
                        column_order.append(col_name.strip())
            else:
                for col_idx, col_value in enumerate(line.split(',')):
                    if col_idx == 0:
                        syscall_name = col_value
                        syscalls[syscall_name] = list()
                    else:
                        syscalls[syscall_name].append(col_value.strip())

    return column_order, syscalls

def update_syscalls_dict(args, columns, syscalls):
    maj, mnr, sub, xtr = get_kernel_ver(args)
    kver = '{}.{}'.format(maj, mnr)

    for col_idx, column in enumerate(columns):
        if 'kver' in column:
            continue

        if column == 'x86':
            arch = 'i386'
        elif column == 'aarch64':
            arch = 'arm64'
        elif column == 'mips':
            arch = 'mipso32'
        elif column == 'ppc':
            arch = 'powerpc'
        elif column == 'ppc64':
            arch = 'powerpc64'
        else:
            arch = column

        table_path = os.path.join(args.datapath, 'syscalls-{}'.format(arch))

        with open(table_path, 'r') as tblf:
            for line in tblf:
                if line.startswith('HPUX_'):
                    continue

                if len(line.split()) == 1:
                    syscall_name = line.strip()
                    if syscall_name.startswith('HPUX'):
                        continue

                    if syscall_name in ignore_syscall_list:
                        continue

                    if syscall_name not in syscalls:
                        if args.verbose:
                            print('syscall {} is not in csv'.format(
                                  syscall_name))

                    if args.verbose:
                        print('syscall {} is undefined in {} for kernel v{}'.
                              format(line.strip(), column, kver))

                    if args.add and not syscall_name in syscalls:
                        # This is a new syscall for this kernel version
                        syscalls[syscall_name] = [None] * len(columns)
                        syscalls[syscall_name][col_idx] = 'PNR'
                        syscalls[syscall_name][col_idx + 1] = 'SCMP_KV_UNDEF'
                else:
                    syscall_name = line.split()[0].strip()
                    syscall_num = int(line.split()[1].strip())

                    if arch == 'mipso32':
                        syscall_num -= 4000
                    elif arch == 'mips64':
                        syscall_num -= 5000
                    elif arch == 'mips64n32':
                        syscall_num -= 6000
                    elif arch == 'x32' and syscall_num >= 0x40000000:
                        syscall_num = syscall_num - 0x40000000

                    if syscall_name in ignore_syscall_list:
                        continue

                    if syscall_name not in syscalls:
                        if args.verbose:
                            print('syscall {} is not in csv'.format(
                                  syscall_name))

                        if args.add:
                            syscalls[syscall_name] = [None] * len(columns)
                        else:
                            continue

                    if syscalls[syscall_name][col_idx] == 'PNR':
                        print('syscall {} was added to {} in kernel v{}'.
                              format(syscall_name, column, kver))

                        syscalls[syscall_name][col_idx] = str(syscall_num)
                        syscalls[syscall_name][col_idx + 1] = \
                            'SCMP_KV_{}_{}'.format(maj, mnr)

    return syscalls

def write_csv(args, columns, syscalls):
    with open(args.csv, 'w') as csvf:
        csvf.write(build_header(args, columns))
        csvf.write('\n')

        for syscall in syscalls:
            csvf.write('{},'.format(syscall))
            csvf.write(','.join(syscalls[syscall]))
            csvf.write('\n')

def main(args):
    columns, syscalls = parse_syscalls_csv(args)
    syscalls = update_syscalls_dict(args, columns, syscalls)
    write_csv(args, columns, syscalls)

if __name__ == '__main__':
    if sys.version_info < (3, 7):
        # Guaranteed dictionary ordering was added in python 3.7
        print("This script requires Python 3.7 or higher.")
        sys.exit(1)

    args = parse_args()
    main(args)
