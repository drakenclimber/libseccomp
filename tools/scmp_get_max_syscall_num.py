#!/usr/bin/env python

#
# Seccomp Library program to determine the largest syscall number
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

max_syscall_num = 0

with open('../src/syscalls.csv', 'r') as csvf:
    for line_num, line in enumerate(csvf):
        if line_num == 0:
            continue

        fields = line.split(',')

        for field_num, field in enumerate(fields):
            if field_num == 0:
                continue

            syscall_num = 0
            try:
                syscall_num = int(field)
            except ValueError:
                continue

            if syscall_num > 983000:
                # skip arm syscalls with a really large base number
                continue

            if syscall_num > max_syscall_num:
                max_syscall_num = syscall_num

print(max_syscall_num)
