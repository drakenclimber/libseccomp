#!/usr/bin/env python

#
# Seccomp Library program to build the syscalls.csv file
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

import argparse
import math

arch_list = ['i386', 'x86_64', 'x32', 'arm', 'arm64', 'loongarch64', 'm68k',
             'mipso32', 'mips64', 'mips64n32', 'parisc', 'parisc64', 'powerpc',
             'powerpc64', 'riscv64', 's390', 's390x', 'sh']

kernel_versions = ['3.0', '3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7',
                   '3.8', '3.9', '3.10', '3.11', '3.12', '3.13', '3.14',
                   '3.15', '3.16', '3.17', '3.18', '3.19', '4.0', '4.1',
                   '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9',
                   '4.10', '4.11', '4.12', '4.13', '4.14', '4.15', '4.16',
                   '4.17', '4.18', '4.19', '4.20', '5.0', '5.1', '5.2',
                   '5.3', '5.4', '5.5', '5.6', '5.7', '5.8', '5.9', '5.10',
                   '5.11', '5.12', '5.13', '5.14', '5.15', '5.16', '5.17',
                   '5.18', '5.19', '6.0', '6.1', '6.2', '6.3', '6.4', '6.5',
                   '6.6', '6.7', '6.8', '6.9', '6.10', '6.11', '6.12',
                   '6.13']

syscall_list = [ 'accept', 'accept4', 'access', 'acct', 'add_key', 'adjtimex',
    'afs_syscall', 'alarm', 'arch_prctl', 'arm_fadvise64_64',
    'arm_sync_file_range', 'atomic_barrier', 'atomic_cmpxchg_32', 'bdflush',
    'bind', 'bpf', 'break', 'breakpoint', 'brk', 'cachectl', 'cacheflush',
    'cachestat', 'capget', 'capset', 'chdir', 'chmod', 'chown', 'chown32',
    'chroot', 'clock_adjtime', 'clock_adjtime64', 'clock_getres',
    'clock_getres_time64', 'clock_gettime', 'clock_gettime64',
    'clock_nanosleep', 'clock_nanosleep_time64', 'clock_settime',
    'clock_settime64', 'clone', 'clone3', 'close', 'close_range', 'connect',
    'copy_file_range', 'creat', 'create_module', 'delete_module', 'dup',
    'dup2', 'dup3', 'epoll_create', 'epoll_create1', 'epoll_ctl',
    'epoll_ctl_old', 'epoll_pwait', 'epoll_pwait2', 'epoll_wait',
    'epoll_wait_old', 'eventfd', 'eventfd2', 'execve', 'execveat',
    'exit', 'exit_group', 'faccessat', 'faccessat2', 'fadvise64',
    'fadvise64_64', 'fallocate', 'fanotify_init', 'fanotify_mark', 'fchdir',
    'fchmod', 'fchmodat', 'fchmodat2', 'fchown', 'fchown32', 'fchownat',
    'fcntl', 'fcntl64', 'fdatasync', 'fgetxattr', 'finit_module',
    'flistxattr', 'flock', 'fork', 'fremovexattr', 'fsconfig', 'fsetxattr',
    'fsmount', 'fsopen', 'fspick', 'fstat', 'fstat64', 'fstatat64', 'fstatfs',
    'fstatfs64', 'fsync', 'ftime', 'ftruncate', 'ftruncate64', 'futex',
    'futex_requeue', 'futex_time64', 'futex_wait', 'futex_waitv',
    'futex_wake', 'futimesat', 'getcpu', 'getcwd', 'getdents', 'getdents64',
    'getegid', 'getegid32', 'geteuid', 'geteuid32', 'getgid', 'getgid32',
    'getgroups', 'getgroups32', 'getitimer', 'get_kernel_syms',
    'get_mempolicy', 'getpagesize', 'getpeername', 'getpgid', 'getpgrp',
    'getpid', 'getpmsg', 'getppid', 'getpriority', 'getrandom', 'getresgid',
    'getresgid32', 'getresuid', 'getresuid32', 'getrlimit', 'get_robust_list',
    'getrusage', 'getsid', 'getsockname', 'getsockopt', 'get_thread_area',
    'gettid', 'gettimeofday', 'get_tls', 'getuid', 'getuid32', 'getxattr',
    'getxattrat', 'gtty', 'idle', 'init_module', 'inotify_add_watch',
    'inotify_init', 'inotify_init1', 'inotify_rm_watch', 'io_cancel', 'ioctl',
    'io_destroy', 'io_getevents', 'ioperm', 'io_pgetevents',
    'io_pgetevents_time64', 'iopl', 'ioprio_get', 'ioprio_set', 'io_setup',
    'io_submit', 'io_uring_enter', 'io_uring_register', 'io_uring_setup',
    'ipc', 'kcmp', 'kexec_file_load', 'kexec_load', 'keyctl', 'kill',
    'landlock_add_rule', 'landlock_create_ruleset', 'landlock_restrict_self',
    'lchown', 'lchown32', 'lgetxattr', 'link', 'linkat', 'listen',
    'listmount', 'listxattr', 'listxattrat', 'llistxattr', '_llseek', 'lock',
    'lookup_dcookie', 'lremovexattr', 'lseek', 'lsetxattr',
    'lsm_get_self_attr', 'lsm_list_modules', 'lsm_set_self_attr', 'lstat',
    'lstat64', 'madvise', 'map_shadow_stack', 'mbind', 'membarrier',
    'memfd_create', 'memfd_secret', 'migrate_pages', 'mincore', 'mkdir',
    'mkdirat', 'mknod', 'mknodat', 'mlock', 'mlock2', 'mlockall', 'mmap',
    'mmap2', 'modify_ldt', 'mount', 'mount_setattr', 'move_mount',
    'move_pages', 'mprotect', 'mpx', 'mq_getsetattr', 'mq_notify', 'mq_open',
    'mq_timedreceive', 'mq_timedreceive_time64', 'mq_timedsend',
    'mq_timedsend_time64', 'mq_unlink', 'mremap', 'mseal', 'msgctl', 'msgget',
    'msgrcv', 'msgsnd', 'msync', 'multiplexer', 'munlock', 'munlockall',
    'munmap', 'name_to_handle_at', 'nanosleep', 'newfstatat', '_newselect',
    'nfsservctl', 'nice', 'oldfstat', 'oldlstat', 'oldolduname', 'oldstat',
    'olduname', 'open', 'openat', 'openat2', 'open_by_handle_at', 'open_tree',
    'pause', 'pciconfig_iobase', 'pciconfig_read', 'pciconfig_write',
    'perf_event_open', 'personality', 'pidfd_getfd', 'pidfd_open',
    'pidfd_send_signal', 'pipe', 'pipe2', 'pivot_root', 'pkey_alloc',
    'pkey_free', 'pkey_mprotect', 'poll', 'ppoll', 'ppoll_time64', 'prctl',
    'pread64', 'preadv', 'preadv2', 'prlimit64', 'process_madvise',
    'process_mrelease', 'process_vm_readv', 'process_vm_writev', 'prof',
    'profil', 'pselect6', 'pselect6_time64', 'ptrace', 'putpmsg', 'pwrite64',
    'pwritev', 'pwritev2', 'query_module', 'quotactl', 'quotactl_fd', 'read',
    'readahead', 'readdir', 'readlink', 'readlinkat', 'readv', 'reboot',
    'recv', 'recvfrom', 'recvmmsg', 'recvmmsg_time64', 'recvmsg',
    'remap_file_pages', 'removexattr', 'removexattrat', 'rename', 'renameat',
    'renameat2', 'request_key', 'restart_syscall', 'riscv_flush_icache',
    'riscv_hwprobe', 'rmdir', 'rseq', 'rtas', 'rt_sigaction', 'rt_sigpending',
    'rt_sigprocmask', 'rt_sigqueueinfo', 'rt_sigreturn', 'rt_sigsuspend',
    'rt_sigtimedwait', 'rt_sigtimedwait_time64', 'rt_tgsigqueueinfo',
    's390_guarded_storage', 's390_pci_mmio_read', 's390_pci_mmio_write',
    's390_runtime_instr', 's390_sthyi', 'sched_getaffinity', 'sched_getattr',
    'sched_getparam', 'sched_get_priority_max', 'sched_get_priority_min',
    'sched_getscheduler', 'sched_rr_get_interval',
    'sched_rr_get_interval_time64', 'sched_setaffinity', 'sched_setattr',
    'sched_setparam', 'sched_setscheduler', 'sched_yield', 'seccomp',
    'security', 'select', 'semctl', 'semget', 'semop', 'semtimedop',
    'semtimedop_time64', 'send', 'sendfile', 'sendfile64', 'sendmmsg',
    'sendmsg', 'sendto', 'setdomainname', 'setfsgid', 'setfsgid32',
    'setfsuid', 'setfsuid32', 'setgid', 'setgid32', 'setgroups',
    'setgroups32', 'sethostname', 'setitimer', 'set_mempolicy',
    'set_mempolicy_home_node', 'setns', 'setpgid', 'setpriority', 'setregid',
    'setregid32', 'setresgid', 'setresgid32', 'setresuid', 'setresuid32',
    'setreuid', 'setreuid32', 'setrlimit', 'set_robust_list', 'setsid',
    'setsockopt', 'set_thread_area', 'set_tid_address', 'settimeofday',
    'set_tls', 'setuid', 'setuid32', 'setxattr', 'setxattrat', 'sgetmask',
    'shmat', 'shmctl', 'shmdt', 'shmget', 'shutdown', 'sigaction',
    'sigaltstack', 'signal', 'signalfd', 'signalfd4', 'sigpending',
    'sigprocmask', 'sigreturn', 'sigsuspend', 'socket', 'socketcall',
    'socketpair', 'splice', 'spu_create', 'spu_run', 'ssetmask', 'stat',
    'stat64', 'statfs', 'statfs64', 'statmount', 'statx', 'stime', 'stty',
    'subpage_prot', 'swapcontext', 'swapoff', 'swapon', 'switch_endian',
    'symlink', 'symlinkat', 'sync', 'sync_file_range', 'sync_file_range2',
    'syncfs', 'syscall', '_sysctl', 'sys_debug_setcontext', 'sysfs',
    'sysinfo', 'syslog', 'sysmips', 'tee', 'tgkill', 'time', 'timer_create',
    'timer_delete', 'timerfd', 'timerfd_create', 'timerfd_gettime',
    'timerfd_gettime64', 'timerfd_settime', 'timerfd_settime64',
    'timer_getoverrun', 'timer_gettime', 'timer_gettime64', 'timer_settime',
    'timer_settime64', 'times', 'tkill', 'truncate', 'truncate64', 'tuxcall',
    'ugetrlimit', 'ulimit', 'umask', 'umount', 'umount2', 'uname', 'unlink',
    'unlinkat', 'unshare', 'uretprobe', 'uselib', 'userfaultfd', 'usr26',
    'usr32', 'ustat', 'utime', 'utimensat', 'utimensat_time64', 'utimes',
    'vfork', 'vhangup', 'vm86', 'vm86old', 'vmsplice', 'vserver', 'wait4',
    'waitid', 'waitpid', 'write', 'writev']

header = '#syscall (v6.13.0 2025-02-18),x86,x86_kver,x86_64,x86_64_kver,x32,x32_kver,arm,arm_kver,aarch64,aarch64_kver,loongarch64,loongarch64_kver,m68k,m68k_kver,mips,mips_kver,mips64,mips64_kver,mips64n32,mips64n32_kver,parisc,parisc_kver,parisc64,parisc64_kver,ppc,ppc_kver,ppc64,ppc64_kver,riscv64,riscv64_kver,s390,s390_kver,s390x,s390x_kver,sh,sh_kver'

def parse_args():
    parser = argparse.ArgumentParser('Script to populate the syscalls.csv kernel versions',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-d', '--datapath', required=True, type=str, default=None,
                        help="Path to the directory where @hrw's"
                        'syscalls-table tool output the version data')
    parser.add_argument('-o', '--outfile', required=False, type=str,
                        default='src/syscalls.csv', help='output csv')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show verbose warnings')

    args = parser.parse_args()

    return args


def build_syscalls_dict(args):
    syscalls = dict()
    for arch in arch_list:
        syscalls[arch] = dict()

    for kernel_version in kernel_versions:
        for arch in arch_list:
            syscalls_file = '{}/tables-{}/syscalls-{}'.format(args.datapath,
                            kernel_version, arch)
            with open(syscalls_file, 'r') as sysf:
                for line in sysf:

                    if len(line.split()) == 2:
                        syscall = line.split()[0]
                        syscall_num = line.split()[1]
                        syscall_version = kernel_version

                        # While unusual, some syscall numbers did change over
                        # time.  For example, seccomp() went from 277 (x86_64)
                        # in kernel 3.17 to 317 in kernel 3.18.  Argh.
                        if syscall in syscalls[arch]:
                            # Save off the first version that the syscall was
                            # available.  that's what we should populate the
                            # table with.
                            syscall_version = syscalls[arch][syscall][1]
                            syscalls[arch].pop(syscall)

                        syscalls[arch][syscall] = [syscall_num, syscall_version]

    return syscalls

def search_for_syscalls_in_holes(args, syscalls):
    """Search for syscalls in holes

    Searches through each architecture's syscalls and ensures that new
    syscalls were added at the end (and not in a "hole" in the middle of
    the syscall numbers)
    """
    for arch in arch_list:
        for syscall in syscall_list:
                if syscall in syscalls[arch]:
                    num = int(syscalls[arch][syscall][0])
                    mjr = int(syscalls[arch][syscall][1].split('.')[0])
                    mnr = int(syscalls[arch][syscall][1].split('.')[1])

                    for tmp in syscall_list:
                        if tmp == syscall:
                            continue

                        if tmp in syscalls[arch]:
                            tmp_num = int(syscalls[arch][tmp][0])
                            tmp_mjr = int(syscalls[arch][tmp][1].split('.')[0])
                            tmp_mnr = int(syscalls[arch][tmp][1].split('.')[1])

                            if tmp_num < num:
                                # we only want to look at syscall nums larger
                                # (and in theory newer) than our syscall number
                                continue

                            if tmp_mjr < mjr or (tmp_mjr == mjr and tmp_mnr < mnr):
                                print('Warning syscall {} in arch {} was '
                                      'added in a hole'.format(syscall, arch))
                                break

def write_csv(args, syscalls):
    with open(args.outfile, 'w') as outf:
        outf.write(header)
        outf.write('\n')
        for syscall in syscall_list:
            outf.write('{}'.format(syscall))
            for arch in arch_list:
                if syscall in syscalls[arch]:
                    version = syscalls[arch][syscall][1]
                    version = version.replace('.', '_')

                    num = int(syscalls[arch][syscall][0])
                    if arch == 'mipso32':
                        num -= 4000
                    elif arch == 'mips64':
                        num -= 5000
                    elif arch == 'mips64n32':
                        num -= 6000

                    outf.write(',{},SCMP_KV_{}'.format(num, version))
                else:
                    outf.write(',PNR,SCMP_KV_UNDEF')
            outf.write('\n')

def main(args):
    syscalls = build_syscalls_dict(args)

    if args.verbose:
        search_for_syscalls_in_holes(args, syscalls)

    write_csv(args, syscalls)

if __name__ == '__main__':
    args = parse_args()
    main(args)
