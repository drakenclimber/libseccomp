#!/usr/bin/env python3
import abc
import os
import subprocess

FIRST_KNOWN_KERNEL = 5.04
KERNEL_DICT = {
        'v5.04': 'KV_5_04',
        'v5.05': 'KV_5_05',
        'v5.06': 'KV_5_06',
        'v5.07': 'KV_5_07',
        'v5.08': 'KV_5_08',
        'v5.09': 'KV_5_09',
        'v5.10': 'KV_5_10',
        'v5.11': 'KV_5_11',
        'v5.12': 'KV_5_12',
        'v5.13': 'KV_5_13',
        'v5.14': 'KV_5_14',
        'v5.15': 'KV_5_15',
        'v5.16': 'KV_5_16',
}

def run(command, shell=True):
    if shell:
        if isinstance(command, str):
            # nothing to do.  command is already formatted as a string
            pass
        elif isinstance(command, list):
            command = ' '.join(command)
        else:
            raise ValueError('Unsupported command type')

    subproc = subprocess.Popen(command, shell=shell,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = subproc.communicate()
    ret = subproc.returncode

    out = out.strip().decode('UTF-8')
    err = err.strip().decode('UTF-8')

    if ret != 0:
        raise OSError("Command '{}' failed with ret = {} and stderr = {}".format(
            ''.join(command), ret, err))

    return out


class Arch(object):
    def __init__(self):
        #self.kernel_path = None
        # HACK
        self.kernel_path = '/home/thromatka/git/clean/upstream-torvalds'
        self.syscall_file = None
        self.git_blame = None
        self.arch_name = None

        # a dictionary of syscalls and the line number they appear on
        # e.g. self.syscall_dict['utime'] = 143
        self.syscall_dict = dict()

        # a dictionary of commit hashes and their earliest tag.  this is
        # purely a performance optimization
        self.commit_tag_dict = dict()


    def run_git_blame(self):
        cmd = 'pushd {} > /dev/null 2>&1;' \
              'git blame {};' \
              'popd'.format(self.kernel_path, self.syscall_file)

        self.git_blame = run(cmd)

    @abc.abstractmethod
    def build_syscall_dict(self):
        raise NotImplementedError

    def get_commit_hash(self, syscall_name):
        for line in self.git_blame.splitlines():
            line_num_str = '{})'.format(self.syscall_dict[syscall_name])
            if line.find(line_num_str) != -1 and \
               line.find(syscall_name) != -1:
                   return line.split()[0]

    def find_oldest_tag(self, commit_hash):
        cmd = 'pushd {} > /dev/null 2>&1;' \
              'git tag --contains {};' \
              'popd'.format(self.kernel_path, commit_hash)
        res = run(cmd)

        tags = res.splitlines()
        tags.sort()
        for tag in tags:
            if tag.find('-rc') == -1:
                # this is the oldest non-release-candidate tag.  return it
                return tag

        raise OSError('Failed to find any tags associated with commit {}' \
                      .format(commit_hash))

    def validate(self, syscall_name, tag_enum):
        if tag_enum == 'KV_UNDEF':
            # This syscall doesn't exist on this architecture
            return

        commit_hash = self.get_commit_hash(syscall_name)
        try:
            tag = self.commit_tag_dict[commit_hash]
        except KeyError as ke:
            tag = self.find_oldest_tag(commit_hash)
            self.commit_tag_dict[commit_hash] = tag

        try:
            kernel_enum = KERNEL_DICT[tag]
        except KeyError as ke:
            if float(tag[1:]) < FIRST_KNOWN_KERNEL:
                kernel_enum = 'KV_PRE_5_17'

        if kernel_enum != tag_enum:
            print('Warning: arch {} syscall {} has tag {} but kernel has' \
                  ' tag {}'.format(self.arch_name, syscall_name, tag_enum,
                  kernel_enum))
            return False

        return True


class Arch_x86_64(Arch):
    def __init__(self):
        super().__init__()
        self.syscall_file = os.path.join(self.kernel_path,
                'arch/x86/entry/syscalls/syscall_64.tbl')
        self.run_git_blame()
        self.arch_name = 'x86_64'

    def build_syscall_dict(self):
        cmd = "cat {}/arch/x86/entry/syscalls/syscall_64.tbl" \
              " | grep -nv \"^#\"" \
              " | sed 's/:/ /g'" \
              " | awk '{{ print $3,$1,$4 }}'" \
              " | sed '/^x32/d'" \
              " | awk '{{ print $3,$2 }}'" \
              " | sort ".format(self.kernel_path)
        
        res = run(cmd)

        for line in res.splitlines():
            syscall,line_num = line.split()
            self.syscall_dict[syscall] = line_num


validators = [
        None,           # column 0
        None,           # column 1, x86
        Arch_x86_64(),  # column 2, x86_64
        None,           # column 3
        None,           # column 4
        None,           # column 5
        None,           # column 6
        None,           # column 7
        None,           # column 8
        None,           # column 9
        None,           # column 10
        None,           # column 11
        None,           # column 12
        None,           # column 13
        None,           # column 14
        None,           # column 15
        None,           # column 16
]

def parse_introduced_header(line):
    cols = line.split(',')
    for idx, col in enumerate(cols):
        if validators[idx] is not None:
            validators[idx].build_syscall_dict()


def parse_introduced_data(line, line_num):
    cols = line.split(',')
    if len(cols) != len(validators):
        raise IndexError(
                '{} architectures were specified in the CSV, but '
                'Validators[] has {} architectures specified'.format(
                len(cols), len(validators)))

    for idx, col in enumerate(cols):
        error_cnt = 0
        col = col.strip()

        if idx == 0:
            syscall_name = col
        else:
            if validators[idx] is not None:
                if not validators[idx].validate(syscall_name, col):
                    error_cnt += 1


if __name__ == '__main__':
    with open('introduced.csv', 'r') as f:
        for idx, line in enumerate(f):
            if idx == 0:
                parse_introduced_header(line)
            else:
                error_cnt = parse_introduced_data(line, idx)

    sys.exit(error_cnt)
