#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <bits/stdc++.h>
#include <errno.h>
#include "syscall_table.h" // syscall_names: std::map<long, std::string>

#define COLOR_SYSCALL "\033[1;32m"
#define COLOR_ARGTYPE "\033[1;34m"
#define COLOR_RETURN  "\033[1;33m"
#define COLOR_ERROR   "\033[1;31m"
#define COLOR_RESET   "\033[0m"

using namespace std;

// 用于描述哪些参数是字符串（最多支持6个参数）
struct SyscallParamInfo {
    vector<int> string_indices; // 比如 {0,1} 表示第1、第2个参数是字符串
};
std::map<long, std::string> syscall_arg_types = {
    {59, "execve(const char *filename, char *const argv[], char *const envp[])"},
    {257, "openat(int dirfd, const char *pathname, int flags, mode_t mode)"},
    {2, "open(const char *pathname, int flags, mode_t mode)"},
    {21, "access(const char *pathname, int mode)"},
};

std::map<long, SyscallParamInfo> string_param_map = {
    {59, {{0, 1}}},    // execve(filename, argv, envp)
    {2,  {{0}}},       // open(pathname, ...)
    {257, {{1}}},      // openat(dirfd, pathname, ...)
    {21, {{0}}},       // access(pathname, ...)
    {0,  {}},          // read(fd, buf, count) - buf 不是字符串，不解析
};

std::string read_string(pid_t pid, unsigned long addr) {
    std::string result;
    union {
        long word;
        char chars[sizeof(long)];
    } data;

    while (true) {
        errno = 0;
        data.word = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
        if (errno != 0) break;

        for (int i = 0; i < sizeof(long); i++) {
            if (data.chars[i] == '\0') return result;
            result += data.chars[i];
        }
        addr += sizeof(long);
    }
    return result;
}

// 获取第 i 个参数（仅限 x86_64 下最多6个）
unsigned long get_syscall_arg(const user_regs_struct& regs, int index) {
    switch (index) {
        case 0: return regs.rdi;
        case 1: return regs.rsi;
        case 2: return regs.rdx;
        case 3: return regs.r10;
        case 4: return regs.r8;
        case 5: return regs.r9;
        default: return 0;
    }
}

int main() {

    pid_t target_pid;
    cin >> target_pid;
    // 附加到目标进程
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
        perror("ptrace attach failed");
        return 1;
    }

    int status;
    waitpid(target_pid, &status, 0);

    bool entering = true;
    struct user_regs_struct regs;

    while (true) {
        ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL);
        waitpid(target_pid, &status, 0);

        if (WIFEXITED(status)) break;

        ptrace(PTRACE_GETREGS, target_pid, NULL, &regs);

#ifdef __x86_64__
        long syscall_num = regs.orig_rax;

        if (entering) {
            auto it = syscall_names.find(syscall_num);
            string name = (it != syscall_names.end()) ? it->second : "unknown";

            cout << COLOR_SYSCALL << "→ " << name << COLOR_RESET << " (" << syscall_num << ")\n";

            // 打印参数类型
            if (syscall_arg_types.count(syscall_num)) {
                cout << COLOR_ARGTYPE << "    " << syscall_arg_types[syscall_num] << COLOR_RESET << "\n";
            }

            // 打印参数值，并尝试解码字符串
            for (int i = 0; i < 6; ++i) {
                unsigned long val = get_syscall_arg(regs, i);
                cout << "    arg" << i << " = 0x" << std::hex << val;

                // 判断是否应该解码为字符串
                auto info_it = string_param_map.find(syscall_num);
                if (info_it != string_param_map.end()) {
                    for (int str_idx : info_it->second.string_indices) {
                        if (str_idx == i && val > 0x1000) {
                            std::string s = read_string(target_pid, val);
                            if (!s.empty())
                                cout << " → \"" << s << "\"";
                            break;
                        }
                    }
                }
                cout << "\n";
            }

        } else {
            long ret = regs.rax;
            if (ret >= 0) {
                cout << COLOR_RETURN << "← Return: 0x" << std::hex << ret << COLOR_RESET << "\n\n";
            } else {
                cout << COLOR_ERROR << "← Return (err): " << ret << COLOR_RESET << "\n\n";
            }
        }
#endif
        entering = !entering;
    }

    // 脱离目标进程
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    return 0;
}