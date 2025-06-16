#include "tracer.h"
#include <QDebug>

// 包含了 ptrace 和 waitpid 所需的头文件
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <syscall.h>
#include <fstream>
#include <string>
#include <time.h> // For clock_gettime

// 辅助函数：获取高精度时间戳
quint64 get_timestamp_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (quint64)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
// 用于获取进程名的辅助函数
QString get_process_name(pid_t pid) {
    QString comm_path = QString("/proc/%1/comm").arg(pid);
    std::ifstream comm_file(comm_path.toStdString());
    std::string name;
    if (comm_file.is_open()) {
        std::getline(comm_file, name);
        comm_file.close();
    }
    return QString::fromStdString(name);
}

Tracer::Tracer(QObject *parent) : QObject(parent) {}

void Tracer::stop() {
    m_running = false;
}

void Tracer::start(unsigned int pid) {
    m_running = true;

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        emit finished(QString("Error: Failed to attach to PID %1. Make sure you are running with sudo.").arg(pid));
        return;
    }

    int status;
    waitpid(pid, &status, 0);

    // 检查进程是否真的被附加了
    if (!WIFSTOPPED(status)) {
        emit finished(QString("Error: Failed to stop process %1 after attaching.").arg(pid));
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return;
    }

    qInfo() << "Successfully attached to PID" << pid;
    QString processName = get_process_name(pid);

    ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD);

    bool is_syscall_entry = true;
    long current_syscall = -1;
    quint64 start_ts = 0;

    while (m_running) {
        if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) break;
        if (waitpid(pid, &status, 0) == -1) break;

        if (!(WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80))) continue;

        if (is_syscall_entry) {
            // 系统调用入口
            struct user_regs_struct regs_entry;
            if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs_entry) == -1) break;

            current_syscall = regs_entry.orig_rax;
            start_ts = get_timestamp_ns();

        } else {
            // 系统调用出口
            struct user_regs_struct regs_exit;
            if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs_exit) == -1) break;

            quint64 end_ts = get_timestamp_ns();
            quint64 duration = (end_ts > start_ts) ? (end_ts - start_ts) : 0;

            // 从 regs_exit.rax 获取返回值
            long return_value = regs_exit.rax;

            // 发射带有返回值的信号
            emit newSyscallData(start_ts, duration, return_value, current_syscall, pid, processName);
        }

        is_syscall_entry = !is_syscall_entry; // 切换状态
    }

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    qInfo() << "Detached from PID" << pid;
    emit finished("Tracer stopped.");
}
