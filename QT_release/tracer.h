#ifndef TRACER_H
#define TRACER_H

#include <QObject>
#include <QString>
QString get_process_name(pid_t pid);
class Tracer : public QObject
{
    Q_OBJECT
public:
    explicit Tracer(QObject *parent = nullptr);
    void stop();

public slots:
    // 启动追踪，接收 PID 作为参数
    void start(unsigned int pid);

signals:
    // 当捕获到新的系统调用时，发射此信号
    void newSyscallData(quint64 ts, quint64 duration, long ret, long syscall, unsigned int pid, const QString& comm);
    // 当追踪结束时发射
    void finished(const QString& message);

private:
    volatile bool m_running = false;
};

#endif // TRACER_H
