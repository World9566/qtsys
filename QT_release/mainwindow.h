#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QtCharts/QChartView>
#include <QtCharts/QBarSeries>
#include <QtCharts/QBarSet>
#include <QtCharts/QBarCategoryAxis>
#include <QTimer>
#include <QGraphicsScene>
#include <QGraphicsRectItem>
// 向前声明 Tracer 类
class Tracer;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE
struct ProcessInfo {
    QString name;
    qint64 pid;
};
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_startButton_clicked();
    void handleSyscallData(quint64 ts, quint64 duration, long ret, long syscall, unsigned int pid, const QString& comm);
    void onTracingFinished(const QString& message);
    void updateFrequencyChart();
    void on_listWidget_itemSelectionChanged();
    void on_refreshButton_clicked();
    void filterProcessList(const QString &text);
private:
    Ui::MainWindow *ui;
    Tracer *m_tracer;
    QThread *m_tracerThread;
    QChart* m_chart;
    QBarSeries* m_series;
    QMap<QString, int> m_syscallCounts;
    QTimer* m_chartUpdateTimer;
    QGraphicsScene* m_timelineScene;
    quint64 m_timelineStartTs = 0;
    // 用一个 map 来给不同类型的 syscall 分配不同的 Y 轴 "泳道"
    QMap<QString, int> m_syscallLaneMap;
    int m_nextLane = 0;
    QList<ProcessInfo> m_allProcesses; // 存储所有进程的列表
    QMap<QString, QGraphicsItem*> m_legendItems;
    void populateProcessList();
};

#endif // MAINWINDOW_H
