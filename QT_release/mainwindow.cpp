#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "tracer.h"
#include <QMessageBox>
#include <QtCharts/QValueAxis>
#include <QDir>
#include <QRegularExpression> // 用于判断目录名是否是数字
#include <QFile>
// 我们需要一个 syscall-number -> name 的映射
#include <QMap>
#include "syscall_map.h"
qint64 get_system_boot_time_epoch_ns() {
    // 当前 UTC 时间（单位 ns）
    qint64 now_epoch_ns = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch() * 1000000LL;

    // 当前 monotonic 时间（单位 ns）
    struct timespec ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    qint64 now_monotonic_ns = ts_now.tv_sec * 1000000000LL + ts_now.tv_nsec;

    // 系统启动时间 = 当前时间 - monotonic 时间
    return now_epoch_ns - now_monotonic_ns;
}
QString formatTimestamp(qint64 nanoseconds) {
    qint64 boot_time_ns = get_system_boot_time_epoch_ns();
    qint64 real_time_ns = boot_time_ns + nanoseconds;

    time_t seconds = real_time_ns / 1000000000LL;
    qint64 remaining_ns = real_time_ns % 1000000000LL;

    // 使用 UTC 时间 + 8 小时得到北京时间
    seconds += 8 * 3600;
    struct tm *timeinfo = gmtime(&seconds);

    char timeStr[32];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);

    return QString("%1.%2").arg(timeStr).arg(QString("%1").arg(remaining_ns, 9, 10, QChar('0')));
}
QString formatDuration(qint64 nanoseconds) {
    const qint64 ns_in_us = 1000;
    const qint64 ns_in_ms = 1000 * ns_in_us;
    const qint64 ns_in_s  = 1000 * ns_in_ms;
    const qint64 ns_in_min = 60 * ns_in_s;

    qint64 minutes = nanoseconds / ns_in_min;
    nanoseconds %= ns_in_min;

    qint64 seconds = nanoseconds / ns_in_s;
    nanoseconds %= ns_in_s;

    qint64 milliseconds = nanoseconds / ns_in_ms;
    nanoseconds %= ns_in_ms;

    qint64 microseconds = nanoseconds / ns_in_us;
    nanoseconds %= ns_in_us;

    QStringList parts;
    if (minutes > 0)
        parts << QString("%1 min").arg(minutes);
    if (seconds > 0)
        parts << QString("%1 s").arg(seconds);
    if (milliseconds > 0)
        parts << QString("%1 ms").arg(milliseconds);
    if (microseconds > 0)
        parts << QString("%1 µs").arg(microseconds);
    if (nanoseconds > 0)
        parts << QString("%1 ns").arg(nanoseconds);

    if (parts.isEmpty())
        parts << "0 ns";

    return parts.join(" ");
}
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_tracer(nullptr)
    , m_tracerThread(nullptr)
    , m_chart(nullptr) // 初始化为空指针
    , m_series(nullptr)
    , m_chartUpdateTimer(nullptr)
    , m_timelineScene(nullptr)
{
    ui->setupUi(this);

    // --- 表格初始化 (不变) ---
    ui->syscallTable->setColumnCount(5);
    ui->syscallTable->setHorizontalHeaderLabels({"PID", "Process", "Syscall Number", "Syscall Name", "Return Value"});
    ui->syscallTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    // --- 时间线场景初始化 (保持简单) ---
    m_timelineScene = new QGraphicsScene(this);
    ui->timelineView->setScene(m_timelineScene);
    ui->timelineView->setDragMode(QGraphicsView::ScrollHandDrag);

    // --- 图表初始化 (只创建最核心的对象) ---
    m_chart = new QChart();
    ui->frequencyChartView->setChart(m_chart); // 将 chart 关联到 view
    ui->frequencyChartView->setRenderHint(QPainter::Antialiasing);

    // --- 定时器初始化 ---
    m_chartUpdateTimer = new QTimer(this);
    connect(m_chartUpdateTimer, &QTimer::timeout, this, &MainWindow::updateFrequencyChart);

    //刷新进程
    populateProcessList();
}

MainWindow::~MainWindow()
{
    if (m_tracerThread && m_tracerThread->isRunning()) {
        m_tracer->stop();
        m_tracerThread->quit();
        m_tracerThread->wait();
    }
    delete ui;
}

void MainWindow::on_startButton_clicked()
{
    if (m_tracerThread && m_tracerThread->isRunning()) {
        m_tracer->stop();
        ui->startButton->setEnabled(false);
        return;
    }

    bool ok;
    unsigned int pid = ui->pidInput->text().toUInt(&ok);
    if (!ok || ui->pidInput->text().isEmpty()) {
        QMessageBox::warning(this, "Invalid PID", "Please enter a valid process ID.");
        return;
    }

    // --- 重置所有UI和数据，为新的追踪做准备 ---

    // 1. 清理旧数据
    m_syscallCounts.clear();
    m_timelineScene->clear();
    m_syscallLaneMap.clear();
    m_nextLane = 0;
    m_timelineStartTs = 0;
    ui->syscallTable->setRowCount(0);

    // 2. 重置图表
    m_chart->removeAllSeries();
    // 先移除旧的坐标轴，以防万一
    for (QAbstractAxis *axis : m_chart->axes()) {
        m_chart->removeAxis(axis);
    }

    m_series = new QBarSeries();
    m_chart->addSeries(m_series);

    m_chart->setTitle("Top 10 System Call Frequency");
    m_chart->setAnimationOptions(QChart::SeriesAnimations);

    // --- 使用新的 API ---
    // 创建坐标轴
    QBarCategoryAxis *axisX = new QBarCategoryAxis();
    QValueAxis *axisY = new QValueAxis();
    axisY->setLabelFormat("%d");
    axisY->setTitleText("Count");

    // 1. 将坐标轴添加到图表，并指定对齐方式
    m_chart->addAxis(axisX, Qt::AlignBottom);
    m_chart->addAxis(axisY, Qt::AlignLeft);

    // 2. 将数据系列附加到坐标轴
    m_series->attachAxis(axisX);
    m_series->attachAxis(axisY);
    m_chart->legend()->setVisible(false);

    // --- 启动追踪线程---
    m_tracerThread = new QThread();
    m_tracer = new Tracer();
    m_tracer->moveToThread(m_tracerThread);

    connect(m_tracerThread, &QThread::started, m_tracer, [this, pid](){ m_tracer->start(pid); });
    connect(m_tracer, &Tracer::finished, this, &MainWindow::onTracingFinished);
    connect(m_tracer, &Tracer::newSyscallData, this, &MainWindow::handleSyscallData);

    m_tracerThread->start();

    // --- 更新UI状态 ---
    ui->startButton->setText("Stop Tracing");
    ui->pidInput->setEnabled(false);
    m_chartUpdateTimer->start(1000); // 启动图表更新定时器
}
// 新的槽函数，用于处理接收到的数据
void MainWindow::handleSyscallData(quint64 ts, quint64 duration, long ret, long syscall, unsigned int pid, const QString& comm)
{
    // --- 更新表格 ---
    int row = ui->syscallTable->rowCount();
    ui->syscallTable->insertRow(row);
    ui->syscallTable->setItem(row, 0, new QTableWidgetItem(QString::number(pid)));
    ui->syscallTable->setItem(row, 1, new QTableWidgetItem(comm));
    ui->syscallTable->setItem(row, 2, new QTableWidgetItem(QString::number(syscall)));

    QString syscallName = getSyscallName(syscall);
    ui->syscallTable->setItem(row, 3, new QTableWidgetItem(syscallName));
    ui->syscallTable->setItem(row, 4, new QTableWidgetItem(QString::number(ret)));

    ui->syscallTable->scrollToBottom();
    QString name = getSyscallName(syscall);
    m_syscallCounts[name]++; // 增加对应系统调用的计数

    // --- 更新时间线 ---
        if (m_timelineStartTs == 0) {
        m_timelineStartTs = ts; // 将第一个事件的时间戳作为时间线的起点
    }
    ui->timelineView->setMouseTracking(true);
    // 为 syscall 分配一个 "泳道" (Y 轴位置)
    if (!m_syscallLaneMap.contains(syscallName)) {
        m_syscallLaneMap[syscallName] = m_nextLane++;
    }
    int lane = m_syscallLaneMap[syscallName];

    // 定义时间线的缩放比例和尺寸
    const double scale = 0.00001; // 100,000 ns = 1 pixel
    const int laneHeight = 20;
    const int laneSpacing = 5;

    // 计算矩形的位置和大小
    double x = (ts - m_timelineStartTs) * scale;
    double y = lane * (laneHeight + laneSpacing);
    double w = (duration > 0) ? (duration * scale) : 2.0; // 持续时间太短的给个最小宽度

    // 创建一个代表该系统调用的矩形
    QGraphicsRectItem *item = new QGraphicsRectItem(x, y, w, laneHeight);

    // 根据系统调用类型设置不同颜色
    QColor color = QColor::fromHsv((syscall * 20) % 360, 200, 230);
    item->setBrush(color);
    item->setPen(Qt::NoPen);

    // 添加工具提示，鼠标悬浮时显示详细信息
    item->setToolTip(QString("Syscall: %1\nStart: %2 \nDuration: %3 ")
                         .arg(syscallName)
                         .arg(formatTimestamp(ts))
                         .arg(formatDuration(duration)));

    m_timelineScene->addItem(item);

    // 自动滚动到最新的事件
    ui->timelineView->ensureVisible(item, 50, 50);
}

// 槽函数，用于处理追踪结束的事件
void MainWindow::onTracingFinished(const QString& message)
{
    m_chartUpdateTimer->stop();
    m_tracerThread->quit();
    m_tracerThread->wait();
    delete m_tracerThread;
    m_tracerThread = nullptr;
    delete m_tracer;
    m_tracer = nullptr;

    ui->startButton->setText("Start Tracing");
    ui->pidInput->setEnabled(true);
    ui->startButton->setEnabled(true);

    if (!message.contains("stopped")) { // 如果不是正常停止，则显示错误信息
        QMessageBox::information(this, "Tracer Finished", message);
    }
}

// 实现新的槽函数 updateFrequencyChart():
void MainWindow::updateFrequencyChart()
{
    m_series->clear(); // 清空旧的条形数据

    // QMap 不方便按值排序，我们复制到一个 QList<QPair> 中
    QList<QPair<QString, int>> sortedCounts;
    for(auto it = m_syscallCounts.constBegin(); it != m_syscallCounts.constEnd(); ++it) {
        sortedCounts.append({it.key(), it.value()});
    }

    // 按计数值降序排序
    std::sort(sortedCounts.begin(), sortedCounts.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });

    // 只取 Top 10
    QStringList categories;
    auto *barSet = new QBarSet("Syscalls");
    int count = 0;
    for(const auto& pair : sortedCounts) {
        if (count++ >= 10) break;
        *barSet << pair.second;
        categories << pair.first;
    }

    m_series->append(barSet);

    // m_chart->axes(Qt::Horizontal) 返回所有水平方向的坐标轴
    // 因为我们只有一个，所以取第一个
    if (!m_chart->axes(Qt::Horizontal).isEmpty()) {
        QBarCategoryAxis *axisX = qobject_cast<QBarCategoryAxis*>(m_chart->axes(Qt::Horizontal).first());
        if (axisX) {
            axisX->clear();
            axisX->append(categories);
        }
    }

    // m_chart->axes(Qt::Vertical) 返回所有垂直方向的坐标轴
    if (!m_chart->axes(Qt::Vertical).isEmpty() && !sortedCounts.isEmpty()) {
        QValueAxis *axisY = qobject_cast<QValueAxis*>(m_chart->axes(Qt::Vertical).first());
        if (axisY) {
            axisY->setRange(0, sortedCounts.first().second);
        }
    }
}
void MainWindow::on_listWidget_itemSelectionChanged()
{
    QList<QListWidgetItem *> selectedItems = ui->listWidget->selectedItems();

    if (!selectedItems.isEmpty()) {
        QListWidgetItem *selectedItem = selectedItems.first();
        // 从 UserRole 中获取 PID
        qint64 pid = selectedItem->data(Qt::UserRole).toLongLong();
        ui-> pidInput->setText(QString::number(pid));
    } else {
        // 如果没有选中项，清空PID输入框
        ui-> pidInput->clear();
    }
}

void MainWindow::populateProcessList()
{
    ui->listWidget->clear();
    m_allProcesses.clear();
    ui-> pidInput->clear();

    QDir procDir("/proc");
    // 过滤出目录，并只获取以数字命名的目录
    QStringList pidDirs = procDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks, QDir::Name);

    // 正则表达式来检查目录名是否完全是数字
    QRegularExpression pidRx("^\\d+$");

    for (const QString& dirName : pidDirs) {
        if (pidRx.match(dirName).hasMatch()) {
            qint64 pid = dirName.toLongLong();
            // 现在调用我们新的辅助函数来获取进程名
            QString processName = get_process_name(pid);
            ProcessInfo info;
            info.name = processName;
            info.pid = pid;
            m_allProcesses.append(info);
        }
    }

    // 填充QListWidget
    if (m_allProcesses.isEmpty()) {
        QListWidgetItem *item = new QListWidgetItem("未找到任何运行中的进程。", ui->listWidget);
        item->setFlags(item->flags() & ~Qt::ItemIsSelectable);
    } else {
        for (int i = 0; i < m_allProcesses.size(); ++i) {
            const ProcessInfo &info = m_allProcesses.at(i);
            QString displayText = QString("%1 (PID: %2)").arg(info.name).arg(info.pid);
            QListWidgetItem *item = new QListWidgetItem(displayText, ui->listWidget);
            item->setData(Qt::UserRole, QVariant::fromValue(info.pid));
        }
    }
}

void MainWindow::on_refreshButton_clicked()
{
    populateProcessList();
}
