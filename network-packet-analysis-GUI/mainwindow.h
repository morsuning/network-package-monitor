#ifndef MAINWINDOW_H


#define MAINWINDOW_H

#include <QMainWindow>
#include <QDialog>
#include <QStandardItemModel>
#include <QTimer>

#include "choice_device.h"
#include "libpcap_thread.h"

namespace Ui {
  class MainWindow;
}

class MainWindow : public QMainWindow
{
  Q_OBJECT

public:

  MainWindow(QWidget *parent = 0);
  ~MainWindow();

private slots:
  void receiveData(QString data);
  void on_Start_clicked();
  void on_Stop_clicked();
  //void msgUpdate();
  void show_detail();
  //void set_color(int num,int color1,int color2,int color3);

signals:
  //doubleClicked(const QModelIndex &);

private:
  Ui::MainWindow *ui;
  libpcap_thread *pcapThread;
  //QTimer *timer;
  QString dev_name;
  QStandardItemModel *libpcap_data;
  int Column = 6;
};

#endif // MAINWINDOW_H
