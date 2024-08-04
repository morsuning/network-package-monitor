#ifndef CHOICE_DEVICE_H

#define CHOICE_DEVICE_H

#include <QDialog>

#include "mainwindow.h"
//extern QString dev_name;

namespace Ui {
  class choice_device;
}

class choice_device : public QDialog
{
  Q_OBJECT

public:
  explicit choice_device(QWidget *parent = 0);
  ~choice_device();

private slots:
  void on_buttonBox_accepted();
  void on_buttonBox_rejected();

signals:
    void sendData(QString);   //用来传递数据的信号

private:
  Ui::choice_device *ui;
};

#endif // CHOICE_DEVICE_H
