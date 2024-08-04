#include "choice_device.h"
#include "ui_choice_device.h"
//#include "extern.h"

#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <QDebug>
#include <string.h>
#include <QMap>
#include <QThread>

choice_device::choice_device(QWidget *parent) :
  QDialog(parent),
  ui(new Ui::choice_device)
{
  ui->setupUi(this);
  pcap_if_t *all_devs;
  int i=0;//shebei bianhao
  char errbuf[PCAP_ERRBUF_SIZE];
  if (pcap_findalldevs(&all_devs, errbuf) == -1) {/* 获取当前计算机的所有网络设备 */
      ui->dev_list->insertItem(0,"");
      //qDebug()<<"未找到设备，请确认此程序在root权限下运行!";
  }
  for(pcap_if_t* d = all_devs; d; d=d->next) {//print list
      ui->dev_list->insertItem(i++,d->name);
  }
  pcap_freealldevs(all_devs);
}

choice_device::~choice_device()
{
  delete ui;
}

void choice_device::on_buttonBox_accepted()
{
    emit sendData(ui->dev_list->currentItem()->text());
    //qDebug()<<ui->dev_list->currentItem()->text();
    close();
}

void choice_device::on_buttonBox_rejected()
{
    close();
}
