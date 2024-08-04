#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "choice_device.h"
#include<QDebug>
//#include "extern.h"

QStandardItemModel* model;
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  ui->setupUi(this);

  choice_device device;
  QDialog *dlg = &device;
  device.setModal(true);
  connect(dlg,SIGNAL(sendData(QString)),this,SLOT(receiveData(QString)));
  device.exec();

  ui->packet_info->setEditTriggers(QAbstractItemView::NoEditTriggers);//meihang neirong buke bianji
  ui->packet_info->setSelectionMode(QAbstractItemView::SingleSelection);//yici xuanze yihang
  ui->packet_info->setSelectionBehavior(QAbstractItemView::SelectRows);//danji xuanze yihang
  ui->packet_info->horizontalHeader()->setStretchLastSection(true);//lietou zishiying kuandu zuihou yilie tianchong kongbai
  //ui->packet_info->setRowHeight(row_index,24);
  ui->packet_info->verticalHeader()->hide();//yinchang hangtou
  ui->netinfo_label->setText("Device:"+this->dev_name);
  //ui->packet_info->setContextMenuPolicy(Qt::CustomContextMenu);//<<<<<<<<<<<<<youjian caidan
  libpcap_data = new QStandardItemModel();
  libpcap_data->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("No.")));
  //libpcap_data->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("Time")));
  libpcap_data->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("Source")));
  libpcap_data->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("Destination")));
  libpcap_data->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("Protocol")));
  libpcap_data->setHorizontalHeaderItem(4, new QStandardItem(QObject::tr("Length")));
  libpcap_data->setHorizontalHeaderItem(5, new QStandardItem(QObject::tr("Info")));
  ui->packet_info->setModel(libpcap_data);

  ui->packet_info->setColumnWidth(0,8);
  ui->packet_info->setColumnWidth(4,10);
  ui->packet_info->setColumnWidth(5,600);

//  this->timer = new QTimer;
//  connect(timer,SIGNAL(timeout()),
//          this,SLOT(msgUpdate()));

  connect(ui->packet_info,&QTableView::clicked,this,&MainWindow::show_detail);
}

MainWindow::~MainWindow()
{
  delete ui;
}

void MainWindow::receiveData(QString data)
{
  this->dev_name = data;
}

void MainWindow::on_Start_clicked()
{
  pcapThread = new libpcap_thread(dev_name,libpcap_data);

  //qDebug()<<dev_name;
  ui->netinfo_label->setText("Device:"+this->dev_name+"\tDevice IP:"+pcapThread->localIP/*+"\t\tPacket:"
                             +QString::number(packet_number)*/);
  pcapThread->start();//抓包线程启动
  //timer->start(1000);//界面刷新
  //qDebug()<<" Please ensure that this program runs in root authority!";
}

void MainWindow::on_Stop_clicked()
{
  pcapThread->terminate();
  qDebug()<<"stop";
}

//void MainWindow::set_color(int num,int color1,int color2,int color3)
//{
//  for(int i = 0;i < Column;i++){
//      libpcap_data->item(num,i)->setForeground(QBrush(QColor(color1,color2,color3)));
//    }
//}

void MainWindow::show_detail()
{
  QModelIndex index;
  index = ui->packet_info->currentIndex();
  index.row();
  //qDebug()<<index.row();
  ui->source_packet->setText(pcapThread->data.at(index.row()).show);
}


