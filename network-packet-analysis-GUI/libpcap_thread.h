#ifndef LIBPCAP_H
#define LIBPCAP_H

#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>
#include <QMap>
#include <arpa/inet.h>
#include <QThread>
#include <QVector>
#include <QStandardItemModel>

class libpcap_thread : public QThread
{
public:
  libpcap_thread(QString dev_name,QStandardItemModel* libpcap_data);
  int packet_number;
  int packet_number2;
  QVector<struct tmpinfo> data;
  QString localIP;
private:
    void analyzeETHERNET_callback(const u_char *packet,struct pcap_pkthdr *pcap_pkthdr);
    void analyzeIP(const u_char *packet_content,struct tmpinfo tmp);
    void analyzeARP(const u_char *packet_content,struct tmpinfo tmp);
    void analyzeTCP(const u_char *packet_content,struct tmpinfo tmp);
    void analyzeUDP(const u_char *packet_content,struct tmpinfo tmp);
    void analyzeICMP(const u_char *packet_content,struct tmpinfo tmp);
    pcap_t *pcap_handle;
    int res;
    struct pcap_pkthdr *pcap_pkthdr;
    const u_char *packet_content;
    QStandardItemModel* libpcap_data;
protected:
    void run();
signals:
    void done(void);
};

#endif // LIBPCAP_H

struct ether_header
{
    u_int8_t ether_dhost[6];
    /* 目的以太网地址 */
    u_int8_t ether_shost[6];
    /* 源以太网地址 */
    u_int16_t ether_type;
    /* 以太网类型 */
};

struct ip_header
{
#ifdef WORDS_BIGENDIAN
    u_int8_t ip_version: 4,  /* IP协议版本 */
        ip_header_length: 4; /* IP协议首部长度 */
#else
    u_int8_t ip_header_length: 4, ip_version: 4;
#endif
    u_int8_t ip_tos;
    /* TOS服务质量 */
    u_int16_t ip_length;
    /* 总长度 */
    u_int16_t ip_id;
    /* 标识 */
    u_int16_t ip_off;
    /* 偏移 */
    u_int8_t ip_ttl;
    /* 生存时间 */
    u_int8_t ip_protocol;
    /* 协议类型 */
    u_int16_t ip_checksum;
    /* 校验和 */
    struct in_addr ip_souce_address;
    /* 源IP地址 */
    struct in_addr ip_destination_address;
    /* 目的IP地址 */
};

struct tmpinfo
{
    QString sIP;
    QString dIP;
    QString type;
    QString length;
    QString index;
    QString info = "";
    QString show = "";
    //int count;
};

struct icmp_hdr
{
   unsigned char icmp_type;   //类型
   unsigned char code;        //代码
   unsigned short chk_sum;    //16位检验和
};

struct icmp_echo_hdr
{
    icmp_hdr base_hdr;
    unsigned short id;
    unsigned short seq;
};

struct icmp_error_hdr
{
    icmp_hdr base_hdr;
    unsigned long unused;
};

struct arp_header{
    u_int16_t arp_hardware_type;
    u_int16_t arp_protocol_type;
    u_int8_t arp_hardware_length;
    u_int8_t arp_protocol_length;
    u_int16_t arp_operation_code;
    u_int8_t arp_source_ethernet_address[6];
    u_int8_t arp_source_ip_address[4];
    u_int8_t arp_arp_destination_ethernet_address[6];
    u_int8_t arp_destination_ip_address[4];
};

struct tcp_header{
    u_int16_t tcp_source_port;
    u_int16_t tcp_destination_port;
    u_int32_t tcp_acknowledgement;
    u_int32_t tcp_ack;
#ifdef WORDS_BIGENGIAN
    u_int8_t tcpoffset:4,
        tcp_reserved:4;
#else
    u_int8_t tcp_reserved:4,
            tcp_offset:4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows;
    u_int16_t tcp_checksum;
    u_int16_t tcp_urgent_pointer;
};

struct udp_header{
    u_int16_t udp_source_port;
    u_int16_t udp_destination_port;
    u_int16_t udp_length;
    u_int16_t udp_checksum;
};
