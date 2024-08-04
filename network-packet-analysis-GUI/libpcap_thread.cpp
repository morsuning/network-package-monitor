#include "libpcap_thread.h"
#include <qdebug.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

libpcap_thread::libpcap_thread(QString dev_name,QStandardItemModel* libpcap_data)
{
  this->libpcap_data = libpcap_data;
  char* net_interface;
  QByteArray QBA2chr = dev_name.toLatin1();
  net_interface = QBA2chr.data();//device name choosed
  struct ifaddrs * if_addr = NULL;//Socket dizhijiegou
  void* tmp_addr = NULL;
  if(getifaddrs(&if_addr))//huoqu benji IP dizhi
      localIP = QString("获取失败");
  while (if_addr!=NULL) {
      if ((if_addr->ifa_addr->sa_family == AF_INET  ) && (QString(if_addr->ifa_name) == dev_name)) {
          tmp_addr = &((struct sockaddr_in *)if_addr->ifa_addr)->sin_addr;
          char addressBuffer[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, tmp_addr, addressBuffer, INET_ADDRSTRLEN);
          localIP = QString(addressBuffer);//benji IP dizhi
          break;
      }
      if(if_addr!=NULL) if_addr = if_addr->ifa_next;
  }

  char error_content[PCAP_ERRBUF_SIZE];

  //char *net_interface;

  //struct bpf_program bpf_filter;

  bpf_u_int32 net_mask;

  bpf_u_int32 net_ip;

  //net_interface = pcap_lookupdev(error_content);

  pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);

  pcap_handle = pcap_open_live(net_interface, 65535, 1, 0, error_content);//BUFSIZ == 8192
  if(!pcap_handle){
    qDebug() << "error:pcap_open_live():\n";
    exit(-1);
  }

  //pcap_compile(pcap_handle, &bpf_filter, fpCode.toLatin1().data(), 0, net_ip);

  //pcap_setfilter(pcap_handle, &bpf_filter);

  packet_number = 0;
  packet_number2 = 1;
}

void libpcap_thread::analyzeETHERNET_callback(const u_char *packet,struct pcap_pkthdr *pcap_pkthdr)
{
  u_short ethernet_type;
  struct ether_header *ethernet_protocol = (struct ether_header*)packet;
  struct tmpinfo tmp;

  tmp.show += QString("------Ethernet Protocol (Link Layer)------\n");
  tmp.show += QString("Packet length:"+QString::number(pcap_pkthdr->len)+"\n");
  tmp.show += QString("Number of bytes:"+QString::number(pcap_pkthdr->caplen)+"\n");
  tmp.show += QString("Received time:"+QString(ctime((const time_t *)&pcap_pkthdr->ts.tv_sec)));
  u_char* mac_string = (u_char*)ethernet_protocol->ether_shost;
  tmp.show += QString("Mac Source Address is: "+QString::number(mac_string[0]+mac_string[1],16)+":"
      +QString::number(mac_string[2]+mac_string[3],16)+":"+QString::number(mac_string[4]+mac_string[5],16)+":"
      +QString::number(mac_string[6]+mac_string[7],16)+":"+QString::number(mac_string[8]+mac_string[9],16)+":"
      +QString::number(mac_string[10]+mac_string[11],16)+"\n");
  mac_string = ethernet_protocol->ether_dhost;
  tmp.show += QString("Mac Destination Address is: "+QString::number(mac_string[0]+mac_string[1],16)+":"
      +QString::number(mac_string[2]+mac_string[3],16)+":"+QString::number(mac_string[4]+mac_string[5],16)+":"
      +QString::number(mac_string[6]+mac_string[7],16)+":"+QString::number(mac_string[8]+mac_string[9],16)+":"
      +QString::number(mac_string[10]+mac_string[11],16)+"\n\n");

  tmp.index = QString::number(packet_number2);
  tmp.length = QString::number(pcap_pkthdr->caplen);
  packet_number2++;
  ethernet_type = ntohs(ethernet_protocol->ether_type);
  switch (ethernet_type) {
  case 0x0800://IP
      tmp.show += QString("------IP Protocol (Network Layer)------\n");
      analyzeIP(packet,tmp);
      break;
  case 0x8035://RARP
      tmp.show += QString("------RARP Protocol (Network Layer)------\n");
      analyzeARP(packet,tmp);
      break;
  case 0x8006://ARP
      tmp.show += QString("------ARP Protocol (Network Layer)------\n");
      analyzeARP(packet,tmp);
      break;
  default:
      tmp.type = QString("Unknown Network Layer Protocol");
      tmp.show += QString("------Unknown Protocol (Network Layer)------\n");
      //qDebug()<<"Unknown(not IP, ARP or RARP)\n";//<<<<<<<<<<<<<<<<<<<<<
      data.append(tmp);
      break;
  }
}

void libpcap_thread::analyzeIP(const u_char *packet,struct tmpinfo tmp)
{
  struct ip_header *ip_protocol = (struct ip_header*)(packet + 14);
  tmp.sIP = QString(inet_ntoa(ip_protocol->ip_souce_address));
  tmp.dIP = QString(inet_ntoa(ip_protocol->ip_destination_address));

  tmp.show += QString("IP Version:"+QString::number(ip_protocol->ip_version)+"\n");
  tmp.show += QString("Header Length"+QString::number(ip_protocol->ip_header_length*(u_int8_t)4)+"\n");
  tmp.show += QString("Totol Length:"+QString::number(ntohs(ip_protocol->ip_length))+"\n");
  tmp.show += QString("TOS:"+QString::number(ip_protocol->ip_tos)+"\n");
  tmp.show += QString("Identification:"+QString::number(ntohs(ip_protocol->ip_id))+"\n");
  tmp.show += QString("Offset:"+QString::number(ntohs(ip_protocol->ip_off))+"\n");
  tmp.show += QString("TTL:"+QString::number(ip_protocol->ip_ttl)+"\n");
  tmp.show += QString("Header Checksum:"+QString::number(ip_protocol->ip_checksum)+"\n");
  tmp.show += QString("Destination Address:"+QString(inet_ntoa(ip_protocol->ip_destination_address))+"\n");
  tmp.show += QString("Source Address:"+QString(inet_ntoa(ip_protocol->ip_souce_address))+"\n");
  tmp.show += QString("Protocol(Source value):"+QString::number(ip_protocol->ip_protocol)+"\n\n");

  switch (ip_protocol->ip_protocol) {
    case IPPROTO_TCP:
        tmp.type = QString("TCP");
        tmp.show += QString("------TCP Protocol (Transport Layer)------\n");
        analyzeTCP(packet,tmp);
        break;
    case IPPROTO_UDP:
        tmp.type = QString("UDP");
        tmp.show += QString("------UDP Protocol (Transport Layer)------\n");
        analyzeUDP(packet,tmp);
        break;
    case IPPROTO_ICMP:
        tmp.type = QString("ICMP");
        tmp.show += QString("------ICMP Protocol (Transport Layer)------\n");
        analyzeICMP(packet,tmp);
        break;
    default:
        tmp.type = QString("Unknown Transport Layer Protocol");
        tmp.show += QString("------Unknown Protocol (Transport Layer)------\n");
        //printf("Unknown Transport Layer Protocol(not TCP, UDP or ICMP)\n");
        data.append(tmp);
        break;
    }
}

void libpcap_thread::analyzeARP(const u_char *packet,struct tmpinfo tmp)
{
  struct arp_header* arp_protocol;
  arp_protocol = (struct arp_header*) (packet+14);

  tmp.show += QString("ARP Hardware Type:"+QString::number(ntohs(arp_protocol->arp_hardware_type))+"\n");
  tmp.show += QString("ARP Protocol Type:"+QString::number(ntohs(arp_protocol->arp_protocol_type))+"\n");
  tmp.show += QString("ARP Hardware Length:"+QString::number(arp_protocol->arp_hardware_length)+"\n");
  tmp.show += QString("ARP Protocol Type:"+QString::number(arp_protocol->arp_protocol_length)+"\n");
  tmp.show += QString("ARP Operation:"+QString::number(ntohs(arp_protocol->arp_operation_code))+"\n\n");

  switch (ntohs(arp_protocol->arp_operation_code)) {
    case 1:
      tmp.info += QString("ARP Request Protocol  ");
      break;
    case 2:
      tmp.info += QString("ARP Reply Protocol  ");
      break;
    case 3:
      tmp.info += QString("RARP Request Protocol  ");
      break;
    case 4:
      tmp.info += QString("RARP Reply Protocol  ");
      break;
    default:
      tmp.info += QString("Unknown ARP Protocol  ");
      break;
    }

  data.append(tmp);
}

void libpcap_thread::analyzeTCP(const u_char *packet,struct tmpinfo tmp)
{
  struct tcp_header* tcp_protocol;
  tcp_protocol = (struct tcp_header*)(packet+14+20);

  tmp.show += QString("Source Port:"+QString::number(ntohs(tcp_protocol->tcp_source_port))+"\n");
  tmp.show += QString("Destination Port:"+QString::number(ntohs(tcp_protocol->tcp_destination_port))+"\n");
  tmp.show += QString("Sequence Number:"+QString::number
                      (ntohl(tcp_protocol->tcp_acknowledgement))+"\n");
  tmp.show += QString("Acknowledgement Number:"+QString::number(ntohs(tcp_protocol->tcp_source_port))+"\n");
  tmp.show += QString("Header Length:"+QString::number(ntohl(tcp_protocol->tcp_ack))+"\n");
  tmp.show += QString("Reserved:"+QString::number(tcp_protocol->tcp_reserved)+"\n");
  tmp.show += QString("Flags:"+QString::number(tcp_protocol->tcp_flags)+"\n");
  tmp.show += QString("Windows Size:"+QString::number(ntohs(tcp_protocol->tcp_windows))+"\n");
  tmp.show += QString("Checksum:"+QString::number(ntohs(tcp_protocol->tcp_checksum))+"\n");
  tmp.show += QString("Urgent pointer:"+QString::number(ntohs(tcp_protocol->tcp_urgent_pointer))+"\n\n");

  switch (ntohs(tcp_protocol->tcp_destination_port)) {
    case 80:
      tmp.info += QString("HTTP Protocol  ");
      break;
    case 21:
      tmp.info += QString("FTP Protocol  ");
      break;
    case 23:
      tmp.info += QString("TELNET Protocol  ");
      break;
    case 25:
      tmp.info += QString("SMTP Protocol  ");
      break;
    case 110:
      tmp.info += QString("POP Protocol  ");
      break;
    case 443:
      tmp.info += QString("TLS Protocol  ");
      break;
    default:
      tmp.info += QString("Unknown Port  ");
      break;
    }
  data.append(tmp);
}

void libpcap_thread::analyzeUDP(const u_char *packet,struct tmpinfo tmp)
{
  struct udp_header* udp_protocol;
  udp_protocol = (struct udp_header*)(packet+14+20);

  tmp.show += QString("Source Port:"+QString::number(ntohs(udp_protocol->udp_source_port))+"\n");
  tmp.show += QString("Destination Port:"+QString::number(ntohs(udp_protocol->udp_destination_port))+"\n");
  tmp.show += QString("Length:"+QString::number(ntohs(udp_protocol->udp_length))+"\n");
  tmp.show += QString("Checksum:"+QString::number(ntohs(udp_protocol->udp_checksum))+"\n");

  switch (ntohs(udp_protocol->udp_destination_port)) {
    case 138:
      tmp.info += QString("NETBIOS Datagram Service  ");
      break;
    case 137:
      tmp.info += QString("NETBIOS Name Service  ");
      break;
    case 139:
      tmp.info += QString("NETBIOS Session Service  ");
      break;
    case 53:
      tmp.info += QString("name-domain Service  ");
      break;
    default:
      tmp.info += QString("Unknown Service Type  ");
      break;
  }
  data.append(tmp);
}

void libpcap_thread::analyzeICMP(const u_char *packet,struct tmpinfo tmp)
{
  struct icmp_hdr* icmp_head= (struct icmp_hdr*)(packet + 14 + 20);
  icmp_echo_hdr* echo_head = (icmp_echo_hdr *) (packet + 14 + 20);

  tmp.show += QString("ICMP Code:"+QString::number(icmp_head->code)+"\n");
  tmp.show += QString("ICMP Checksum:"+QString::number(ntohs(icmp_head->chk_sum))+"\n");
  tmp.show += QString("Identifier:"+QString::number(echo_head->id)+"\n");
  tmp.show += QString("Sequence Number:"+QString::number(echo_head->seq)+"\n");

  switch(icmp_head->icmp_type) {
    case 0:
      tmp.info += QString("ICMP Echo Reply Protocol  ");

      break;
    case 3:
      tmp.info += QString("Destination Unreachable  ");
      break;
    case 8:
      tmp.info += QString("ICMP Echo Request Protocol  ");
      break;
    default:
      tmp.info += QString("Unknow ICMP Protocol Type  ");
      break;
  }
  data.append(tmp);
}

void libpcap_thread::run()
{

  pcap_dumper_t *file = pcap_dump_open(pcap_handle, "./tmp.pcap");

  while((res = pcap_next_ex(pcap_handle,&pcap_pkthdr,&packet_content)) >= 0){
      //qDebug()<<"thread is running";
      if(res == 0)//chaoshi
          continue;

      pcap_dump((u_char*)file,pcap_pkthdr,packet_content);
      //pcap_dump_close(file);
      analyzeETHERNET_callback(packet_content,pcap_pkthdr);

      QVector<struct tmpinfo>::iterator itr = data.begin();
      while(itr != data.end()) {
    //      if(itr->type == QString("TCP")){
    //          set_color(row,255,0,0);
    //        }else if(itr->type == QString("UDP")){
    //          set_color(row,0,0,255);
    //        }else if(itr->type == QString("ICMP")){
    //          set_color(row,0,255,0);
    //        }
        libpcap_data->setItem(packet_number,0,new QStandardItem(itr->index));
        libpcap_data->setItem(packet_number,1,new QStandardItem(itr->sIP));
        libpcap_data->setItem(packet_number,2,new QStandardItem(itr->dIP));
        libpcap_data->setItem(packet_number,3,new QStandardItem(itr->type));
        libpcap_data->setItem(packet_number,4,new QStandardItem(itr->length));
        libpcap_data->setItem(packet_number,5,new QStandardItem(itr->info));
        itr++;
        }
      packet_number++;
  }
}

