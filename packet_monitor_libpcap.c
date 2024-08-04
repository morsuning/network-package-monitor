#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

//TODO：带图形界面的抓包程序后端
//TODO：获取网络设备信息
//TODO：读取查看时过滤
//TODO：过滤规则：源IP目的IP源目MAC端口
//TODO：能将捕获的数据报以一种格式存储，可以通过图形程序再次打开并阅读

/**
 * 界面设计：
 * 开始按钮 点击后显示网络接口名字和掩码等信息然后开始抓取
 * 停止按钮 点击后停止抓取
 * 导出 点击后可导出为特定格式的数据包----最好借鉴标准 若有此功能退出时应提示保存
 * 导入 可导入本程序生成的数据包显示出来的效果和即时抓取的一样
 *  下拉菜单选择显示的数据报格式
 *  展示窗口：类似wireshark显示数据报内容
 *  过滤器 可按多种规则过滤显示不同的数据包
 */


/**
 *
    struct pcap_pkthdr
    {
        struct timeval ts; // 抓到包的时间
        bpf_u_int32 caplen; // 表示抓到的数据长度
        bpf_u_int32 len; // 表示数据包的实际长度
    }
 * @param arg
 * @param pkthdr
 * @param packet
 */

// struct ether_header{
//    u_int8_t ether_dhost[6];//目的地址
//    u_int8_t ether_shost[6];//源地址
//    u_int16_t ether_type;//以太网类型
// };

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

void analyzeARP(const u_char* packet)
{
    struct arp_header* arp_protocol;
    u_short protocol_type;
    u_short hardware_type;
    u_short operation_code;
    u_char hardware_length;
    u_char protocol_length;
    //u_char* mac_string;
    arp_protocol = (struct arp_header*) (packet+14);//跳过以太网数据部分
    hardware_type = ntohs(arp_protocol->arp_hardware_type);
    protocol_type = ntohs(arp_protocol->arp_protocol_type);
    operation_code = ntohs(arp_protocol->arp_operation_code);
    hardware_length = arp_protocol->arp_hardware_length;
    protocol_length = arp_protocol->arp_protocol_length;
    printf("ARP Hardware Type:%d\n",hardware_type);
    printf("ARP Protocol Type:%d\n",protocol_type);
    printf("ARP Hardware Length:%d\n",hardware_length);
    printf("ARP Protocol Length:%d\n",protocol_length);
    printf("ARP Operation:%d\n",operation_code);
    switch (operation_code){
        case 1:
            printf("ARP Request Protocol\n");
            break;
        case 2:
            printf("ARP Reply Protocol\n");
            break;
        case 3:
            printf("RARP Request Protocol\n");
            break;
        case 4:
            printf("RARP Reply Protocol\n");
            break;
        default:
            printf("Unknown ARP Protocol\n");
            break;
    }
}

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

void analyzeTCP(const u_char *packet)
{
    struct tcp_header* tcp_protocol;
    u_char flags;
    int header_length;
    u_short source_port;
    u_short destination_port;
    u_short windows;
    u_short urgent_pointer;
    u_int sequence;
    u_int acknowledgement;
    u_int16_t checksum;
    tcp_protocol = (struct tcp_header*)(packet+14+20);//跳过以太网和IP头
    source_port = ntohs(tcp_protocol->tcp_source_port);
    destination_port = ntohs(tcp_protocol->tcp_destination_port);
    header_length = tcp_protocol->tcp_offset * 4;
    sequence = ntohl(tcp_protocol->tcp_acknowledgement);
    acknowledgement = ntohl(tcp_protocol->tcp_ack);
    windows = ntohs(tcp_protocol->tcp_windows);
    urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);
    flags = tcp_protocol->tcp_flags;
    checksum = ntohs(tcp_protocol->tcp_checksum);
    printf("Sequence Number:%u\n",sequence);
    printf("Acknowledgement Number:%u\n",acknowledgement);
    printf("Header Length:%d\n",header_length);
    printf("Reserved:%d\n",tcp_protocol->tcp_reserved);
    printf("Flags:%d\n",flags);
    printf("Windows Size:%d\n",windows);
    printf("Checksum:%d\n",checksum);
    printf("Urgent pointer:%d\n",urgent_pointer);
    printf("Source Port:%d\n",source_port);
    printf("Destination Port:%d\n",destination_port);
    switch (destination_port){
        case 80:
            printf("HTTP protocol\n");
            break;
        case 21:
            printf("FTP protocol\n");
            break;
        case 23:
            printf("TELNET protocol\n");
            break;
        case 25:
            printf("SMTP protocol\n");
            break;
        case 110:
            printf("POP protocol\n");
            break;
        case 443:
            printf("TLS protocol\n");
            break;
        default:
            printf("Unknown Port\n");
            break;
    }
}

struct udp_header{
    u_int16_t udp_source_port;
    u_int16_t udp_destination_port;
    u_int16_t udp_length;
    u_int16_t udp_checksum;
};

void analyzeUDP(const u_char *packet)
{
    struct udp_header* udp_protocol;
    u_short source_port;
    u_short destination_port;
    u_short length;
    udp_protocol = (struct udp_header*)(packet+14+20);
    source_port = ntohs(udp_protocol->udp_source_port);
    destination_port = ntohs(udp_protocol->udp_destination_port);
    length = ntohs(udp_protocol->udp_length);
    printf("Length:%d\n",length);
    printf("Checksum:%d\n",ntohs(udp_protocol->udp_checksum));
    printf("Source port:%d\n",source_port);
    printf("Destination port:%d\n",destination_port);
    switch (destination_port){
        case 138:
            printf("NETBIOS Datagram Service\n");
            break;
        case 137:
            printf("NETBIOS Name Service\n");
            break;
        case 139:
            printf("NETBIOS Session Service\n");
            break;
        case 53:
            printf("name-domain Service\n");
            break;
        default:
            printf("Unknown Service Type\n");
            break;
    }
}

struct icmp_header{
    u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_checksum;
    u_int16_t icmp_id_;
    u_int16_t icmp_sequence;
};

void analyzeICMP(const u_char *packet)
{
    struct icmp_header* icmp_protocol;
    icmp_protocol = (struct icmp_header*)(packet+14+20);
    printf("ICMP Checksum:%d\n",ntohs(icmp_protocol->icmp_checksum));
    printf("ICMP Type:%d\n",icmp_protocol->icmp_type);
    printf("ICMP Code:%d\n",icmp_protocol->icmp_code);
    printf("Identifier:%d\n",icmp_protocol->icmp_id_);
    printf("Sequence Number:%d\n",icmp_protocol->icmp_sequence);
    switch (icmp_protocol->icmp_type){
        case 8:
            printf("ICMP Echo Request Protocol\n");
            break;
        case 0:
            printf("ICMP Echo Reply Protocol\n");
            break;
        default:
            printf("Unknown ICMP Protocol Type\n");
            break;
    }
    
}

struct ip_header{
#ifdef WORDS_BIGENDIAN
    u_int8_t ip_version:4,
    ip_header_length:4;
#else
    u_int8_t  ip_header_length:4,
              ip_version:4;
#endif
    u_int8_t ip_tos;
    u_int16_t ip_length;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int16_t ip_ttl;
    u_int16_t ip_protocol;
    u_int16_t ip_checksum;
    struct in_addr ip_source_address;
    struct in_addr ip_destination_address;
};

void analyzeIP(const u_char *packet)
{
    struct ip_header* ip_protocol;
    struct iphdr* ip;//库定义IP头
    u_int header_length;
    u_int offset;
    u_char tos;
    //u_int16_t checksum;
    ip_protocol = (struct ip_header*)(packet + 14);
    ip = (struct iphdr*)(packet + 14);
    //checksum = ntohs(ip_protocol->ip_checksum);
    header_length = ip_protocol->ip_header_length*(u_int8_t)4;
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_off);
    printf("IP Version:%d\n",ip_protocol->ip_version);
    printf("Header Length:%d\n",header_length);
    printf("Total Length:%d\n",ntohs(ip_protocol->ip_length));
    printf("TOS:%d\n",tos);
    printf("Identification:%d\n",ntohs(ip_protocol->ip_id));
    printf("Offset:%d\n",offset);
    printf("TTL:%d\n",ip_protocol->ip_ttl);
    printf("Header Checksum:%d\n",ip->check);
    printf("Destination Address:%s\n",inet_ntoa(ip_protocol->ip_destination_address));
    printf("Source Address:%s\n",inet_ntoa(ip_protocol->ip_source_address));
    printf("Protocol(Source value):%d\n",ip->protocol);
    switch (ip->protocol){
        case IPPROTO_TCP:
            printf("The Transport Layer Protocol is TCP\n");
            printf("----TCP Protocol (Transport Layer)----\n");
            analyzeTCP(packet);
            break;
        case IPPROTO_UDP:
            printf("The Transport Layer Protocol is UDP\n");
            printf("----UDP Protocol (Transport Layer)----\n");
            analyzeUDP(packet);
            break;
        case IPPROTO_ICMP:
            printf("The Transport Layer Protocol is ICMP\n");
            printf("----ICMP Protocol (Transport Layer)----\n");
            analyzeICMP(packet);
            break;
        default:
            printf("Unknown Transport Layer Protocol(not TCP, UDP or ICMP)\n");
            break;
    }
}

void analyzeETHERNET_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int * id = (int *)arg;

    struct ether_header* ethernet_protocol;
    u_char* mac_string;
    u_short ethernet_type;

    // pcap_dumper_t *file = pcap_dump_open(p, "./tmp.pcap");
    // pcap_dump((u_char*)file,pcap_pkthdr,packet);

    printf("id: %d\n", ++(*id));

    printf("----Ethernet Protocol (Link Layer)----\n");
    printf("Packet Length:%d\n", pkthdr->len);//包长
    printf("Number of Bytes:%d\n", pkthdr->caplen);//实际收到的包长
    printf("Received Time:%s", ctime((const time_t *)&pkthdr->ts.tv_sec));
    ethernet_protocol = (struct ether_header*)packet;

    mac_string = (u_char*)ethernet_protocol->ether_shost;//源mac地址
    printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),
           *(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    mac_string = (u_char*)ethernet_protocol->ether_dhost;//获取目的mac
    printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),
           *(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));

    ethernet_type = ntohs(ethernet_protocol->ether_type);
    //printf("协议类型（原始）：%04x\n",ethernet_type);
    printf("上层协议类型：\n");
    switch (ethernet_type){
        case ETHERTYPE_IP/*0x0800*/:
            printf("----IP Protocol (Network Layer)----\n");
            analyzeIP(packet);
            break;
        case ETHERTYPE_ARP/*0x0806*/:
            printf("----ARP Protocol (Network Layer)----\n");
            analyzeARP(packet);
            break;
        case 0x8035:
            printf("----RARP Protocol (Network Layer)----\n");
            analyzeARP(packet);
            break;
        default:
            printf("Unknown Network Layer Protocol(not IP, ARP or RARP)\n");
            break;
    }

    printf("Source Packet:\n");
    for(int i=0; i<pkthdr->len; ++i) {
        printf(" %02x", packet[i]);
        if( (i + 1) % 16 == 0 ) {
            printf("\n");
        }
    }
    printf("\n\n");
}

int main()
{
    //定义错误信息、接口地址、IP地址和掩码地址
    char error_content[PCAP_ERRBUF_SIZE], * net_interface, * net_ip_string, * net_mask_string;
    u_int32_t net_ip,net_mask;

    struct in_addr net_ip_address;
    struct in_addr net_mask_address;

    net_interface = pcap_lookupdev(error_content);//获取单个接口<---------
    if(!net_interface) {
        printf("error: %s\n", error_content);
        exit(1);
    }

//    pcap_if_t* alldevs;
//    if((pcap_findalldevs(&alldevs,error_content))==-1) {//获取全部网络设备,未使用
//        fprintf(stderr,"Errof in pcap_findalldevs_ex:%s\n",error_content);
//        exit(1);
//    }

    /*printf the device_list*/
//    for(d=alldevs;d!=NULL;d=d->next)
//    {
//        printf("\n%s\n",d->name);
//
//    }
//    pcap_freealldevs(alldevs);

    pcap_lookupnet(net_interface,&net_ip,
                                    &net_mask,error_content);//获取对应接口的网络地址和掩码
    net_ip_address.s_addr = net_ip;
    net_ip_string = inet_ntoa(net_ip_address);//获取IP地址
    net_mask_address.s_addr = net_mask;
    net_mask_string = inet_ntoa(net_mask_address);//获取掩码<----------
    printf("接口：%s\n",net_interface);//输出接口
    printf("掩码：%s\n",net_mask_string);//输出掩码

    struct pcap_pkthdr protocol_header;//数据包头
    struct bpf_program bpf_filter;//bpf过滤规则
    char bpf_filter_string[] = "ip";

    int mode;
    printf("是否设置混杂模式：0--yes,1--no\n");
    scanf("%d",&mode);

    pcap_t* live_device = pcap_open_live(net_interface,65535,1,0,error_content);//句柄BUFIZ=8192
    if(!live_device){
        fprintf(stderr,"error:pcap_open_live():%s\n",error_content);
        exit(-1);
    }

//    pcap_compile(live_device,//接口
//                 &bpf_filter,//BPF过滤规则
//                 bpf_filter_string,//过滤规则字符串
//                 0,//优化参数
//                 net_ip);//网络地址

    int packet_num;
    printf("请输入要抓取的数据包个数：\n");
    scanf("%d",&packet_num);

    int id = 0;
    pcap_loop(live_device, packet_num, analyzeETHERNET_callback, (u_char *) &id);

    return 0;
}