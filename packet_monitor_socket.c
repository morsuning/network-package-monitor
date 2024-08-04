/*
 * @Author: morsuning
 * @Date: 2018-12-19 22:49:42 
 * @Last Modified by: morsuning
 * @Last Modified time: 2018-12-20 09:15:21
 */

// 本程序仅限Linux操作系统运行

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h> // getopt
#include <termios.h>

#include <pthread.h> // 编译时加-pthread或-lpthread

#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>

// 各种协议结构体包含在的头文件
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define MAXSIZE 8192
#define ON 1
#define OFF 0
#define OPTION_NUM 10

enum
{
    HELP,
    STATISTICS,
    FIND,
    PACKET,
    PROTOCOL,
    IP,
    PORT,
    SOURCE,
    DESTINATION,
    MAC
};

// 两个线程协商终止信号
int terminate = 0;

typedef struct statistics_info
{
    int packet_count; // 包数
    int packet_bytes_count;
    double bit_speed; // bit速度

    int mac_broad_count; // Mac 广播帧
    int mac_short_count; // <64
    int mac_long_count;  // >1518
    int mac_bytes_count;
    int mac_packet_count;

    //double mac_bytes_speed;
    double mac_packet_speed;

    //int ip_broadcast_count;
    //int ip_bytes_count;
    int ip_packet_count;
    double ip_precent;

    int tcp_packet_count;
    double tcp_precent;

    int udp_packet_count;
    double udp_precent;

    int icmp_packet_count;
    int icmp_redirect_count;     // icmp_type 5
    int icmp_unreachable_count;  // icmp_type 3 且仅在icmp_code为0 1 2 3 11 12是不可达，其他为失败
    int icmp_echo_reply_count;   // icmp_type 0
    int icmp_echo_request_count; // icmp_type 8
    double icmp_precent;

    int arp_packet_count;
    double arp_precent;

} statistics_info;

// 定义了被过滤的值，会被初始化为0，故若
typedef struct options
{
    // short is_empty[5]; // is_empty该位为1表示有效，顺序为该结构体的顺序
    int protocol;         // 协议 0-4 分别是ARP IP UDP TCP ICMP
    in_addr_t ip_in_addr; // inet_addr 和inet_ntoa完成字符串和in_addr结构体的互换
    u_short port;
    u_char mac[6];
    short part; // 0表示源 1表示目的
} options;

typedef struct statistics_time
{
    // 开始和结束时间
    char start_time[19];
    char end_time[19];
    time_t start;
} statistics_time;

typedef struct options_and_statistics_info
{
    statistics_info *d;
    options *o;
    statistics_time *t;
    int opts[OPTION_NUM];
} options_and_statistics_info;

struct sockaddr_ip
{
    u_short port;
    in_addr_t ip;
};

// 网络发现模块
void discover_device();
void find_device(u_char *mac, int *device_num, u_char *device_mac[], int *find_num);
int is_exist(u_char *mac, int *device_num, u_char *device_mac[]);
char *mac_ntoa(u_char *d);

// 统计与过滤模块
void statistics_with_filter(options *cur_opt, int *opts);
int init_socket(struct sockaddr_ip *sa_ip);
void print_result(statistics_info *result, statistics_time *cur_time);
void statistics(u_char *packet, statistics_info *statistics_info, options *options, int *opts);
void *wait_commond();
void *collect_packet(void *para);

// 底层模块
void print_packet();
void print_ethernet(struct ether_header *eth);
void print_arp(struct ether_arp *arp);
void print_ip(struct ip *ip);
void print_icmp(struct icmp *icmp);
void print_tcp(struct tcphdr *tcp);
void print_tcp_mini(struct tcphdr *tcp);
void print_udp(struct udphdr *udp);
char *tcp_ftoa(int flag);
char *ip_ttoa(int flag);
char *ip_ftoa(int flag);

char getch();
void print_help(char *cmd);

// 主程序初始化选项，初始化socket，创建统计单元（结构体)，
// 根据选项，进行相应的统计，记录开始和结束时间，多线程，一个线程抓包分析一个线程等待命令，输入q终止，打印统计信息
int main(int argc, char *const argv[])
{

    int opts[OPTION_NUM];
    memset(opts, 0, sizeof(opts));
    options *cur_opt = (options *)malloc(sizeof(options));
    bzero(cur_opt, sizeof(options));
    // 解析选项并初始化选择和选项参数 getopt
    // -h 帮助 -s 统计 -f 网络发现 -n 显示抓到的包信息--依协议层次
    // -r <协议> 过滤协议 -i <IP> 过滤IP -p <端口> 过滤端口 -o 过滤源 -d 过滤目的 -m <MAC> 过滤MAC
    // 协议 ARP IP UDP TCP ICMP
    // -h -f -n -s四个选项同时只能开启一项 其中-s可以使用过滤选项-r -i -p -o -d -m
    int opt;
    if (argc == 1)
    {
        print_help(argv[0]);
    }
    while ((opt = getopt(argc, argv, "n::h::sf::odp:r:i:p:m:")) != EOF)
    {
        switch (opt)
        {
        case 'h':
            opts[HELP] = ON;
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
        case 's':
            if (opts[FIND] == ON || opts[PACKET] == ON)
            {
                fprintf(stderr, "Exclusive Option\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }
            else
            {
                opts[STATISTICS] = ON;
            }
            break;
        case 'f':
            if (opts[STATISTICS] == ON || opts[PACKET] == ON)
            {
                fprintf(stderr, "Exclusive Option\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }
            else
            {
                opts[FIND] = ON;
            }
            break;
        case 'n':
            if (opts[STATISTICS] == ON || opts[FIND] == ON)
            {
                fprintf(stderr, "Exclusive Option\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }
            else
            {
                opts[PACKET] = ON;
            }
            break;
        case 'r':
            opts[PROTOCOL] = ON;
            if (memcmp(optarg, "arp", 3) == 0)
            {
                cur_opt->protocol = 0;
            }
            else if (memcmp(optarg, "ip", 2) == 0)
            {
                cur_opt->protocol = 1;
            }
            else if (memcmp(optarg, "udp", 3) == 0)
            {
                cur_opt->protocol = 2;
            }
            else if (memcmp(optarg, "tcp", 3) == 0)
            {
                cur_opt->protocol = 3;
            }
            else if (memcmp(optarg, "icmp", 4) == 0)
            {
                cur_opt->protocol = 4;
            }
            else
            {
                fprintf(stderr, "Unknow Protocol: %s\n", optarg);
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;
        case 'i':
            if (INADDR_NONE == inet_addr(optarg))
            {
                // IP不合法
                fprintf(stderr, "Illegal IP Address: %s\n", optarg);
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }
            else
            {
                opts[IP] = ON;
                cur_opt->ip_in_addr = inet_addr(optarg);
            }
            break;
        case 'p':
            if (atoi(optarg) == 0)
            {
                // 未输入数字
                fprintf(stderr, "Illegal Input: %s\n", optarg);
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }
            else
            {
                int port = atoi(optarg);
                if (port > 65535 || port <= 0)
                {
                    fprintf(stderr, "Illegal Port: %d\n", port);
                    print_help(argv[0]);
                    exit(EXIT_FAILURE);
                }
                else
                {
                    opts[PROTOCOL] = ON;
                    cur_opt->port = (short)port;
                }
            }
            break;
        case 'o':
            opts[SOURCE] = ON;
            cur_opt->part = 0;
            break;
        case 'd':
            opts[DESTINATION] = ON;
            cur_opt->part = 1;
            break;
        case 'm':
            opts[MAC] = ON;
            memcpy(cur_opt->mac, optarg, 6);
            break;
        default:
            fprintf(stderr, "Unknow Or Invalid Option: -%c\n", (char)optopt);
            print_help(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // 根据选择，决定根据信息运行哪些程序
    if (opts[FIND] == ON)
    {
        discover_device();
    }
    else if (opts[STATISTICS] == ON)
    {
        statistics_with_filter(cur_opt, opts);
    }
    else if (opts[PACKET] == ON)
    {
        print_packet();
    }

    return 0;
}

// 根据过滤信息统计相应的数据
void statistics_with_filter(options *cur_opt, int *opts)
{
    // 初始化每次运行程序需要的信息，统计数据和时间
    statistics_time *cur_time = (statistics_time *)malloc(sizeof(statistics_time));
    statistics_info *cur_data = (statistics_info *)malloc(sizeof(statistics_info));
    bzero(cur_time, sizeof(statistics_time));
    bzero(cur_data, sizeof(statistics_info));

    // 将指向信息的指针封装进结构体方便多线程调用
    options_and_statistics_info *oas_info = (options_and_statistics_info *)malloc(sizeof(options_and_statistics_info));
    oas_info->d = cur_data;
    oas_info->o = cur_opt;
    oas_info->t = cur_time;
    memcpy(oas_info->opts, opts, sizeof(oas_info->opts));

// 多线程，一个线程负责抓包并统计，一个线程负责等待命令同时能通知另一个线程
#define NUM_THREADS 2
    pthread_t threads[NUM_THREADS];
    // 参数依次是：创建的线程id，线程参数，调用的函数，传入的函数参数
    if (pthread_create(&threads[1], NULL, collect_packet, oas_info) != 0)
    {
        perror("pthread_create error ");
    }
    if (pthread_create(&threads[2], NULL, wait_commond, NULL) != 0)
    {
        perror("pthread_create error ");
    }
    // 使主线程等待该线程结束后才结束
    pthread_join(threads[1], NULL);
    pthread_join(threads[2], NULL);
}

// 进程1:不断抓包并统计
void *collect_packet(void *para)
{
    options_and_statistics_info *oas_info = (options_and_statistics_info *)para;
    int len;
    char buff[MAXSIZE];
    u_char *packet;

    //-----------------------------备用 ：暂无实际用途
    struct sockaddr_ip *sa_ip = (struct sockaddr_ip *)malloc(sizeof(struct sockaddr_ip));
    bzero(sa_ip, sizeof(struct sockaddr_ip));
    //-----------------------------备用

    int socket_fd = init_socket(sa_ip);
    //获取时间，单位秒 clock（）单位ms
    time_t start_time = time(NULL); // 获取开始时间
    oas_info->t->start = start_time;
    struct tm *start_lt = localtime(&(start_time));
    snprintf(oas_info->t->start_time, 19, "%d/%d/%d %d:%d:%d", start_lt->tm_year + 1900, start_lt->tm_mon, start_lt->tm_mday, start_lt->tm_hour, start_lt->tm_min, start_lt->tm_sec);
    while (1)
    {
        // 循环内置接收信号的地方，接收到信号时获取结束时间同时显示统计结果
        if (terminate == 1)
        {
            time_t end_time = time(NULL); // 获取结束时间
            struct tm *end_lt = localtime(&(end_time));
            snprintf(oas_info->t->end_time, 19, "%d/%d/%d %d:%d:%d", end_lt->tm_year + 1900, end_lt->tm_mon, end_lt->tm_mday, end_lt->tm_hour, end_lt->tm_min, end_lt->tm_sec);
            print_result(oas_info->d, oas_info->t);
            break;
        }
        if ((len = read(socket_fd, buff, MAXSIZE)) < 0)
        {
            perror("read ");
            exit(EXIT_FAILURE);
        }
        packet = buff;
        statistics(packet, oas_info->d, oas_info->o, oas_info->opts);
    }
    pthread_exit(NULL);
}

// 进程2:负责等待命令，通知另一个线程
void *wait_commond()
{
    char commond;
    while (1)
    {
        commond = getch();
        if (commond - 'q' == 0)
        {
            terminate = 1;
            pthread_exit(NULL);
        }
    }
}

// 显示统计结果
void print_result(statistics_info *result, statistics_time *cur_time)
{
    // typedef struct tm time_format;
    // time_format *start_lt, *end_lt;                // 方便显示的时间结构
    // start_lt = localtime(&(cur_time->start_time)); // 得到格式化的开始时间
    // end_lt = localtime(&(cur_time->end_time));     // 得到格式化的结束时间
    //printf ( "%d/%d/%d %d:%d:%d\n",lt->tm_year+1900, lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);//输出结果
    //printf("The pause used %f s by time()\n",difftime(t_end,t_start)); //计算时间差
    time_t end_time = time(NULL);
    double diff_time = difftime(end_time, cur_time->start);
    printf("+-------------------------+-------------------------+\n");
    printf("|Start Time: %39s|\n", cur_time->start_time); // 默认右对齐
    printf("+-------------------------+-------------------------+\n");
    printf("|End Time: %41s|\n", cur_time->end_time);
    printf("+-------------------------+-------------------------+\n");
    printf("|Total Packets: %10d|Bit/s: %18.2f|\n", result->packet_count, (result->packet_bytes_count * 8) / diff_time);
    printf("+-------------------------+-------------------------+\n");
    printf("|MAC Packets: %12d|Packet/s: %15.2f|\n", result->mac_packet_count, result->mac_packet_count / diff_time);
    printf("+-------------------------+-------------------------+\n");
    printf("|MAC Bytes: %14d|Mac Broadcast: %10d|\n", result->mac_bytes_count, result->mac_broad_count);
    printf("+-------------------------+-------------------------+\n");
    printf("|MAC Short: %14d|Mac Long: %15d|\n", result->mac_short_count, result->mac_long_count);
    printf("+-------------------------+-------------------------+\n");
    printf("|IP Packets: %13d|IP Precent: %13.2f|\n", result->ip_packet_count, result->ip_packet_count / (result->packet_count * 1.0));
    printf("+-------------------------+-------------------------+\n");
    printf("|TCP Packets: %12d|TCP Precent: %12.2f|\n", result->tcp_packet_count, result->tcp_packet_count / (result->packet_count * 1.0));
    printf("+-------------------------+-------------------------+\n");
    printf("|UDP Packets: %12d|UDP Precent: %12.2f|\n", result->udp_packet_count, result->udp_packet_count / (result->packet_count * 1.0));
    printf("+-------------------------+-------------------------+\n");
    printf("|ICMP Packets: %11d|ICMP Precent: %11.2f|\n", result->icmp_packet_count, result->icmp_packet_count / (result->packet_count * 1.0));
    printf("+-------------------------+-------------------------+\n");
    printf("|ICMP Redirect: %10d|ICMP Unreachable: %7d|\n", result->icmp_redirect_count, result->icmp_unreachable_count);
    printf("+-------------------------+-------------------------+\n");
    printf("|ICMP Echo Reply: %8d|ICMP Echo Request: %6d|\n", result->icmp_echo_reply_count, result->icmp_echo_request_count);
    printf("+-------------------------+-------------------------+\n");
}

// 根据选项，统计包中相应信息，将其添加进data中
void statistics(u_char *packet, statistics_info *info, options *options, int *opts)
{
    //统计命令行界面，带表格，包含以下信息
    //开始时间，结束时间，数据包总数
    //IP包数、占比
    //UDP包数、占比
    //ICMP包数、占IP比
    //网络超长帧>1518、占比
    //网络超短帧<64、占比
    //Bit/s
    //ICMP Redirects 和ICMP Unreachable
    struct ether_header *eth;
    struct ether_arp *arp;
    struct ip *ip;
    struct icmp *icmp;
    struct tcphdr *tcp;
    struct udphdr *udp;
    void *p = packet;

    if (opts[PROTOCOL] == OFF && opts[IP] == OFF && opts[PORT] == OFF && opts[SOURCE] == OFF && opts[DESTINATION] == OFF && opts[MAC] == OFF)
    {
        info->packet_count++;
        eth = (struct ether_header *)p;
        info->mac_packet_count++;
        // MAC帧统计
        int type = ntohs(eth->ether_type);
        if (type >= 1500)
        {
            info->mac_long_count++;
        }
        if (type < 1500)
        {
            info->mac_bytes_count += type;
            //info->packet_bytes_count += type;
        }
        if (type < 64)
        {
            info->mac_short_count++;
        }
        char *mac_broad = "ff:ff:ff:ff:ff:ff";
        if (memcmp(mac_broad, mac_ntoa(eth->ether_shost), 17) == 0 || memcmp(mac_broad, mac_ntoa(eth->ether_dhost), 17) == 0)
        {
            info->mac_broad_count++;
        }

        p += sizeof(struct ether_header);

        if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
        {
            arp = (struct ether_arp *)p;
            info->arp_packet_count++;
        }
        else if (ntohs(eth->ether_type) == ETHERTYPE_IP)
        {
            ip = (struct ip *)p;
            p += ((int)(ip->ip_hl) << 2);

            info->ip_packet_count++;
            //info->ip_bytes_count += ntohs(ip->ip_len);
            info->packet_bytes_count += ntohs(ip->ip_len);

            switch (ip->ip_p)
            {
            case IPPROTO_TCP:
                tcp = (struct tcphdr *)p;
                p += ((int)(tcp->th_off) << 2);

                info->tcp_packet_count++;

                break;
            case IPPROTO_UDP:
                udp = (struct udphdr *)p;
                p += sizeof(struct udphdr);

                info->udp_packet_count++;
                break;
            case IPPROTO_ICMP:
                icmp = (struct icmp *)p;
                p = icmp->icmp_data;

                info->icmp_packet_count++;
                switch (icmp->icmp_type)
                {
                case 5:
                    info->icmp_redirect_count++;
                    break;
                case 3:
                    info->icmp_unreachable_count++;
                    break;
                case 0:
                    info->icmp_echo_reply_count++;
                    break;
                case 8:
                    info->icmp_echo_request_count++;
                    break;
                }

                break;
            default:
                break;
            }
        }
    }
    else if (opts[PROTOCOL] == ON)
    {
        eth = (struct ether_header *)p;
        p += sizeof(struct ether_header);

        switch (options->protocol)
        {
        case 0: //arp
            if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
            {
                info->packet_count++;
                info->mac_packet_count++;
                arp = (struct ether_arp *)p;
                info->arp_packet_count++;
                int type = ntohs(eth->ether_type);
                if (type >= 1500)
                {
                    info->mac_long_count++;
                }
                if (type < 1500)
                {
                    info->mac_bytes_count += type;
                    //info->packet_bytes_count += type;
                }
                if (type < 64)
                {
                    info->mac_short_count++;
                }
                char *mac_broad = "ff:ff:ff:ff:ff:ff";
                if (memcmp(mac_broad, mac_ntoa(eth->ether_shost), 17) == 0 || memcmp(mac_broad, mac_ntoa(eth->ether_dhost), 17) == 0)
                {
                    info->mac_broad_count++;
                }
            }
            break;
        case 1: //ip
            if (ntohs(eth->ether_type) == ETHERTYPE_IP)
            {
                ip = (struct ip *)p;
                p += ((int)(ip->ip_hl) << 2);
                info->packet_count++;
                info->mac_packet_count++;
                info->ip_packet_count++;
                //info->ip_bytes_count += ntohs(ip->ip_len);
                info->packet_bytes_count += ntohs(ip->ip_len);
                int type = ntohs(eth->ether_type);
                if (type >= 1500)
                {
                    info->mac_long_count++;
                }
                if (type < 1500)
                {
                    info->mac_bytes_count += type;
                    //info->packet_bytes_count += type;
                }
                if (type < 64)
                {
                    info->mac_short_count++;
                }
                char *mac_broad = "ff:ff:ff:ff:ff:ff";
                if (memcmp(mac_broad, mac_ntoa(eth->ether_shost), 17) == 0 || memcmp(mac_broad, mac_ntoa(eth->ether_dhost), 17) == 0)
                {
                    info->mac_broad_count++;
                }
            }
            break;
        case 2: //udp
            if (ntohs(eth->ether_type) == ETHERTYPE_IP)
            {
                ip = (struct ip *)p;
                p += ((int)(ip->ip_hl) << 2);

                if (ip->ip_p == IPPROTO_UDP)
                {
                    info->packet_count++;
                    info->mac_packet_count++;
                    info->udp_packet_count++;
                    info->ip_packet_count++;
                    info->packet_bytes_count += ntohs(ip->ip_len);
                    int type = ntohs(eth->ether_type);
                    if (type >= 1500)
                    {
                        info->mac_long_count++;
                    }
                    if (type < 1500)
                    {
                        info->mac_bytes_count += type;
                        //info->packet_bytes_count += type;
                    }
                    if (type < 64)
                    {
                        info->mac_short_count++;
                    }
                    char *mac_broad = "ff:ff:ff:ff:ff:ff";
                    if (memcmp(mac_broad, mac_ntoa(eth->ether_shost), 17) == 0 || memcmp(mac_broad, mac_ntoa(eth->ether_dhost), 17) == 0)
                    {
                        info->mac_broad_count++;
                    }
                }
            }
            break;
        case 3: //tcp
            if (ntohs(eth->ether_type) == ETHERTYPE_IP)
            {
                ip = (struct ip *)p;
                p += ((int)(ip->ip_hl) << 2);
                if (ip->ip_p == IPPROTO_TCP)
                {
                    info->packet_count++;
                    info->mac_packet_count++;
                    info->tcp_packet_count++;
                    info->ip_packet_count++;
                    info->packet_bytes_count += ntohs(ip->ip_len);
                    int type = ntohs(eth->ether_type);
                    if (type >= 1500)
                    {
                        info->mac_long_count++;
                    }
                    if (type < 1500)
                    {
                        info->mac_bytes_count += type;
                        //info->packet_bytes_count += type;
                    }
                    if (type < 64)
                    {
                        info->mac_short_count++;
                    }
                    char *mac_broad = "ff:ff:ff:ff:ff:ff";
                    if (memcmp(mac_broad, mac_ntoa(eth->ether_shost), 17) == 0 || memcmp(mac_broad, mac_ntoa(eth->ether_dhost), 17) == 0)
                    {
                        info->mac_broad_count++;
                    }
                }
            }
            break;
        case 4: //icmp
            if (ntohs(eth->ether_type) == ETHERTYPE_IP)
            {
                ip = (struct ip *)p;
                p += ((int)(ip->ip_hl) << 2);
                if (ip->ip_p == IPPROTO_ICMP)
                {
                    info->icmp_packet_count++;
                    info->packet_count++;
                    info->mac_packet_count++;
                    info->ip_packet_count++;
                    int type = ntohs(eth->ether_type);
                    if (type >= 1500)
                    {
                        info->mac_long_count++;
                    }
                    if (type < 1500)
                    {
                        info->mac_bytes_count += type;
                        //info->packet_bytes_count += type;
                    }
                    if (type < 64)
                    {
                        info->mac_short_count++;
                    }
                    char *mac_broad = "ff:ff:ff:ff:ff:ff";
                    if (memcmp(mac_broad, mac_ntoa(eth->ether_shost), 17) == 0 || memcmp(mac_broad, mac_ntoa(eth->ether_dhost), 17) == 0)
                    {
                        info->mac_broad_count++;
                    }
                }
            }
            break;
        }
    }
    else if (opts[IP] == ON)
    {
        eth = (struct ether_header *)p;
        p += sizeof(struct ether_header);

        if (ntohs(eth->ether_type) == ETHERTYPE_IP)
        {
            ip = (struct ip *)p;
            p += ((int)(ip->ip_hl) << 2);
            if (memcmp(&ip->ip_src.s_addr, &options->ip_in_addr, sizeof(options->ip_in_addr)) || memcmp(&ip->ip_dst.s_addr, &options->ip_in_addr, sizeof(options->ip_in_addr)))
            {
                info->mac_packet_count++;
                info->packet_count++;
                info->ip_packet_count++;
                info->packet_bytes_count += ntohs(ip->ip_len);
                int type = ntohs(eth->ether_type);
                if (type >= 1500)
                {
                    info->mac_long_count++;
                }
                if (type < 1500)
                {
                    info->mac_bytes_count += type;
                    //info->packet_bytes_count += type;
                }
                if (type < 64)
                {
                    info->mac_short_count++;
                }
                char *mac_broad = "ff:ff:ff:ff:ff:ff";
                if (memcmp(mac_broad, mac_ntoa(eth->ether_shost), 17) == 0 || memcmp(mac_broad, mac_ntoa(eth->ether_dhost), 17) == 0)
                {
                    info->mac_broad_count++;
                }
                switch (ip->ip_p)
                {
                case IPPROTO_TCP:
                    tcp = (struct tcphdr *)p;
                    p += ((int)(tcp->th_off) << 2);
                    info->tcp_packet_count++;

                    break;
                case IPPROTO_UDP:
                    udp = (struct udphdr *)p;
                    p += sizeof(struct udphdr);

                    info->udp_packet_count++;
                    break;
                case IPPROTO_ICMP:
                    icmp = (struct icmp *)p;
                    p = icmp->icmp_data;

                    info->icmp_packet_count++;
                    switch (icmp->icmp_type)
                    {
                    case 5:
                        info->icmp_redirect_count++;
                        break;
                    case 3:
                        info->icmp_unreachable_count++;
                        break;
                    case 0:
                        info->icmp_echo_reply_count++;
                        break;
                    case 8:
                        info->icmp_echo_request_count++;
                        break;
                    }
                    break;
                default:
                    break;
                }
            }
        }
    }
    else if (opts[PORT] == ON)
    {
        eth = (struct ether_header *)p;
        p += sizeof(struct ether_header);
        if (ntohs(eth->ether_type) == ETHERTYPE_IP)
        {
            ip = (struct ip *)p;
            p += ((int)(ip->ip_hl) << 2);
            if (ip->ip_p == IPPROTO_UDP)
            {
                udp = (struct udphdr *)p;
                if (options->port == udp->uh_sport || options->port == udp->uh_dport)
                {
                    info->mac_packet_count++;
                    info->packet_count++;
                    info->ip_packet_count++;
                    info->udp_packet_count++;
                    int type = ntohs(eth->ether_type);
                    if (type >= 1500)
                    {
                        info->mac_long_count++;
                    }
                    if (type < 1500)
                    {
                        info->mac_bytes_count += type;
                        //info->packet_bytes_count += type;
                    }
                    if (type < 64)
                    {
                        info->mac_short_count++;
                    }
                    char *mac_broad = "ff:ff:ff:ff:ff:ff";
                    if (memcmp(mac_broad, mac_ntoa(eth->ether_shost), 17) == 0 || memcmp(mac_broad, mac_ntoa(eth->ether_dhost), 17) == 0)
                    {
                        info->mac_broad_count++;
                    }
                }
            }
            if (ip->ip_p == IPPROTO_TCP)
            {
                tcp = (struct tcphdr *)p;
                p += ((int)(tcp->th_off) << 2);
                info->mac_packet_count++;
                info->packet_count++;
                info->ip_packet_count++;
                info->tcp_packet_count++;
                int type = ntohs(eth->ether_type);
                if (type >= 1500)
                {
                    info->mac_long_count++;
                }
                if (type < 1500)
                {
                    info->mac_bytes_count += type;
                    //info->packet_bytes_count += type;
                }
                if (type < 64)
                {
                    info->mac_short_count++;
                }
                char *mac_broad = "ff:ff:ff:ff:ff:ff";
                if (memcmp(mac_broad, mac_ntoa(eth->ether_shost), 17) == 0 || memcmp(mac_broad, mac_ntoa(eth->ether_dhost), 17) == 0)
                {
                    info->mac_broad_count++;
                }
            }
        }
    }
    else if (opts[SOURCE] == ON)
    {
        // TODO
    }
    else if (opts[DESTINATION] == ON)
    {
        // TODO
    }
    else if (opts[MAC] == ON)
    {
        // TODO
    }
}

int init_socket(struct sockaddr_ip *sa_ip)
{
    int socket_fd;
    if ((socket_fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0)
    {
        perror("socket error ");
        exit(EXIT_FAILURE);
    }
//-----------------------------备用 ：暂无实际用途
#define CMAX 256
    char ifname[CMAX] = "";
    if (strcmp(ifname, "") != 0)
    {
#define MYPORT 5900
        struct sockaddr_in socket_info;
        socket_info.sin_family = AF_INET; // socket唯一选择
        // socket_info.sin_port = htons(MYPORT);    // 直接=0则系统随机选择一个未被占有的端口号
        socket_info.sin_port = sa_ip->port | MYPORT;
        socket_info.sin_addr.s_addr = sa_ip->ip; // 获得本机IP地址
        bzero(&(socket_info.sin_zero), 8);

        // snprintf(sa.sa_data, CMAX, "%s", ifname);

        // 用于绑定特定IP和端口，一般为服务器的服务端口
        // sockaddr与sockaddr_in在内存上一致，只不过sockaddr不好用，所以造型一下
        if (bind(socket_fd, (const struct sockaddr *)&socket_info, sizeof socket_info) < 0)
        {
            perror("bind error ");
            exit(EXIT_FAILURE);
        }
    }
//-----------------------------备用
    return socket_fd;
}

// 类Unix下实现win下<conio.h>库的getch():即无需回车地读取输入
// 需库<unistd.h><termios.h>
char getch()
{
    char buf = 0;
    struct termios old = {0};
    if (tcgetattr(0, &old) < 0)
        perror("tcsetattr()");
    old.c_lflag &= ~ICANON;
    old.c_lflag &= ~ECHO;
    old.c_cc[VMIN] = 1;
    old.c_cc[VTIME] = 0;
    if (tcsetattr(0, TCSANOW, &old) < 0)
        perror("tcsetattr ICANON");
    if (read(0, &buf, 1) < 0)
        perror("read()");
    old.c_lflag |= ICANON;
    old.c_lflag |= ECHO;
    if (tcsetattr(0, TCSADRAIN, &old) < 0)
        perror("tcsetattr ~ICANON");
    return (buf);
}

void print_help(char *cmd)
{
    fprintf(stderr, "usage: %s [-h Help] [-f Find Device] [-n Packet Information] [-s Statistics]\n \
    [-r Protocols] [-i IP Address] [-p Port] [-m MAC] [-o Source] [-d Destination]\n",
            cmd);
    fprintf(stderr, "Protocols: arp ip icmp tcp udp\n");
    fprintf(stderr, "IP Format: xxx.xxx.xxx.xxx\n");
    fprintf(stderr, "Port Range: 0-65535\n");
    fprintf(stderr, "Mac Format: xx:xx:xx:xx:xx:xx\n");
    fprintf(stderr, "Only Once In -h, -s, -f or -n\n");
}

void discover_device()
{
    int socket_fd;
    u_char *device_mac[100];
    int find_num = 100;
    int device_num = 0;
    if ((socket_fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0)
    {
        perror("socket error ");
        exit(EXIT_FAILURE);
    }
    printf("正在搜索设备……\n");
    while (find_num > 0)
    {
        struct ether_header *eth;
        char buff[MAXSIZE];
        void *packet;
        int len;
        u_char src_mac[6];
        u_char dst_mac[6];
        if ((len = read(socket_fd, buff, MAXSIZE)) < 0)
        {
            perror("read");
            exit(EXIT_FAILURE);
        }
        packet = buff;
        eth = (struct ether_header *)packet;
        memset(src_mac, 0, sizeof(src_mac));
        memset(dst_mac, 0, sizeof(src_mac));
        memcpy(src_mac, eth->ether_shost, sizeof(eth->ether_shost));
        memcpy(dst_mac, eth->ether_dhost, sizeof(eth->ether_dhost));
        find_device(src_mac, &device_num, device_mac, &find_num);
        find_device(dst_mac, &device_num, device_mac, &find_num);
    }
    printf("已发现100个网络设备\n");
}

void find_device(u_char *mac, int *device_num, u_char *device_mac[], int *find_num)
{
    u_char nil[6];
    memset(nil, 0, sizeof(nil));
    if (memcmp(mac, nil, sizeof(nil)) == 0)
    {
        return;
    }

    if (is_exist(mac, device_num, device_mac))
    {
        device_mac[*device_num] = (u_char *)malloc(sizeof(mac));
        memcpy(device_mac[*device_num], mac, 6);
        *device_num = *device_num + 1;
        printf("Device %d: %17s\n", *device_num, mac_ntoa(mac));
        *find_num = *find_num - 1;
    }
}

int is_exist(u_char *mac, int *device_num, u_char *device_mac[])
{
    if (*device_num == 0)
        return 1;
    for (int i = 0; i < *device_num; i++)
    {
        if (memcmp(device_mac[i], mac, 6) == 0)
        {
            return 0;
        }
    }
    return 1;
}

char *mac_ntoa(u_char *d)
{
#define MAX_MACSTR 50
    static char str[MAX_MACSTR];
    snprintf(str, MAX_MACSTR, "%02x:%02x:%02x:%02x:%02x:%02x",
             d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}

void print_packet()
{
    int socket_fd;
    if ((socket_fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0)
    {
        perror("socket ");
        exit(EXIT_FAILURE);
    }
    while (1)
    {
        struct ether_header *eth;
        struct ether_arp *arp;
        struct ip *ip;
        struct icmp *icmp;
        struct tcphdr *tcp;
        struct udphdr *udp;
        char buff[MAXSIZE];
        void *p;
        int len;

        if ((len = read(socket_fd, buff, MAXSIZE)) < 0)
        {
            perror("read");
            exit(EXIT_FAILURE);
        }
        p = buff;
        eth = (struct ether_header *)p;
        p += sizeof(struct ether_header);
        print_ethernet(eth);
        if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
        {
            arp = (struct ether_arp *)p;
            print_arp(arp);
        }
        else if (ntohs(eth->ether_type) == ETHERTYPE_IP)
        {
            ip = (struct ip *)p;
            p += ((int)(ip->ip_hl) << 2);
            print_ip(ip);
            switch (ip->ip_p)
            {
            case IPPROTO_TCP:
                tcp = (struct tcphdr *)p;
                p += ((int)(tcp->th_off) << 2);
                print_tcp(tcp);
                break;
            case IPPROTO_UDP:
                udp = (struct udphdr *)p;
                p += sizeof(struct udphdr);
                print_udp(udp);
                break;
            case IPPROTO_ICMP:
                icmp = (struct icmp *)p;
                p = icmp->icmp_data;
                print_icmp(icmp);
                break;
            default:
                break;
            }
        }
    }
}

void print_ethernet(struct ether_header *eth)
{
    int type = ntohs(eth->ether_type);
    if (type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");

    printf("+-------------------------+-------------------------"
           "+-------------------------+\n");
    printf("| Destination MAC Address:                          "
           "         %17s|\n",
           mac_ntoa(eth->ether_dhost));
    printf("+-------------------------+-------------------------"
           "+-------------------------+\n");
    printf("| Source MAC Address:                               "
           "         %17s|\n",
           mac_ntoa(eth->ether_shost));
    printf("+-------------------------+-------------------------"
           "+-------------------------+\n");
    if (type < 1500)
        printf("| Length:            %5u|\n", type);
    else
        printf("| Ethernet Type:    0x%04x|\n", type);
    printf("+-------------------------+\n");
}

void print_arp(struct ether_arp *arp)
{
    static char *arp_op_name[] = {
        "Undefine",
        "(ARP Request)",
        "(ARP Reply)",
        "(RARP Request)",
        "(RARP Reply)"};
#define ARP_OP_MAX (sizeof arp_op_name / sizeof arp_op_name[0])
    int op = ntohs(arp->ea_hdr.ar_op);

    if (op < 0 || ARP_OP_MAX < op)
        op = 0;

    printf("Protocol: ARP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Hard Type: %2u%-11s| Protocol:0x%04x%-9s|\n",
           ntohs(arp->ea_hdr.ar_hrd),
           (ntohs(arp->ea_hdr.ar_hrd) == ARPHRD_ETHER) ? "(Ethernet)" : "(Not Ether)",
           ntohs(arp->ea_hdr.ar_pro),
           (ntohs(arp->ea_hdr.ar_pro) == ETHERTYPE_IP) ? "(IP)" : "(Not IP)");
    printf("+------------+------------+-------------------------+\n");
    printf("| HardLen:%3u| Addr Len:%2u| OP: %4d%16s|\n",
           arp->ea_hdr.ar_hln, arp->ea_hdr.ar_pln, ntohs(arp->ea_hdr.ar_op),
           arp_op_name[op]);
    printf("+------------+------------+-------------------------"
           "+-------------------------+\n");
    printf("| Source MAC Address:                               "
           "         %17s|\n",
           mac_ntoa(arp->arp_sha));
    printf("+---------------------------------------------------"
           "+-------------------------+\n");
    printf("| Source IP Address:                 %15s|\n",
           inet_ntoa(*(struct in_addr *)&arp->arp_spa));
    printf("+---------------------------------------------------"
           "+-------------------------+\n");
    printf("| Destination MAC Address:                          "
           "         %17s|\n",
           mac_ntoa(arp->arp_tha));
    printf("+---------------------------------------------------"
           "+-------------------------+\n");
    printf("| Destination IP Address:            %15s|\n",
           inet_ntoa(*(struct in_addr *)&arp->arp_tpa));
    printf("+---------------------------------------------------+\n");
}

void print_ip(struct ip *ip)
{
    printf("Protocol: IP\n");
    printf("+-----+------+------------+-------------------------+\n");
    printf("| IV:%1u| HL:%2u| T: %8s| Total Length: %10u|\n",
           ip->ip_v, ip->ip_hl, ip_ttoa(ip->ip_tos), ntohs(ip->ip_len));
    printf("+-----+------+------------+-------+-----------------+\n");
    printf("| Identifier:        %5u| FF:%3s| FO:        %5u|\n",
           ntohs(ip->ip_id), ip_ftoa(ntohs(ip->ip_off)),
           ntohs(ip->ip_off) & IP_OFFMASK);
    printf("+------------+------------+-------+-----------------+\n");
    printf("| TTL:    %3u| Pro:    %3u| Header Checksum:   %5u|\n",
           ip->ip_ttl, ip->ip_p, ntohs(ip->ip_sum));
    printf("+------------+------------+-------------------------+\n");
    printf("| Source IP Address:                 %15s|\n",
           inet_ntoa(*(struct in_addr *)&(ip->ip_src)));
    printf("+---------------------------------------------------+\n");
    printf("| Destination IP Address:            %15s|\n",
           inet_ntoa(*(struct in_addr *)&(ip->ip_dst)));
    printf("+---------------------------------------------------+\n");
}

char *ip_ftoa(int flag)
{
    static int f[] = {'R', 'D', 'M'};
#define IP_FLG_MAX (sizeof f / sizeof f[0])
    static char str[IP_FLG_MAX + 1];
    unsigned int mask = 0x8000;
    int i;

    for (i = 0; i < IP_FLG_MAX; i++)
    {
        if (((flag << i) & mask) != 0)
            str[i] = f[i];
        else
            str[i] = '0';
    }
    str[i] = '\0';
    return str;
}

char *ip_ttoa(int flag)
{
    static int f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
#define TOS_MAX (sizeof f / sizeof f[0])
    static char str[TOS_MAX + 1];
    unsigned int mask = 0x80;
    int i;
    for (i = 0; i < TOS_MAX; i++)
    {
        if (((flag << i) & mask) != 0)
            str[i] = f[i];
        else
            str[i] = '0';
    }
    str[i] = '\0';
    return str;
}

void print_icmp(struct icmp *icmp)
{
    static char *type_name[] = {
        "Echo Reply",
        "Undefine",
        "Undefine",
        "Destination Unreachable",
        "Source Quench",
        "Redirect (change route)",
        "Undefine",
        "Undefine",
        "Echo Request",
        "Undefine",
        "Undefine",
        "Time Exceeded",
        "Parameter Problem",
        "Timestamp Request",
        "Timestamp Reply",
        "Information Request",
        "Information Reply",
        "Address Mask Request",
        "Address Mask Reply",
        "Unknown"};
#define ICMP_TYPE_MAX (sizeof type_name / sizeof type_name[0])
    int type = icmp->icmp_type;
    if (type < 0 || ICMP_TYPE_MAX <= type)
        type = ICMP_TYPE_MAX - 1;
    printf("Protocol: ICMP (%s)\n", type_name[type]);
    printf("+------------+------------+-------------------------+\n");
    printf("| Type:   %3u| Code:   %3u| Checksum:          %5u|\n",
           icmp->icmp_type, icmp->icmp_code, ntohs(icmp->icmp_cksum));
    printf("+------------+------------+-------------------------+\n");
    if (icmp->icmp_type == 0 || icmp->icmp_type == 8)
    {
        printf("| Identification:    %5u| Sequence Number:   %5u|\n",
               ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
        printf("+-------------------------+-------------------------+\n");
    }
    else if (icmp->icmp_type == 3)
    {
        if (icmp->icmp_code == 4)
        {
            printf("| void:          %5u| Next MTU:          %5u|\n",
                   ntohs(icmp->icmp_pmvoid), ntohs(icmp->icmp_nextmtu));
            printf("+-------------------------+-------------------------+\n");
        }
        else
        {
            printf("| Unused:                                 %10lu|\n",
                   (unsigned long)ntohl(icmp->icmp_void));
            printf("+-------------------------+-------------------------+\n");
        }
    }
    else if (icmp->icmp_type == 5)
    {
        printf("| Router IP Address:                 %15s|\n",
               inet_ntoa(*(struct in_addr *)&(icmp->icmp_gwaddr)));
        printf("+---------------------------------------------------+\n");
    }
    else if (icmp->icmp_type == 11)
    {
        printf("| Unused:                                 %10lu|\n",
               (unsigned long)ntohl(icmp->icmp_void));
        printf("+---------------------------------------------------+\n");
    }

    if (icmp->icmp_type == 3 || icmp->icmp_type == 5 || icmp->icmp_type == 11)
    {
        struct ip *ip = (struct ip *)icmp->icmp_data;
        char *p = (char *)ip + ((int)(ip->ip_hl) << 2);

        print_ip(ip);
        switch (ip->ip_p)
        {
        case IPPROTO_TCP:
            print_tcp_mini((struct tcphdr *)p);
            break;
        case IPPROTO_UDP:
            print_udp((struct udphdr *)p);
            break;
        }
    }
}

void print_tcp(struct tcphdr *tcp)
{
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n",
           ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10lu|\n",
           (unsigned long)ntohl(tcp->th_seq));
    printf("+---------------------------------------------------+\n");
    printf("| Acknowledgement Number:                 %10lu|\n",
           (unsigned long)ntohl(tcp->th_ack));
    printf("+------+---------+--------+-------------------------+\n");
    printf("| DO:%2u| Reserved|F:%6s| Window Size:       %5u|\n",
           tcp->th_off, tcp_ftoa(tcp->th_flags), ntohs(tcp->th_win));
    printf("+------+---------+--------+-------------------------+\n");
    printf("| Checksum:          %5u| Urgent Pointer:    %5u|\n",
           ntohs(tcp->th_sum), ntohs(tcp->th_urp));
    printf("+-------------------------+-------------------------+\n");
}

void print_tcp_mini(struct tcphdr *tcp)
{
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n",
           ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10lu|\n",
           (unsigned long)ntohl(tcp->th_seq));
    printf("+---------------------------------------------------+\n");
}

char *tcp_ftoa(int flag)
{
    static int f[] = {'U', 'A', 'P', 'R', 'S', 'F'};
#define TCP_FLG_MAX (sizeof f / sizeof f[0])
    static char str[TCP_FLG_MAX + 1];
    unsigned int mask = 1 << (TCP_FLG_MAX - 1);
    int i;
    for (i = 0; i < TCP_FLG_MAX; i++)
    {
        if (((flag << i) & mask) != 0)
            str[i] = f[i];
        else
            str[i] = '0';
    }
    str[i] = '\0';
    return str;
}

void print_udp(struct udphdr *udp)
{
    printf("Protocol: UDP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n",
           ntohs(udp->uh_sport), ntohs(udp->uh_dport));
    printf("+-------------------------+-------------------------+\n");
    printf("| Length:            %5u| Checksum:          %5u|\n",
           ntohs(udp->uh_ulen), ntohs(udp->uh_sum));
    printf("+-------------------------+-------------------------+\n");
}
