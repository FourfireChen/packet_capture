#include "packet_capture.h"
#include <string>
#include <zconf.h>
#include <map>

using namespace std;

int tcp_num_count;
int udp_num_count;
int fin, syn, rst, push, ack, urg, ece, cwr;
map<string, record> record_map;

char *GetLocalIp() {
    char hostname[1024];
    int ret = gethostname(hostname, sizeof(hostname));
    if (ret == -1) {
        return nullptr;
    }
    struct hostent *hent;
    hent = gethostbyname(hostname);
    if (nullptr == hent) {
        return nullptr;
    }
    return inet_ntoa(*((struct in_addr *) hent->h_addr));
}

bool IsLocalIp(char *ip) {
    string ipStr = ip;
    string localIp = GetLocalIp();
    return localIp.substr(0, localIp.find_last_of('.')) == ipStr.substr(0, ipStr.find_last_of('.'));
}

void GotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 1;

    // 以太网头部
    struct sniff_ethernet *ethernet;
    // IP 头部
    struct sniff_ip *ip;
    // TCP 头部
    struct sniff_tcp *tcp;
    // UDP 头部
    struct sniff_udp *udp;

    int size_ip;
    int size_tcp;
    int size_payload;
    // 0=TCP; 1=UDP; 2=IP
    int proto_flag = -1;

    // 包总数
    printf("\n第%d个包:\n", count);
    count++;

    // 以太网头部
    ethernet = (struct sniff_ethernet *) (packet);

    // 计算IP头部偏移
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * IP首部长度错误: %u bytes\n", size_ip);
        return;
    }
    if (IsLocalIp(inet_ntoa(ip->ip_src))) {
        // 发送包
        record_map[inet_ntoa(ip->ip_dst)].send++;
    } else if (IsLocalIp(inet_ntoa(ip->ip_dst))) {
        // 接收包
        record_map[inet_ntoa(ip->ip_src)].receive++;
    }


    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("协议: TCP\n");
            proto_flag = 0;
            break;
        case IPPROTO_UDP:
            printf("协议: UDP\n");
            proto_flag = 1;
            break;
        case IPPROTO_IP:
            printf("协议: IP\n");
            proto_flag = 2;
            break;
        default:
            printf("协议: other\n");
            return;
    }

    if (proto_flag == 0) {
        // TCP
        tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF (tcp) * 4;
        if (size_tcp < 20) {
            printf("   * TCP头部长度错误: %u bytes\n", size_tcp);
            return;
        }

        printf("        From: %s : %d\n", inet_ntoa(ip->ip_src), ntohs (tcp->th_sport));
        printf("          To: %s : %d\n", inet_ntoa(ip->ip_dst), ntohs (tcp->th_dport));
        printf("  Seq number: %d\n", ntohl (tcp->th_seq));
        if (tcp->th_flags & TH_FIN) {
            printf("         FIN: 1\n");
            fin++;
        }
        if (tcp->th_flags & TH_CWR) {
            cwr++;
        }
        if (tcp->th_flags & TH_ACK) {
            ack++;
        }
        if (tcp->th_flags & TH_PUSH) {
            push++;
        }
        if (tcp->th_flags & TH_ECE) {
            ece++;
        }
        if (tcp->th_flags & TH_RST) {
            rst++;
        }
        if (tcp->th_flags & TH_URG) {
            urg++;
        }
        if (tcp->th_flags & TH_SYN) {
            syn++;
        }

        size_payload = ntohs (ip->ip_len) - (size_ip + size_tcp);
        printf("size_payload: %d\n", size_payload);
        tcp_num_count++;
    } else if (proto_flag == 1) {
        // UDP包
        udp = (struct sniff_udp *) (packet + SIZE_ETHERNET + size_ip);
        printf("        From: %s : %d\n", inet_ntoa(ip->ip_src), ntohs (udp->sport));
        printf("          To: %s : %d\n", inet_ntoa(ip->ip_dst), ntohs (udp->dport));
        printf("      Length: %d\n", ntohs (udp->udp_length));
        printf("         Sum: %d\n", ntohs (udp->udp_sum));

        size_payload = ntohs (ip->ip_len) - (size_ip + 8);
        printf("size_payload: %d\n", size_payload);
        udp_num_count++;
    }
}

int main(int argc, char **argv) {
    GetLocalIp();
    // 设备名称
    char *dev;
    // 错误缓冲区
    char errbuf[PCAP_ERRBUF_SIZE];
    // 数据包捕获句柄
    pcap_t *handle;
    // 过滤表达
    char filter_exp[] = "ip";
    // 过滤表达
    struct bpf_program fp;
    // 子网掩码
    bpf_u_int32 mask;
    // IP地址
    bpf_u_int32 net;

    // 检查来自命令行参数需要捕获设备的名称
    if (argc == 2) {
        dev = argv[1];
    } else if (argc > 2) {
        fprintf(stderr, "参数错了\n\n");
        exit(EXIT_FAILURE);
    } else {
        // 如果命令行参数没有指定, 则自动找到一个设备
        dev = pcap_lookupdev(errbuf);
        if (dev == nullptr) {
            fprintf(stderr, "没有默认网络设备: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
    }

    // 获得捕获设备的网络号和掩码
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "设备网络号或掩码捕获错误 %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    // 显示捕获设备信息
    printf("设备: %s\n", dev);
    printf("要捕获的包数量: %d\n", PACKETS_NUM);
    printf("过滤规则: %s\n", filter_exp);
    printf("网络号：%d\n", net);

    /* 打开捕获设备
       @1        捕获的设备
       @2        每次捕获数据的最大长度
       @3        1 启用混杂模式
       @4        捕获时间, 单位ms
       @5        错误缓冲区 */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "打开设备错误 %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    // 返回数据链路层类型，确保是对以太网设备捕获
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s 设备不是DLT_EN10MB\n", dev);
        exit(EXIT_FAILURE);
    }

    // 编译过滤表达式
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "过滤表达式错误呀 %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // 应用过滤规则
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "无法应用过滤规则，检查一下规则 %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // 开始捕获包
    pcap_loop(handle, PACKETS_NUM, GotPacket, nullptr);

    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\n结束.\n");
    printf("共有%d个UDP包\n", udp_num_count);

    printf("共有%d个TCP包\n", tcp_num_count);
    printf("具体类型数量如下：fin %d, syn %d, rst %d, push %d, ack %d, urg %d, ece %d, cwr %d\n",
           fin,
           syn,
           rst,
           push,
           ack,
           urg,
           ece,
           cwr);

    for (auto &pair: record_map) {
        printf("IP %s      send %d      receive %d\n", pair.first.c_str(), pair.second.send, pair.second.receive);
    }

    return 0;
}