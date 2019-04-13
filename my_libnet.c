#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libnet.h>

#define TIMES 1000

int main(int argc, char *argv[])
{
	char send_msg[TIMES] = "";
	char err_buf[100] = "";
	libnet_t *lib_net = NULL;
	int lens = 0;
	libnet_ptag_t lib_t = 0;
	unsigned char src_mac[6] = {0x00, 0x0c, 0x29, 0x97, 0xc7, 0xc1}; //发送者网卡地址00:0c:29:97:c7:c1
	unsigned char dst_mac[6] = {0x00, 0x0c, 0x29, 0x7b, 0xa7, 0x20}; //接收者网卡地址‎74-27-EA-B5-FF-D8
	char *src_ip_str = "192.168.31.163";							 //源主机IP地址
	char *dst_ip_str = "192.168.47.151";							 //目的主机IP地址
	unsigned long src_ip, dst_ip = 0;

	int tcp = 1;

	printf("0) UDP Test\n1) TCP Test\n");
	scanf("%d",&tcp);

	if (tcp == 0)  //UDP
	{
		int i = 0;
		for (i = 0; i < TIMES; i++)
		{
			lens = sprintf(send_msg, "%d: %s", i, "this is for the libnet udp test made by sam 1160801026\n"); //send_msg是包内容，用sprintf()获取其长度

			lib_net = libnet_init(LIBNET_LINK_ADV, "ens33", err_buf); //初始化
			if (NULL == lib_net)
			{
				perror("libnet_init");
				exit(-1);
			}

			src_ip = libnet_name2addr4(lib_net, src_ip_str, LIBNET_RESOLVE); //将字符串类型的ip转换为顺序网络字节流
			dst_ip = libnet_name2addr4(lib_net, dst_ip_str, LIBNET_RESOLVE);

			lib_t = libnet_build_udp( //构造udp数据包
				8080,
				8080,
				8 + lens,
				0,
				send_msg,
				lens,
				lib_net,
				0);

			lib_t = libnet_build_ipv4( //构造ip数据包
				20 + 8 + lens,
				0,
				500,
				0,
				10,
				17,
				0,
				src_ip,
				dst_ip,
				NULL,
				0,
				lib_net,
				0);

			lib_t = libnet_build_ethernet( //构造以太网数据包
				(u_int8_t *)dst_mac,
				(u_int8_t *)src_mac,
				0x800, // 或者，ETHERTYPE_IP
				NULL,
				0,
				lib_net,
				0);
			int res = 0;
			res = libnet_write(lib_net); //发送数据包
			if (-1 == res)
			{
				perror("libnet_write");
				exit(-1);
			}

			libnet_destroy(lib_net); //销毁资源
		}
	}
	else   //TCP
	{
		int i = 0;
		for (i = 0; i < TIMES; i++)
		{
			lens = sprintf(send_msg, "%d: %s", i, "this is for the libnet tcp test made by sam 1160801026\n"); //send_msg是包内容，用sprintf()获取其长度

			lib_net = libnet_init(LIBNET_LINK_ADV, "ens33", err_buf); //初始化
			if (NULL == lib_net)
			{
				perror("libnet_init");
				exit(-1);
			}

			src_ip = libnet_name2addr4(lib_net, src_ip_str, LIBNET_RESOLVE); //将字符串类型的ip转换为顺序网络字节流
			dst_ip = libnet_name2addr4(lib_net, dst_ip_str, LIBNET_RESOLVE);
			lib_t = libnet_build_tcp(
				8080,				 /* 源端口 */
				14257,				 /* 目的端口 */
				lens*i,				 /* 序列号 */
				lens*i+1,				 /* 确认号 */
				TH_PUSH | TH_ACK,	/* Control flags */
				14600,				 /* 窗口尺寸 */
				0,					 /* 校验和,0为自动计算 */
				0,					 /* 紧急指针 */
				LIBNET_TCP_H + lens, /* 长度 */
				send_msg,			 /* 负载内容 */
				lens,				 /* 负载内容长度 */
				lib_net,			 /* libnet句柄 */
				0					 /* 新建包 */
			);
			// if (lib_t == -1)
			// {
			// 	printf("libnet_build_tcp failure\n");
			// 	return (-3);
			// };
			lib_t = libnet_build_ipv4( //构造ip数据包
				LIBNET_IPV4_H + LIBNET_TCP_H + lens,
				0,
				500,
				0,
				10,
				6,
				0,
				src_ip,
				dst_ip,
				NULL,
				0,
				lib_net,
				0);
			lib_t = libnet_build_ethernet( //构造以太网数据包
				(u_int8_t *)dst_mac,
				(u_int8_t *)src_mac,
				0x800, // 或者，ETHERTYPE_IP
				NULL,
				0,
				lib_net,
				0);
			int res = 0;
			res = libnet_write(lib_net); //发送数据包
			if (-1 == res)
			{
				perror("libnet_write");
				exit(-1);
			}

			libnet_destroy(lib_net); //销毁资源
		}
	}
	printf("----ok-----\n");
	return 0;
}
