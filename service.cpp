
#include<stdio.h>
#include<iostream>
#include<string>
#include<string.h>
#include<vector>
using namespace std;


#ifdef _WIN32
#include<WinSock2.h>
#include<Ws2tcpip.h>
#include <IPHlpApi.h>
#include <Windows.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"IPHlpApi.lib")

#else
#include <stdlib.h>
#include <unistd.h>  
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>   
#include <fcntl.h>

#endif

#ifndef SOCKET
#define SOCKET int
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif


#define close closesocket
#define PORT 8088
#define BUFFER_SIZE 1024
#define checkSocket(val,str)\
	if(val == -1){\
		std::cout<<str<<" "<<strerror(errno)<<std::endl;\
		return -1;\
	}	

typedef enum COMMOND_LIST
{
	CMD_NULL = 0,
	CMD_GETWORD,
	CMD_GETPIC,
	CMD_GETVIDEO,
	CMD_GETTXT,
	CMD_CLOSE,
}COMMOND_LIST;

static std::vector<std::string> local_ip;


int GetLocalIp(std::vector<std::string> &local_ip);
int Communication(SOCKET csockfd);
int RevCmd(SOCKET sockfd, COMMOND_LIST &cmd);
int SendData(SOCKET sockfd, char* data, long size);
int RecvData(SOCKET sockfd, char* data, long size);


int main()
{
#ifdef _WIN32
	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0)
	{
		return false;
	}
#endif

	//BOOL on = TRUE;
	const int on = 1;

	//set local addr
	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(PORT);
	socklen_t nlen = sizeof(servaddr);

	//set broadcast addr
	struct sockaddr_in addrFrom;
	memset(&addrFrom, 0, sizeof(struct sockaddr_in));
	addrFrom.sin_family = AF_INET;
	addrFrom.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	addrFrom.sin_port = htons(PORT);

	//creat TCP socket
	SOCKET tcp_sockfd;
	checkSocket((tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0)), "Socket Despcritor: ");
	checkSocket(setsockopt(tcp_sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on)), "Set: ");
	checkSocket((bind(tcp_sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr))), "Bind: ");
	checkSocket(listen(tcp_sockfd, 10), "Listen: ");

	//creat new UDP
	while (1)
	{
		//UDP broadcast;
		SOCKET udp_sockfd;
		checkSocket((udp_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)), "Socket Despcritor: ");
		checkSocket(setsockopt(udp_sockfd, SOL_SOCKET, SO_BROADCAST, (char*)&on, sizeof(on)), "Set Socket: ");
		checkSocket((bind(udp_sockfd, (struct sockaddr*)&(servaddr), sizeof(servaddr))), "Bind: ");
		

		//get local ip
		std::string lo_ip;
		int ip_len;
		GetLocalIp(local_ip);
		for (int i = 0; i < local_ip.size(); ++i)
		{
			if (local_ip[i].substr(0, 7) == "192.168")
			{
				/*lo_ip = new char(local_ip[i].size());
				memcpy(lo_ip, local_ip[i].c_str(), local_ip[i].size());*/
				ip_len = local_ip[i].size();
				lo_ip = local_ip[i].substr(0, ip_len);
			}
		}
		std::cout << "Local Ip\t\t" << lo_ip << std::endl;
		std::cout << "clinet should send\t[Are you ok]\tthen we can get connect\n";

		//set send message
		char *sendmsg = new char[ip_len];
		memcpy(sendmsg, lo_ip.c_str(), ip_len);
		//std::cout << "sendmsg\t\t\t" << sendmsg << std::endl;

		fd_set rset;
		FD_ZERO(&rset);
		int maxsockfd = max(tcp_sockfd, udp_sockfd) + 1;
		while (1) {
			FD_ZERO(&rset);
			FD_SET(tcp_sockfd, &rset);	
			FD_SET(udp_sockfd, &rset);	

			if (select(maxsockfd, &rset, NULL, NULL, NULL) < 0)
			{
				if (errno == EINTR)
					continue;

				std::cout << "Select: " << strerror(errno) << std::endl;
				return 1;
			}

			//if UDP
			if (FD_ISSET(udp_sockfd, &rset)) {
				//reveice broadcast and check if "Are"
				char revmsg[BUFFER_SIZE] = { 0 };
				if (recvfrom(udp_sockfd, revmsg, BUFFER_SIZE, 0, (struct sockaddr*)&addrFrom, &nlen) < 0
					|| strncmp(revmsg, "Are", 3)) {
					continue;
				}
				std::cout << "receive: " << revmsg << std::endl;

				//if receive "Are you ok", send local information
				if (!strcmp(revmsg, "Are you ok")) {
					//send local information
					checkSocket(sendto(udp_sockfd, sendmsg, strlen(sendmsg), 0, (sockaddr*)&addrFrom, nlen), "Send: ");
					std::cout << "send: " << sendmsg << std::endl;
				}
				continue;
			}

			//if TCP
			if (FD_ISSET(tcp_sockfd, &rset)) {
				close(udp_sockfd);
				Communication(tcp_sockfd);
				break;//create new broadcast
			}
		}
	}
	return 0;
}

int GetLocalIp(std::vector<std::string> &local_ip) //WinGetIp
{
#ifdef _WIN32

	//PIP_ADAPTER_INFO结构体指针存储本机网卡信息
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	//得到结构体大小,用于GetAdaptersInfo参数
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	//调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	//记录网卡数量
	int netCardNum = 0;
	//记录每张网卡上的IP地址数量
	int IPnumPerNetCard = 0;
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		//如果函数返回的是ERROR_BUFFER_OVERFLOW
		//则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
		//这也是说明为什么stSize既是一个输入量也是一个输出量
		//释放原来的内存空间
		delete pIpAdapterInfo;
		//重新申请内存空间用来存储所有网卡信息
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	if (ERROR_SUCCESS == nRel)
	{
		//输出网卡信息
		//可能有多网卡,因此通过循环去判断
		while (pIpAdapterInfo)
		{
			/*cout << "网卡数量：" << ++netCardNum << endl;
			cout << "网卡名称：" << pIpAdapterInfo->AdapterName << endl;
			cout << "网卡描述：" << pIpAdapterInfo->Description << endl;
			switch (pIpAdapterInfo->Type)
			{
			case MIB_IF_TYPE_OTHER:
			cout << "网卡类型：" << "OTHER" << endl;
			break;
			case MIB_IF_TYPE_ETHERNET:
			cout << "网卡类型：" << "ETHERNET" << endl;
			break;
			case MIB_IF_TYPE_TOKENRING:
			cout << "网卡类型：" << "TOKENRING" << endl;
			break;
			case MIB_IF_TYPE_FDDI:
			cout << "网卡类型：" << "FDDI" << endl;
			break;
			case MIB_IF_TYPE_PPP:
			printf("PP\n");
			cout << "网卡类型：" << "PPP" << endl;
			break;
			case MIB_IF_TYPE_LOOPBACK:
			cout << "网卡类型：" << "LOOPBACK" << endl;
			break;
			case MIB_IF_TYPE_SLIP:
			cout << "网卡类型：" << "SLIP" << endl;
			break;
			default:

			break;
			}
			cout << "网卡MAC地址：";*/
			for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++)
				if (i < pIpAdapterInfo->AddressLength - 1)
				{
					//printf("%02X-", pIpAdapterInfo->Address[i]);
				}
				else
				{
					//printf("%02X\n", pIpAdapterInfo->Address[i]);
				}
			//cout << "网卡IP地址如下：" << endl;
			//可能网卡有多IP,因此通过循环去判断
			IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo->IpAddressList);
			do
			{
				/*cout << "该网卡上的IP数量：" << ++IPnumPerNetCard << endl;
				cout << "IP 地址：" << pIpAddrString->IpAddress.String << endl;
				cout << "子网地址：" << pIpAddrString->IpMask.String << endl;
				cout << "网关地址：" << pIpAdapterInfo->GatewayList.IpAddress.String << endl;*/
				local_ip.push_back(pIpAddrString->IpAddress.String);
				pIpAddrString = pIpAddrString->Next;
			} while (pIpAddrString);
			pIpAdapterInfo = pIpAdapterInfo->Next;
			//cout << "--------------------------------------------------------------------" << endl;
		}

	}
	//释放内存空间
	if (pIpAdapterInfo)
	{
		delete pIpAdapterInfo;
	}
	/*for (int i=0;i<local_ip.size(); ++i)
	{
	printf("ip is %s\n", local_ip[i]);
	}*/

#else
	struct ifreq *ifr, *ifend;
	struct ifreq ifreq;
	struct ifconf ifc;
	struct ifreq ifs[10];
	SOCKET local_sockfd;
	local_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ifc.ifc_len = sizeof(ifs);
	ifc.ifc_req = ifs;
	if (ioctl(local_sockfd, SIOCGIFCONF, &ifc) < 0) {
		printf("ioctl(SIOCGIFCONF): %m/n");
		return -1;
	}
	ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
	for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
		if (ifr->ifr_addr.sa_family == AF_INET) {
			//strncpy(ifreq.ifr_name, "ens3",sizeof(ifreq.ifr_name));
			strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
			if (ioctl(local_sockfd, SIOCGIFHWADDR, &ifreq) < 0) {
				printf("SIOCGIFHWADDR(%s): %m/n", ifreq.ifr_name);
				return -1;
			}
			local_ip.push_back(inet_ntoa(((struct sockaddr_in *)  &ifr->ifr_addr)->sin_addr));
			printf("\nIp Address %s\t", inet_ntoa(((struct sockaddr_in *)  &ifr->ifr_addr)->sin_addr));
			printf("\nDevice %s -> Ethernet %02x:%02x:%02x:%02x:%02x:%02x\t", ifreq.ifr_name,
				(int)((unsigned char *)&ifreq.ifr_hwaddr.sa_data)[0],
				(int)((unsigned char *)&ifreq.ifr_hwaddr.sa_data)[1],
				(int)((unsigned char *)&ifreq.ifr_hwaddr.sa_data)[2],
				(int)((unsigned char *)&ifreq.ifr_hwaddr.sa_data)[3],
				(int)((unsigned char *)&ifreq.ifr_hwaddr.sa_data)[4],
				(int)((unsigned char *)&ifreq.ifr_hwaddr.sa_data)[5]);
		}
	}
#endif // _WIN32
	return 0;
}

int Communication(SOCKET csockfd)
{
	//set time out
	struct timeval timeout = { 10, 0 };
	checkSocket(setsockopt(csockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)), "Set Send Time Out: ");
	checkSocket(setsockopt(csockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)), "Set Receive Time Out: ");

	// Wait a connection, and obtain a new socket file despriptor for single connection */
	std::cout << "Wait For Connect." << std::endl;

	struct sockaddr_in addr_remote;
	int	sin_size = sizeof(struct sockaddr_in);
	SOCKET nsockfd;
	checkSocket((nsockfd = accept(csockfd, (struct sockaddr *)&addr_remote, (socklen_t *__restrict)&sin_size)), "Failed to Connect: ");

	std::cout << "OK: Server has got connect from " + string(inet_ntoa(addr_remote.sin_addr)) << std::endl;

	//send commond
	string sendc = "service: wait for commond";
	if ((send(nsockfd, sendc.c_str(), sendc.size(), 0)) <= 0)
	{
		std::cout << "ERROR: Send State: " << std::endl;
		return 1;
	}
	std::cout << "OK: Send Stat: " << sendc << std::endl;

	//wait commond
	string str;
	while (1)
	{
		COMMOND_LIST cmd = CMD_NULL;
		RevCmd(nsockfd, cmd);

		switch (cmd)
		{
		case CMD_GETWORD: {
			printf("OK: Received GetWord Commond\n");

			str = "HH,No World!";
			/*char *data = new char[str.size()];
			if (SendData(nsockfd, (char*)data, sizeof(char)))
			{
				cmd = CMD_CLOSE;
			}*/
			int len = send(nsockfd, str.c_str(), str.size(), 0);
			std::cout << "send data: " << str.c_str();
			while (len < str.size())
			{
				//std::cout << "data send uncompleted" << std::endl;
				str = str.substr(len + 1, str.size());
				len = send(nsockfd, str.c_str(), str.size(), 0);
				std::cout << str.c_str();
			}
			if (len == SOCKET_ERROR)
			{
				break;
			}
			std::cout << endl;
			break;
		}
		case CMD_GETPIC: {
			printf("OK: Received GetPic Commond\n");

			str = "HH,No Picture!";
			/*char *data = new char[str.size()];
			if (SendData(nsockfd, (char*)data, sizeof(char)))
			{
			cmd = CMD_CLOSE;
			}*/
			int len = send(nsockfd, str.c_str(), str.size(), 0);
			std::cout << "send data: " << str.c_str();
			while (len < str.size())
			{
				//std::cout << "data send uncompleted" << std::endl;
				str = str.substr(len + 1, str.size());
				len = send(nsockfd, str.c_str(), str.size(), 0);
				std::cout << str.c_str();
			}
			if (len == SOCKET_ERROR)
			{
				break;
			}
			std::cout << endl;
			break;
		}
		case CMD_GETVIDEO:{
			printf("OK: Received GetVideo Commond\n");

			str = "HH,No Video!";
			/*char *data = new char[str.size()];
			if (SendData(nsockfd, (char*)data, sizeof(char)))
			{
			cmd = CMD_CLOSE;
			}*/
			int len = send(nsockfd, str.c_str(), str.size(), 0);
			std::cout << "send data: " << str.c_str();
			while (len < str.size())
			{
				//std::cout << "data send uncompleted" << std::endl;
				str = str.substr(len + 1, str.size());
				len = send(nsockfd, str.c_str(), str.size(), 0);
				std::cout << str.c_str();
			}
			if (len == SOCKET_ERROR)
			{
				break;
			}
			std::cout << endl;
			break;
		}
		case CMD_GETTXT: {
			printf("OK: Received GetTxt Commond\n");

			str = "HH,No txt!";
			/*char *data = new char[str.size()];
			if (SendData(nsockfd, (char*)data, sizeof(char)))
			{
			cmd = CMD_CLOSE;
			}*/
			int len = send(nsockfd, str.c_str(), str.size(), 0);
			std::cout << "send data: " << str.c_str();
			while (len < str.size())
			{
				//std::cout << "data send uncompleted" << std::endl;
				str = str.substr(len + 1, str.size());
				len = send(nsockfd, str.c_str(), str.size(), 0);
				std::cout << str.c_str();
			}
			if (len == SOCKET_ERROR)
			{
				break;
			}
			std::cout << endl;
			break;
		}
		case CMD_CLOSE: {
			std::cout << "OK: Received Close Commond" << std::endl;
			break;
		}
		default: {
			std::cout << "ERROR COMMOND" << std::endl;
			break;
		}

		}
		if (cmd == CMD_CLOSE)
		{
			close(nsockfd);
			std::cout << "OK: Disconnect" << std::endl;
			break;
		}
	}//wait commond
	return 0;
}

//cmd see as enum COMMOND_LIST
int RevCmd(SOCKET sockfd, COMMOND_LIST &cmd)
{
	char revbuf[BUFFER_SIZE];
	int num = 0;


	while ((num = recv(sockfd, revbuf, BUFFER_SIZE, 0)) <= 0)
	{
		if ((errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) && num < 0) {//receive error
			continue;
		}
		else {//disconnected
			std::cout<<"ERROR: Receive Commond: "<<std::endl;
			cmd = CMD_CLOSE;
			return 1;
		}
	}
	//cout << revbuf << "asdf" << endl;
	//cout << num << endl;
	if (num != 1) {//commond error
		cmd = CMD_NULL;
	}
	else {
		revbuf[num] = '\0';
		int cmd_index = revbuf[0] - '0';
		cmd = (COMMOND_LIST)cmd_index;

		printf("OK: Get Commond: %d\n", cmd_index);
	}
	return 0;
}


//transport
int SendData(SOCKET sockfd, char* data, long size)
{
	long all_bytes = 0;
	long num = 0;
	while (all_bytes < size)
	{
		if ((num = send(sockfd, data + all_bytes, size - all_bytes, 0)) <= 0)
		{
			if ((errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) && num < 0) {//receive error
				continue;
			}
			else {//disconnected
				printf("ERROR: Send Data: ");
				return 1;
			}
		}
		all_bytes += num;
	}

	printf("OK: Send Data Done\n");

	return 0;
}

//transport data
int RecvData(SOCKET sockfd, char* data, long size)
{
	long all_bytes = 0;
	long num = 0;
	while (all_bytes < size)
	{
		if ((num = recv(sockfd, data + all_bytes, size - all_bytes, 0)) <= 0)
		{
			if ((errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) && num < 0) {//receive error
				continue;
			}
			else {//disconnected
				printf("ERROR: Receive Data: ");
				return 1;
			}
		}
		all_bytes += num;
	}
	//printf("%d %d\n", num, all_bytes);
	printf("OK: Receive Data Done\n");

	return 0;
}