
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


//get error
static std::string str_state;
#ifdef _WIN32
static int err_id;
LPVOID err_str;
#define getErrStr(str) { str_state = str;\
	err_id = WSAGetLastError();\
	::FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,\
		NULL, err_id, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), reinterpret_cast<LPTSTR>(&err_str), 0, NULL);\
	str_state += (char*)err_str; } 

#else//not WIN32

static int err_id;
#define getErrStr(str) { str_state = str;\
	str_state += strerror(errno); \
	err_id = errno;} 

#endif//WIN32

static struct timeval timeout = { 3, 0 };
//static int timeout = 3000;

int TCP_Connect(const string &device_ip);
int SendCmd(SOCKET sockfd, COMMOND_LIST cmd);
int RevData(SOCKET sockfd, char* data, long size);
int RevData_1(SOCKET sockfd, char* data);

int main()
{
	//…Ë±∏IP
	const string device_ip = "192.168.1.137";
	printf("try connect %s\n", device_ip);

	//tcp connect
	TCP_Connect(device_ip);

	return 0;
}

int TCP_Connect(const string &device_ip)
{
#ifdef _WIN32
	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0)
	{
		return false;
	}
#endif


	std::string ip;
	ip = device_ip;

	SOCKET csockfd = -1;
	bool is_connect = false;
	checkSocket((csockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), "ERROR: Socket Descriptor: ");

//#ifdef _WIN32
//	//set non-block
//	u_long ul = 1;
//	checkSocket(ioctlsocket(csockfd, FIONBIO, (unsigned long *)&ul), "ERROR: Set Non_Block Mode: ");
//#else
//	/*int flags = fcntl(sockfd, F_GETFL, NULL);
//	if(flags == -1 || SOCKET_ERROR == fcntl(csockfd, F_SETFL, flags | O_NONBLOCK)){
//	getErrStr("ERROR: Set Non_Block Mode: ");
//	procErr(str_state);
//	}*/
//#endif

	//set TCP and time out 2s
	const int on = 1;
	checkSocket(setsockopt(csockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on)), "ERROR: Set Socket: ");
	checkSocket(setsockopt(csockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)), "ERROR: Set Socket");
	checkSocket(setsockopt(csockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)), "ERROR: Set Socket");

	//socket address struct 
	struct sockaddr_in remote_addr;
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(PORT);
	checkSocket(inet_pton(AF_INET, ip.c_str(), &remote_addr.sin_addr), "ERROR: inet_pton ip: ");
	memset(remote_addr.sin_zero, 0, 8);

	//try to connect to service
	if (connect(csockfd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr)) != SOCKET_ERROR) {
		is_connect = true;
		printf("SUCESS: Connect to %s\n", ip);
	}
	else {
		printf("ERROR: Connect: ");
		return -1;
	}

	//receive msg,check if "service: wait for commond"
	char revbuf[BUFFER_SIZE] = {""};
	int num = 0;
	if ((num = recv(csockfd, revbuf, BUFFER_SIZE, 0)) <= 0)
	{
		printf("RECVE ERROR : %d", num);
		exit(1);
	}
	else
	{
		printf("OK: Recieve SUCCESS\n");
	}
	string s = revbuf;
	if (!strcmp(s.c_str(), "service: wait for commond"))
	{
		printf("[%s]\n", revbuf);
	}
	else
	{
		printf("WRONG: [%s]!=[service: wait for commond]\n", revbuf);
		exit(1);
	}

	//send commond
	SendCmd(csockfd, CMD_GETTXT);

	//reveive data
	char *data = new char[BUFFER_SIZE];
	RevData_1(csockfd, (char*)data);

	//send commond
	SendCmd(csockfd, CMD_GETPIC);

	//reveive data
	RevData_1(csockfd, (char*)data);

	//send commond
	SendCmd(csockfd, CMD_GETVIDEO);

	//reveive data
	RevData_1(csockfd, (char*)data);

	//send commond
	SendCmd(csockfd, CMD_GETWORD);

	//reveive data
	RevData_1(csockfd, (char*)data);

	//send commond
	SendCmd(csockfd, CMD_CLOSE);

	//reveive data
	RevData_1(csockfd, (char*)data);

	close(csockfd);
#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}


//send commond
int SendCmd(SOCKET sockfd, COMMOND_LIST cmd)
{
	switch (cmd)
	{
	case CMD_NULL:
		printf("null commond\n");
		break;
	case CMD_GETWORD:
		printf("get word commond\n");
		break;
	case CMD_GETPIC:
		printf("get picture commond\n");
		break;
	case CMD_GETVIDEO:
		printf("get video commond\n");
		break;
	case CMD_GETTXT:
		printf("get txt commond\n");
		break;
	case CMD_CLOSE:
		printf("close commond\n");
		break;
	default:
		printf("error commond\n");
		break;
	}

	//send commond
	char sdbuf[2] = { 0 };
	sdbuf[0] = cmd + '0';
	if ((send(sockfd, sdbuf, strlen(sdbuf), 0)) == -1)
	{
		printf("ERROR: Send Commond: ");
		exit(1);
	}
	printf("OK: Send Commond Done\n");
	return 0;
}

//receive data
int RevData(SOCKET sockfd, char* data, long size)
{
	long all_bytes = 0;
	long num = 0;
	//receive data untill (size) byte		
	while (all_bytes < size)
	{
		if ((num = recv(sockfd, (char*)(data + all_bytes), size - all_bytes, 0)) <= 0)
		{
			printf("ERROR: Receive Data: ");
			//procInfo(str_state);
			if ((err_id == EINTR || err_id == EWOULDBLOCK || err_id == EAGAIN) && num < 0) {
				continue;
			}
			else {
				exit(1);
			}
		}
		all_bytes += num;
	}

	printf("OK: Receive Data Done\n");

	return 0;
}

int RevData_1(SOCKET sockfd, char* data)
{

	int num = recv(sockfd, data, BUFFER_SIZE, 0);
	if (num > 0)
	{
		string d = data;
		d = d.substr(0, num);
		printf("[service: %s]\n", d.c_str());
	}
	else if (num == 0)
	{
		printf("Connection closed\n");
	}
	else
	{
		printf("recv failed: %d\n", WSAGetLastError());
		exit(1);
	}
}