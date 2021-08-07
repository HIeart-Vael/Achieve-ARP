#include <iostream>
#include <string>
#include "winsock2.h"

#pragma comment(lib, "ws2_32.lib")
//字节对齐必须是1
#pragma pack(1)
using namespace std;

unsigned char SRC_MAC[6] =  {0xA8, 0x7E, 0xEA, 0x81, 0x88, 0xAF};
unsigned char DEST_MAC[6] = {0xA8, 0x7E, 0xEA, 0x81, 0x88, 0xAF};

string SRC_IP = "10.38.204.26";
string DEST_IP = "127.0.0.1";

class ethernet_head
{
public:
    unsigned char dest_mac[6];   //目标主机MAC地址
    unsigned char source_mac[6]; //源端MAC地址
    unsigned short eh_type;      //以太网类型 - ARP帧类型值(0x0806)
};

class arp_head
{
public:
    unsigned short hardware_type; //硬件类型：以太网类型值(0x1)
    unsigned short protocol_type; //协议类型：IP协议类型为0X0800
    unsigned char add_len;        //硬件地址长度：MAC地址长度为6B
    unsigned char pro_len;        //协议地址长度：IP地址长度为4B
    unsigned short option;        //操作：ARP请求为1，ARP应答为2
    unsigned char sour_addr[6];   //源MAC地址：发送方的MAC地址
    unsigned long sour_ip;        //源IP地址：发送方的IP地址
    unsigned char dest_addr[6];   //目的MAC地址：ARP请求中该字段没有意义；ARP响应中为接收方的MAC地址
    unsigned long dest_ip;        //目的IP地址：ARP请求中为请求解析的IP地址；ARP响应中为接收方的IP地址
    unsigned char padding[18];
};

class arp_packet //最终arp包结构
{
public:
    ethernet_head eth; //以太网头部
    arp_head arp;      //arp数据包头部

    arp_packet();
};

arp_packet::arp_packet()
{
    for(int i=0; i<6; i++)
        this->eth.dest_mac[i] = DEST_MAC[i];

    for(int i=0; i<6; i++)
        this->eth.source_mac[i] = SRC_MAC[i];

    this->eth.eh_type = htons(0x0806);


    this->arp.hardware_type = htons(0x01);

    this->arp.protocol_type = htonl(0x0800);

    this->arp.add_len = 6;

    this->arp.pro_len = 4;

    this->arp.option = htonl(0x01);

    for(int i=0; i<6; i++)
        this->arp.sour_addr[i] = SRC_MAC[i];

    this->arp.sour_ip = inet_addr(SRC_IP.c_str());

    for(int i=0; i<6; i++)
        this->arp.dest_addr[i] = DEST_MAC[i];

    this->arp.dest_ip = inet_addr(DEST_IP.c_str());

    memset(this->arp.padding, 0, 18);
}

int main()
{
    arp_packet arp;
    // cout << arp.eth.dest_mac << endl;
    // cout << arp.eth.source_mac << endl;
    // cout << arp.eth.eh_type << endl;

    WSADATA wsaData;    
    WORD wVersionRequested;
    int errMsg;

    wVersionRequested = MAKEWORD(2 ,2);
    WSAStartup(wVersionRequested, &wsaData);

    SOCKET Socket = socket(AF_INET, SOCK_STREAM, 0);

    SOCKADDR_IN client_addr;
    memset(&client_addr, 0, sizeof(client_addr));   //每个字节都用0填充
    client_addr.sin_family = AF_INET;  //使用IPv4地址
    client_addr.sin_addr.s_addr = inet_addr(DEST_IP.c_str());  //具体的IP地址
    client_addr.sin_port = htons(1234);  //端口

    int is_success = connect(Socket, (PSOCKADDR)&client_addr, sizeof(SOCKADDR));  //请求连接
    //connect执行成功返回0，否则返回SOCKET_ERROR
    if(is_success != 0)
    {
        cout << "Failed to create, error code is: " << is_success << endl;
    }
    cout << "connection successful !" << endl;

    cout << sizeof(arp_packet);
    char buffer[60];

    memcpy(buffer, &arp, 60);
    for(int i=0; i<60; i++)
    {
        cout << buffer[i];
    }

    send(Socket, buffer, sizeof(arp_packet), 0);

    return 0;
}