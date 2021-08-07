#define HAVE_REMOTE //必须放在第一行
//#define HAVE_REMOTE    //Please do not include this file directly. Just define HAVE_REMOTE and then include pcap.h

#include <iostream>
#include <fstream>
#include "winsock2.h"
#include "pcap.h"
//#include "remote-ext.h"  //pcap_findalldevs_ex函数头文件
#pragma comment(lib, "wpcap.lib")

#define _W64    //网上查的，兼容性问题，防止编译报错
using namespace std;

#define ETH_ARP 0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define HARDWARE  1  //硬件类型字段值为表示以太网地址
#define ETH_IP  0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define REQUEST   1   //ARP请求
#define RESPONSE  2      //ARP应答
#define IPTOSBUFFERS  12
#define IPADDR	1	//自定义常量：IP地址
#define MACADDR	2	//自定义常量：MAC地址
#define MAXNUM  10	//自定义常量：最大网络设备数量
#pragma warning( disable : 4996 )

//14字节以太网首部
class EthHeader
{
public:
	u_char DestMAC[6];    //目的MAC地址 6字节
	u_char SourMAC[6];   //源MAC地址 6字节
	u_short EthType;         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};


//28字节ARP帧结构
class ArpHeader
{
public:
	unsigned short hdType;   //硬件类型
	unsigned short proType;   //协议类型
	unsigned char hdSize;   //硬件地址长度
	unsigned char proSize;   //协议地址长度
	unsigned short op;   //操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	u_char smac[6];   //源MAC地址
	u_char sip[4];   //源IP地址
	u_char dmac[6];   //目的MAC地址
	u_char dip[4];   //目的IP地址
};

//定义整个arp报文包，总长度42字节
class ArpPacket 
{
public:
	EthHeader ed;
	ArpHeader ah;
};

ofstream fout("achieve_arp_logs.txt");  //日志文件

char filter[] = "ethor proto \\arp"; //第一个'\'为转义,设置arp过滤规则
bpf_program fcode;
pcap_pkthdr* header;
const u_char* pkt_data;  //指向捕获的数据包具体数据
pcap_t *adhandle; //打开网络适配器，捕捉实例,是pcap_open返回的对象
u_int netmask;
u_char net_ip_addr[MAXNUM + 1][4];//所有网络设备的ip地址，假设网络设备最多10个
u_char net_mac_addr[6];//选择的设备的mac地址
u_char dst_ip[4] = { 0xc0,0xa8,0x7f,0x80 }; //默认目的ip地址 192.168.127.128 本机VMnet8网卡
u_char dst_mac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff }; //目的MAC地址，初值为ff-ff-ff-ff-ff-ff代表广播
u_char random_mac[6] = { 0x12, 0x24, 0x56, 0x78, 0x9a, 0xbc };//为获取本机mac而设置的随机mac
time_t local_tv_sec;
tm* ltime;
char timestr[16];

/*获取适配器ip地址*/
char* iptos(u_long in, int num);
/*封装ARP数据包并广播发送*/
int sendARP(u_char* src_ip, u_char* dst_ip);
/*通过构造一个外来ARP请求获取当前网卡的MAC地址*/
int getMacAddr(int curAdapterNo);
/*打印ip或mac地址*/
void printAddr(u_char* addr, int type);

int main()
{

    /************************************************************
    * * *网络适配器的详细信息存储在一个结构体 pcap_if_t 中* * *
    struct pcap_if_t
    {
        struct pcap_if_t *next;         //如果不为空，则指向下一个元素
        char *name;                     //设备名称
        char *description;              //描述设备
        struct pcap_addr *addresses;    //接口地址列表 pcap_addr为结构体
        bpf_u_int32 flags;              //标志位，标志是否 loopback 设备
    };
    *************************************************************/

   /*************************************************************
    * * *接口地址列表* * *
    struct pcap_addr pcap_addr_t;
    struct pcap_addr
    {
        struct pcap_addr *next;         //如果不为空，则指向下一个元素
        struct sockaddr *addr;          //接口 IP 地址
        struct sockaddr *netmask;       //接口网络掩码
        struct sockaddr *broadaddr;     //接口广播地址
        struct sockaddr *dstaddr;       //接口 P2P 目的地址
    };
   *************************************************************/
    /* 获取本机设备列表 */
    pcap_if_t *alldevs, *d;  //d 用来查找并打印输出的指针
    char errbuf[PCAP_ERRBUF_SIZE];  //用于存储错误信息
    int Ret;  //用于检查
    Ret = pcap_findalldevs(&alldevs, errbuf);
    if(Ret == -1)
    {
        cout << "Error in pcap_findalldevs:" << errbuf << endl;
        fout << "Error in pcap_findalldevs:" << errbuf << endl;
        exit(1);
    }

    /* 打印列表 */
    int i = 0;  //for的循环变量
    for(d=alldevs; d; d=d->next)
    {
        cout << ++i << "." << d->name << endl;
        fout << i << "." << d->name << endl;
        if(d->description)
        {
            cout << d->description ;
            fout << d->description ;
        }
        else
        {
            cout << "No description available" << endl;
            fout << "No description available" << endl;
        }

        //查询并保存网络设备的ip地址
        char* c_address = "0.0.0.0";
        for (pcap_addr_t *a = d->addresses; a; a = a->next)
        {
            
            if (a->addr->sa_family == AF_INET && a->addr)
            {
                c_address = iptos(((SOCKADDR_IN*)a->addr)->sin_addr.s_addr, i);
                break;
            }
        }
        cout << "   IP address: " << c_address << endl;
        fout << "   IP address: " << c_address << endl;
    }
    if(i == 0)
    {
        cout << endl << "No interfaces found!" << endl;
        fout << endl << "No interfaces found!" << endl;
        return -1;
    }

    cout << "Please enter the interface number (1~" << i << "): " ;
    fout << "Please enter the interface number (1~" << i << "): " ;
    int inum;  //用户输入的数字
    cin >> inum;
    fout << "the number input is: " << inum <<endl;

    if(inum<1 || inum>i)  //合法性检查
    {
        cout << "Error! Please input the valid number!" << endl;
        fout << "Error! Please input the valid number!" << endl;

		pcap_freealldevs(alldevs);  //释放设备列表
		return -1;
    }

    /* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);  //执行完成后，此时d为当前选择的适配器

    /* 打开设备 */
    /**********************************************************
    typedef struct pcap pcap_t
    struct pcap
    {
        ADAPTER * adapter;
        LPPACKET Packet;
        int linktype;           //数据链路层类型
        int linktype_ext;       //linktype 成员扩展信息
        int offset;             //时区偏移
        int activated;          //捕获准备好否
    … };
    ***********************************************************/
    // pcap_open_live（）的返回值是 pcap_t 类型的指针

    adhandle = pcap_open_live(  d->name,    //指定适配器名字
                                65535,      //捕获包最大字节限制 65535
                                1,          //混杂模式
                                1000,       //读取超时最大 1000 毫秒
                                errbuf      //错误信息保存在 errbuf
                             );
    if(adhandle == NULL)
    {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		fout << endl << "Unable to open the adapter. " << d->name << " is not supported by WinPcap" << endl;
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
    }

    Ret = getMacAddr(inum);
    //未能自动获取到本机mac地址，则需要手动输入
	if (Ret != 0) {
		cout << "Cannot get MAC address automatically, please input MAC address: " ;
		fout << "Cannot get MAC address automatically, please input MAC address: " ;
		u_int temp;
		for (i = 0; i < 6; i++)
        {
			cin >> temp;
			net_mac_addr[i] = temp;
			fout << temp;
		}
		fout << endl;
	}

    char option;  //y or n
    cout << "Use default destination IP(192.168.127.128)? Y(y)/N(n): " ;
    fout << "Use default destination IP(192.168.127.128)? Y(y)/N(n): " ;
    
    getchar();  //清空\n，否则option的值为\n
    option = cin.get();
    fout << option << endl;
	if (option == 'N' || option == 'n') {
		cout << "Input the IP Address of destination: " ;
		fout << "Input the IP Address of destination: " ;
		u_int temp;
		for (i = 0; i < 4; i++)
        {
			cin >> temp;
			dst_ip[i] = temp;
			fout << temp;
		}
		fout << endl;
	}
	cout << "The MAC Address of Adapter " << inum << ": " ;
	fout << "The MAC Address of Adapter " << inum << ": " ;
	printAddr(net_mac_addr, MACADDR);
	cout << "The IP Address of Adapter " << inum << ": " ;
	fout << "The IP Address of Adapter " << inum << ": " ;
	printAddr(net_ip_addr[inum], IPADDR);
	cout << "The IP Address of destination: " ;
	fout << "The IP Address of destination: " ;
	printAddr(dst_ip, IPADDR);

    Ret = sendARP(net_ip_addr[inum], dst_ip);
    if (Ret == 0)
    {
        cout << "\nSend packet successfully\n" << endl;
        fout << "\nSend packet successfully\n" << endl;
    }
    else
    {
        cout << "Failed to send packet due to: " << GetLastError() << endl;
        fout << "Failed to send packet due to: " << GetLastError() << endl;
    }

    netmask = ((sockaddr_in *)((d->addresses)->netmask))->sin_addr.S_un.S_addr;
    pcap_compile(adhandle, &fcode, filter, 1, netmask); //编译过滤器
    pcap_setfilter(adhandle, &fcode);                   //设置过滤器

    /* 释放设备列表 */
    pcap_freealldevs(alldevs);
    i = 0;

    cout << "Catching packets...\n" << endl;
    fout << "Catching packets...\n" << endl;

    //获取数据包并解析
    /*************************************************************************************
    int pcap_next_ex ( pcap_t * p, struct pcap_pkthdr** pkt_header, const u_char ** pkt_data )
        参数：  p：指定的适配器名称；
                pkt_header：指向捕获数据包的首部；
                pkt_data：指向捕获的数据包具体数据
        返回值：整数值，具体取值的含义如下：
                1：数据包读取成功；
                0：如果超时时间到，则 pkt_header 和 pkt_data 都不指向有用的数据包；
                -1：出现错误；
                2：离线捕获（文件操作）遇到文件尾部的 EOF。
    **************************************************************************************/

    /**************************************************************************************
    struct pcap_pkthdr
    {
        struct timeval ts;          //时间戳
        bpf_u_int32 caplen;         //当前分组长度
        bpf_u_int32 len;            //数据包的长度
    }；
    ***************************************************************************************/
    int begin = -1;
    while (Ret = pcap_next_ex(adhandle, &header, &pkt_data) >= 0)
    {
        //超时
        if (Ret == 0)
        {
            continue;
        }

        //解析ARP包，ARP包封装在MAC帧，MAC帧首部占14字节
        ArpHeader *arpheader = (ArpHeader *)(pkt_data + 14);
        if (begin != 0)
        {
            //比较内存前sizeof(arpheader->sip个字节，完全相同返回0
            begin = memcmp(net_ip_addr[inum], arpheader->sip, sizeof(arpheader->sip));
            if (begin != 0)
            {
                continue;
            }
        }
        cout << "\nmessage " << dec << i++ << ":" << endl;
        fout << "\nmessage " << dec << i << ":" << endl;
        //设置标志，当收到之前发送的request的reply时结束捕获
        bool ok = false;
        if (arpheader->op == 256)
        {
            cout << "request message." << endl;
            fout << "request message." << endl;
        }
        else
        {
            cout << "reply message." << endl;
            fout << "reply message." << endl;
            //如果当前报文时reply报文，则通过比较ip来判断是否时之前发送的request对应的reply
            if (memcmp(arpheader->dip, net_ip_addr[inum], sizeof(arpheader->dip)) == 0)
            {
                memcpy(dst_mac, arpheader->smac, 6);
                ok = true;
            }
        }
        //获取以太网帧长度
        cout << "ARP packet length: " << header->len << endl;
        fout << "ARP packet length: " << header->len << endl;
        //获取时间戳
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
        cout << "current time: " << timestr << endl;
        fout << "current time: " << timestr << endl;
        //打印源ip
        cout << "source ip: ";
        fout << "source ip: ";
        printAddr(arpheader->sip, IPADDR);
        //打印目的ip
        cout << "destination ip: ";
        fout << "destination ip: ";
        printAddr(arpheader->dip, IPADDR);
        //打印源mac
        cout << "source mac: ";
        fout << "source mac: ";
        printAddr(arpheader->smac, MACADDR);
        //打印目的mac
        cout << "destination mac: ";
        fout << "destination mac: ";
        printAddr(arpheader->dmac, MACADDR);

        if (ok)
        {
            cout << "Get the MAC address of destination: ";
            fout << "Get the MAC address of destination: ";
            printAddr(dst_mac, MACADDR);
            cout << "\nEnd of catching...\n" << endl;
            fout << "\nEnd of catching...\n" << endl;
            break;
        }
    }

    fout.close();

    return 0;
}

/*获取适配器ip地址, 代码来源于官方文档*/
char* iptos(u_long in, int num)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;
	p = (u_char*)& in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	memcpy(net_ip_addr[num], p, 4);
	return output[which];
}

/*通过构造一个外来ARP请求获取当前网卡的MAC地址*/
int getMacAddr(int curAdapterNo)
{
	u_char src_ip[4] = { 0x12, 0x34, 0x56, 0x78 };	//随机一个外部发送方的ip地址
	u_char dst_ip[4];								
	memcpy(dst_ip, net_ip_addr[curAdapterNo], 4);	//目的ip地址设置为本机的适配器id
	memcpy(net_mac_addr, random_mac, 6);			//外部发送方的mac地址设置为随机的mac地址
	int res = sendARP(src_ip, dst_ip);
	if (res != 0) {
		return -1;
	}
	while (res = pcap_next_ex(adhandle, &header, &pkt_data) >= 0) {
            if (res == 0) {
			continue;
		}
		ArpHeader* arph = (ArpHeader*)(pkt_data + 14);
		if (arph->op != 256) {
			if (memcmp(arph->dip, src_ip, sizeof(src_ip)) == 0) {	//收到了伪装ARP请求request对应的reply，解析该reply包获得本机mac地址
				memcpy(net_mac_addr, arph->smac, 6);
				break;
			}
		}
	}

	return 0;
}

/*封装ARP数据包并广播发送*/
int sendARP(u_char * src_ip, u_char * dst_ip)
{
	unsigned char sendbuf[42]; //arp包结构大小，42个字节
	EthHeader eh;
	ArpHeader ah;
	memcpy(eh.DestMAC, dst_mac, 6);		//以太网首部目的MAC地址，全为广播地址
	memcpy(eh.SourMAC, net_mac_addr, 6);//以太网首部源MAC地址
	memcpy(ah.smac, net_mac_addr, 6);   //ARP字段源MAC地址
	memcpy(ah.dmac, dst_mac, 6);		//ARP字段目的MAC地址
	memcpy(ah.sip, src_ip, 4);			//ARP字段源IP地址
	memcpy(ah.dip, dst_ip, 4);			//ARP字段目的IP地址
	eh.EthType = htons(ETH_ARP);		//htons：将主机的无符号短整形数转换成网络字节顺序
	ah.hdType = htons(HARDWARE);
	ah.proType = htons(ETH_IP);			//上层协议设置为IP协议
	ah.hdSize = 6;
	ah.proSize = 4;
	ah.op = htons(REQUEST);
	memset(sendbuf, 0, sizeof(sendbuf));   //ARP清零
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	return pcap_sendpacket(adhandle, sendbuf, 42);	// 发送ARP数据包并返回发送状态
}



/*打印ip地址或mac地址*/
void printAddr(u_char * addr, int type)
{
	int size = (type == IPADDR) ? 4 : 6;  //IPADDR->size=4 MACADDR->size=6

    if(size == 4)
    {
        for (int i = 0; i < 3; i++)
        {
            cout << dec << (int)addr[i] << ".";
            fout << dec<< (int)addr[i] << ".";
        }
        cout << dec << (int)addr[3] << endl;
        fout << dec << (int)addr[3] << endl;
    }
    else
    {
        for (int i = 0; i < 5; i++)
        {
            cout << hex << (int)addr[i] << "-";
            fout << hex << (int)addr[i] << "-";
        }
        cout << hex << (int)addr[5] << endl;
        fout << hex << (int)addr[5] << endl;
    }

}