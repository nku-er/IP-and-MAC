#include <pthread.h>
#define WIN32
#include <pcap.h>
#pragma   comment(   lib,   "wpcap.lib"   )// 库文件
#include <iostream>
using namespace std;

#pragma pack(1)
typedef struct FrameHeader_t {
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
} FrameHeader_t;

typedef struct ARPFrame_t { // ARP帧
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	BYTE SendIP[4];
	BYTE RecvHa[6];
	BYTE RecvIP[4];
} ARPFrame_t;
#pragma pack()

// 将char*类型的ip转换为BYTE*类型
BYTE* transform(char* ip)
{
	BYTE ip1[4];
	int j=0;
	for(int i=0;i<4;i++)
	{
		int temp = 0;
		for(;ip[j]!='.' && ip[j];j++)
		{
			temp = temp*10 + ip[j]-'0';
		}
		j++;
		ip1[i] = temp;
		//printf("%d.", ip1[i]);
	}
	return ip1;
}
pcap_t *adhandle;
BYTE * getMAC(char* sendIP, BYTE* sendMAC, char *ip)
{
	const u_char *pkt_data;
	pcap_pkthdr* pkt_header;
	ARPFrame_t *arpData;
	ARPFrame_t ARPFrame;
	// 使用全1的广播地址作为目的MAC地址
	// 本地主机模拟一个远端主机：使用66-66-66-66-66-66
	for(int i=0;i<6;i++)
	{
		ARPFrame.FrameHeader.DesMAC[i]=0xff;
		ARPFrame.FrameHeader.SrcMAC[i]=sendMAC[i];
		ARPFrame.SendHa[i] = sendMAC[i];
		ARPFrame.RecvHa[i]=0;
	}

	BYTE * sendIPBYTE = transform(sendIP);
	BYTE * ipBYTE = transform(ip);
	for(int i=0;i<4;i++)
	{
		ARPFrame.SendIP[i]=sendIPBYTE[i];
		ARPFrame.RecvIP[i]=ipBYTE[i];
	}


	ARPFrame.FrameHeader.FrameType=htons(0x0806);
	ARPFrame.HardwareType=htons(0x0001);
	ARPFrame.ProtocolType=htons(0x0800);
	ARPFrame.HLen=6;
	ARPFrame.PLen=4;
	ARPFrame.Operation=htons(0x0001);
	int result = pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	//cout << result <<endl;
	if(result == -1)
	{
		cout << "发送失败！\n";
		system("pause");
		return NULL;
	}
	else if(result == 0)
	{
		cout << "发送成功! 正在等待ARP响应";
		bool isGot = 0;  // 是否已经成功捕获到所需的数据包
		//int i=0;
		while(!isGot) 
		{
			//cout <<".";
			int temp = pcap_next_ex(adhandle, &pkt_header, &pkt_data) ; //捕获数据包
			if(temp != 1) continue; 
			arpData = (ARPFrame_t*)pkt_data;
			bool isARP = (arpData->FrameHeader.FrameType==htons(0x0806));  // 是否为ARP类型
			bool isOperation = (arpData->Operation==htons(0x2));  // 是否为ARP响应
			bool rightIP = 0;
			if(arpData->SendIP[0,1,2,3] == transform(ip)[0,1,2,3]) rightIP = 1;
			if(!isARP || !isOperation || !rightIP) continue;  // 如果要求不完全符合
			// if(!isARP) continue;  // 暂时只测试ARP包
			cout << "\n捕获到ARP响应：\n";
			isGot = 1; // 否则得到所需
		}
	}
	return arpData->SendHa;
}
// 获取本机MAC地址

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr_t *a;
	const u_char *pkt_data;
	pcap_pkthdr* pkt_header;
	ARPFrame_t *arpData;
	BYTE *tempp;
	char *ip;
	int inum;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];

    //1. 获取设备列表，得到本机网络接口及其接口上绑定的IP地址
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        cout << "获取失败！" << errbuf << endl; 
		system("pause");
        exit(1);
    }
    for(d=alldevs; d; d=d->next)
    {
		cout <<++i <<"、名字：" <<d->name <<"\n";
        if (d->description)
			cout << "   描述：" << d->description << endl;
        else
            cout << "无描述\n";

		for(a=d->addresses; a!=NULL; a=a->next)
		{
			if(a->addr->sa_family==AF_INET) // 判断该地址是否为IP地址
			{
				/* 得到网络接口设备的IP地址信息 */
				ip = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
				//printf("%s\n", ((struct sockaddr_in*)a->addr->sa_data));
				printf("\tIP地址:  %s\n", ip);
				printf("\t网络掩码: %s\n",inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr));
				if (a->broadaddr)
				  printf("\t广播地址: %s\n",inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr));
				if (a->dstaddr)
				  printf("\t目的地址: %s\n",inet_ntoa(((struct sockaddr_in *)a->dstaddr)->sin_addr));
			}
		}
    }

    if(i==0)
    {
        printf("\n无设备\n");
        return -1;
    }

	cout << "请输入序号：";
	cin >> inum;
    
    if(inum < 1 || inum > i)
    {
        cout << "输入超限" ;
        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    // 打开设备
	if((adhandle=pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		cout << "开启失败\n";
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}
	for(a=d->addresses; a!=NULL; a=a->next)
	{
		if(a->addr->sa_family==AF_INET) // 判断该地址是否为IP地址
		{
			/* 得到网络接口设备的IP地址信息 */
			ip = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
		}
	}

	/* 2. 得到本机MAC地址 */
	BYTE *myMAC;
	char* fakeIP = "112.112.112.112";  // 构造的虚假IP
	BYTE fakeMAC[6]={0x70,0x70,0x70,0x70,0x70,0x70};  // 虚假MAC
	myMAC = getMAC(fakeIP, fakeMAC, ip);  // 使用本机IP得到本机MAC地址
	printf("本机MAC地址：%02x-%02x-%02x-%02x-%02x-%02x;\r\n", 
				myMAC[0],
				myMAC[1],
				myMAC[2],
				myMAC[3],
				myMAC[4],
				myMAC[5]);
	printf("本机IP：%s\n\n\n", ip);

	// 3. 得到以太网内IP与MAC：
	while(1){
		cout << "请输入IP地址：";
		char getIP[50];
		cin>>getIP;
		BYTE *getMac;
		getMac = getMAC(ip, myMAC, getIP);
		printf("得到MAC地址：%02x-%02x-%02x-%02x-%02x-%02x;\r\n\n\n", 
					getMac[0],
					getMac[1],
					getMac[2],
					getMac[3],
					getMac[4],
					getMac[5]);
		if(getIP == ".") break;
	}
	
    system("pause");
    return 0;
}