#pragma pack(4)

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
									
#define ICMP_ECHOREP		0		
#define ICMP_DESTUNREACH    3		
#define ICMP_SRCQUENCH      4		
#define ICMP_REDIRECT       5		
#define ICMP_ECHO           8		
#define ICMP_TIMEOUT       11		
#define ICMP_PARMERR       12		
#define MAX_HOPS           30		
#define ICMP_MIN			8		


typedef struct iphdr				
{
	unsigned int   h_len : 4;       
	unsigned int   version : 4;     
	unsigned char  tos;             
	unsigned short total_len;       
	unsigned short ident;           
	unsigned short frag_and_flags;  
	unsigned char  ttl;             
	unsigned char  proto;           
	unsigned short checksum;        
	unsigned int   sourceIP;        
	unsigned int   destIP;          
} IpHeader;


typedef struct _ihdr				
{
	BYTE   i_type;					
	BYTE   i_code;					
	WORD   i_cksum;					
									
	WORD   i_id;					
	WORD   i_seq;					
	
	ULONG	SendTimeStamp;						
				
} IcmpHeader;

#define DEF_PACKET_SIZE         52  
#define MAX_PACKET            1024 


int SetTimetoLive(SOCKET s, int nTimeToLive)
{
	int     nRet;

	nRet = setsockopt(s, IPPROTO_IP, IP_TTL, (LPSTR)&nTimeToLive, sizeof(int)); 
	if (nRet == SOCKET_ERROR)													
	{																			
		printf("setsockopt(IP_TTL) failed: %d\n",
			WSAGetLastError());
		return 0;
	}
	return 1;
}

//    Расшифровка ответа
int DecodeResponse(char *buf, int bytes, SOCKADDR_IN *from, int ttl, ULONG *SendTime)
{
	IpHeader       *iphdr = NULL;
	IcmpHeader     *icmphdr = NULL;
	unsigned short  iphdrlen;

	struct hostent *lpHostent = NULL;
	struct in_addr  inaddr = from->sin_addr;

	ULONG			AnswTime;

	iphdr = (IpHeader *)buf;  
	iphdrlen = iphdr->h_len * 4; 

	if (bytes < iphdrlen + ICMP_MIN)
	{
		printf("Too few bytes from %s\n", inet_ntoa(from->sin_addr));
	}

	icmphdr = (IcmpHeader*)(buf + iphdrlen); // icmp-header извлекаем из ipheader'a

	AnswTime = GetTickCount()-(*SendTime); // получение разности времени отправки и времени возврата

	if (AnswTime == 0)
	{
		AnswTime = 1;
	}

	switch (icmphdr->i_type)
	{

	case ICMP_ECHOREP:     // Эхо-ответ

		lpHostent = gethostbyaddr((const char *)&from->sin_addr, AF_INET, sizeof(struct in_addr));  // Получает доменное имя узла, соответствующее переданному IP-адресу

		if (lpHostent != NULL)
		{
			if (AnswTime > 1000)
			{
				printf(" %c %s (%s)\n", '*', lpHostent->h_name, inet_ntoa(inaddr));
			}
			else
			{
				printf(" %d %s (%s)\n", AnswTime, lpHostent->h_name, inet_ntoa(inaddr));
			}
		}
		return 1;
		break;
	
	case ICMP_TIMEOUT:      // Время ожидания вышло
		if (AnswTime > 1000)
		{
			printf(" %c  %s\n", '*', inet_ntoa(inaddr));
		}
		else
		{
			printf(" %d  %s\n", AnswTime, inet_ntoa(inaddr));
		}
		return 0;
		break;
	
	case ICMP_DESTUNREACH:  // Невозможно добраться до узла
		
		printf(" %d  %s  reports: Host is unreachable\n", AnswTime, inet_ntoa(inaddr));
		return 1;
		break;
	
	default:
		
		printf("non-echo type %d recvd\n", icmphdr->i_type);
		return 1;
		break;
	
	}
	return 0;
}

WORD CheckSumm(WORD *buffer, int size)
{
	unsigned long cksum = 0;
	
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(WORD);
	}
	if (size)
		cksum += *(BYTE*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (WORD)(~cksum);
}


void FillicmpData(char * icmp_data, int datasize)
{
	IcmpHeader *icmp_hdr;

	icmp_hdr = (IcmpHeader*)icmp_data;

	icmp_hdr->i_type = ICMP_ECHO;
	icmp_hdr->i_code = 0;
	icmp_hdr->i_id = 256;
	icmp_hdr->i_cksum = 0;
	icmp_hdr->i_seq = 0;
}

int main(void)
{
	WSADATA      Wsd;                             // Структура для инициализации winsok
	SOCKET       SockRaw;                         // Сокет
	HOSTENT     *Hp = NULL;                       // Структура для хранения информации о хосте 
	SOCKADDR_IN  Dest, From;                      // Описывает сокет для работы с протоколами IP
	int          Ret, DataSize;
	int   		 FromLen = sizeof(From), TimeOut;
	int			 Done = 0, MaxHops, TTL = 1;
	char        *IcmpData, *RecvBuf;
	WORD		 SeqNo = 0;
	char		 DestAdr[80];
	ULONG	     *OldTime, CurTime;

	OldTime = (ULONG*)malloc(sizeof(ULONG));
	*OldTime = 0;
	printf("Please enter IP-addres or internet name\n");
	scanf("%s", &DestAdr);

	if (WSAStartup(MAKEWORD(2, 2), &Wsd) != 0) // Инициализация WSOCK32.DLL
	{
		printf("WSAStartup() failed: %d\n", GetLastError());
		return -1;
	}

	MaxHops = MAX_HOPS;

	SockRaw = WSASocket(AF_INET/*IPv4*/, SOCK_RAW/*сырой сокет*/, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);

	if (SockRaw == INVALID_SOCKET)
	{
		printf("WSASocket() failed: %d\n", WSAGetLastError());
		ExitProcess(-1);
	}
	
	TimeOut = 1000; 

	Ret = setsockopt(SockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *)&TimeOut, sizeof(TimeOut));    // прверяем время получения/отправки
	if (Ret == SOCKET_ERROR)
	{
		printf("setsockopt(SO_RCVTIMEO) failed: %d\n", WSAGetLastError());
		return -1;
	}

	TimeOut = 1000;

	Ret = setsockopt(SockRaw, SOL_SOCKET, SO_SNDTIMEO, (char *)&TimeOut, sizeof(TimeOut));	  // прверяем время получения/отправки
	if (Ret == SOCKET_ERROR)
	{
		printf("setsockopt(SO_SNDTIMEO) failed: %d\n", WSAGetLastError());
		return -1;
	}

	ZeroMemory(&Dest, sizeof(Dest));
	
	//Получаем IP адрес
	
	Dest.sin_family = AF_INET;
	if ((Dest.sin_addr.s_addr = inet_addr(DestAdr)) == INADDR_NONE)
	{
		Hp = gethostbyname(DestAdr);
		if (Hp)
			memcpy(&(Dest.sin_addr), Hp->h_addr, Hp->h_length);
		else
		{
			printf("Unable to resolve %s\n", DestAdr);
			ExitProcess(-1);
		}
	}
	
	DataSize = DEF_PACKET_SIZE; // Установка размера пакета

	DataSize += sizeof(IcmpHeader);
	
	// Выделение отправляющего и принимающего буфера для ICMP-пакетов 
	IcmpData = (char*)(malloc(sizeof(char)*MAX_PACKET));
	RecvBuf = (char*)(malloc(sizeof(char)*MAX_PACKET));

	if ( (!IcmpData)||(!RecvBuf) )
	{
		printf("malloc() failed %d\n", GetLastError());
		return -1;
	}
	 
	//  Заполняем ICMP-заголовок
	FillicmpData(IcmpData, DataSize);

	printf("\nTracing route to %s over a maximum of %d hops:\n\n", DestAdr, MaxHops);

	for (TTL = 1; ((TTL < MaxHops) && (!Done)); TTL++)
	{
		int bwrote;

		for (int i = 1; i < 4; i++)
		{
			SetTimetoLive(SockRaw, TTL);

			
			// Каждый раз перезаполняем ICMP-заголовок
			
			((IcmpHeader*)IcmpData)->i_cksum = 0;
			((IcmpHeader*)IcmpData)->SendTimeStamp = GetTickCount();

			WORD w = SeqNo++;

			((IcmpHeader*)IcmpData)->i_seq = (w >> 8 | w << 8);
			((IcmpHeader*)IcmpData)->i_cksum = CheckSumm((WORD*)IcmpData, DataSize);
			*OldTime = ((IcmpHeader*)IcmpData)->SendTimeStamp;
			
            // Отправляем ICMP-пакет в пункт назначения
			
			bwrote = sendto(SockRaw, IcmpData, DataSize, 0,(SOCKADDR *)&Dest, sizeof(Dest));

			if (bwrote == SOCKET_ERROR)
			{
				if (i < 2)
				{
					printf("%2d\n\n", TTL);
				}
				if (WSAGetLastError() == WSAETIMEDOUT)
				{
					printf("%c  Send request timed out.\n", '*');
					continue;
				}
				printf("sendto() failed: %d\n", WSAGetLastError());
				return -1;
			}

			//  Получение обратно
			
			Ret = recvfrom(SockRaw, RecvBuf, MAX_PACKET, 0, (struct sockaddr*)&From, &FromLen);

			if (Ret == SOCKET_ERROR)
			{
				if (i < 2)
				{
					printf("%2d\n\n", TTL);
				}
				if (WSAGetLastError() == WSAETIMEDOUT)
				{
					printf("%c  Receive Request timed out.\n", '*');
					continue;
				}
				printf("recvfrom() failed: %d\n", WSAGetLastError());
				return -1;
			}

			if (i < 2)
			{
				printf("%2d\n\n", TTL);
			}

			Done = DecodeResponse(RecvBuf, Ret, &From, TTL, OldTime); // Декодируем ответ, для просмотра информациии
			
		}
		printf("\n");
	}

	free(RecvBuf);
	free(IcmpData);
	system("pause");

	return 0;
}