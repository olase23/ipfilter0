/**
*	This file cointains the ipfilter command line tool. 
*	It uses funtions from the ipfilter.dll to load, start, stop, ... the package filter. 
**/

#include "stdafx.h"
#include "..\sys\ipfltr.h"
#include "..\lib\libipfltr.h"
#include "..\lib\libipfproto.h"

void check_args(INT argc, TCHAR **argv);
void usage(CONST PCHAR name);
void cleanup(void);
void check_deps(void);
void get_adapters(void);
void list_adapters(void);

FILTER				add_filter;			//filter structure
PIP_ADAPTER_INFO	adapter_info = NULL;	//network adapter list 

BOOL	add = FALSE;
BOOL	del = FALSE;
BOOL	list = FALSE;
BOOL	start = FALSE;
BOOL	kill = FALSE;
BOOL	adapters = FALSE;
BOOL	force = FALSE;
DWORD	starttype;
DWORD	version;
DWORD	ad_list_size;

void main(INT argc, TCHAR **argv) {
	DWORD errorcode;

	if ((GetVersion() & 0xFF) < 5) {
		fprintf(stderr, "Invalid operating system version!!!\n");
		exit(1);
	}

	if (argc <= 1)
		usage(argv[0]);

	atexit(cleanup);
	memset(&add_filter, 0, FILTER_SIZE);
	check_args(argc, argv);
	check_deps();

	get_adapters();

	if (adapters)
		list_adapters();

	starttype = IsServiceInstalled();

	switch (starttype) {
	case ERROR_SERVICE_DOES_NOT_EXIST:
		fprintf(stderr, "IP filter driver is not right installed.\nPlease run setup again.");
		exit(1);
	case SERVICE_DISABLED:	fprintf(stderr, "IP filter driver is disabled, please run setup again.\n");
		exit(1);
	default:				break;
	}

#ifdef __DEBUG__
	fprintf(stderr, "IPFGetVersion()\n");
#endif

	version = IPFGetVersion();
	if (version == IPF_ERROR)
	{
		fprintf(stderr, "Couldn't carry out the IP filter version.");
		exit(1);
	}

	if (add)
	{

#ifdef __DEBUG__
		fprintf(stderr, "IPFSetFilter()\n");
#endif
		if (!IPFSetFilter(&add_filter, FILTER_SIZE))
		{
			errorcode = GetLastError();
			switch (errorcode)
			{
			case ERROR_NOT_ENOUGH_MEMORY: fprintf(stderr, "Error, not enough memory available.\n");
				break;
			case ERROR_ACCESS_DENIED:	  fprintf(stderr, "Error, too man configured filter.\n");
				break;
			default:		   			  fprintf(stderr, "Couldn't add the filter.\nErrorcode: %d\n", errorcode);
			}
			exit(1);

		}
		exit(0);
	}

	if (del)
	{
#ifdef __DEBUG__
		fprintf(stderr, "IPFDelFilter()\n");
#endif
		if (!IPFDelFilter(&add_filter, FILTER_SIZE)) {
			errorcode = GetLastError();
			switch (errorcode) {
			case ERROR_NOT_FOUND:	fprintf(stderr, "Filter not found.\n");
				break;
			default:				fprintf(stderr, "Error, couldn't delete the filter.\nErrorcode: %d\n", errorcode);
			}

			exit(1);
		}
		exit(0);
	}

	if (list) {
		PFILTER fbuffer = NULL;
		DWORD	n, size, fc;
		struct  in_addr ip;

#ifdef __DEBUG__
		fprintf(stderr, "IPFEnumFilter()\n");
#endif

		size = IPFEnumFilter(NULL, 0);
		if (!size) {
			fprintf(stderr, "No filter configured.\n");
			exit(0);
		}

		fbuffer = (PFILTER)malloc(size);

#ifdef __DEBUG__
		fprintf(stderr, "IPFEnumFilter()\n");
#endif

		if (!IPFEnumFilter(fbuffer, size)) {
			fprintf(stderr, "No filter configured.\n");
			exit(0);
		}

		n = size / FILTER_SIZE;

		fc = 0;
		while (n > 0) {
			fc++;
			fprintf(stdout, "FILTER %d\n", fc);

			if (fbuffer->nic_idx)
				fprintf(stdout, "Interface: %d\n", fbuffer->nic_idx);
			else
				fprintf(stdout, "Interface: ALL\n");

			switch (fbuffer->protocol) 	{
			case 0:				fprintf(stdout, "Protocol: %s\n", TEXT("ALL"));
				break;
			case IP_PROTO_TCP:	fprintf(stdout, "Protocol: %s\n", TEXT("TCP"));
				break;
			case IP_PROTO_UDP:	fprintf(stdout, "Protocol: %s\n", TEXT("UDP"));
				break;
			case IP_PROTO_ICMP:	fprintf(stdout, "Protocol: %s\n", TEXT("ICMP"));
				break;
			default:			fprintf(stdout, "Protocol: %d\n", fbuffer->protocol);
			}

			ip.s_addr = fbuffer->srcaddr;
			fprintf(stdout, "Source Address: %s", inet_ntoa(ip));

			if (!fbuffer->sport[0])
				fprintf(stdout, "\tSource Port: %s", TEXT("ALL"));
			else if (fbuffer->sport[0] && !fbuffer->sport[1])
				fprintf(stdout, "\tSource Port: %d", ntohs(fbuffer->sport[0]));
			else
				fprintf(stdout, "\tSource Port Range: %d - %d", ntohs(fbuffer->sport[0]), ntohs(fbuffer->sport[1]));

			ip.s_addr = fbuffer->srcmask;
			fprintf(stdout, "\tMask: %s\n", inet_ntoa(ip));

			ip.s_addr = fbuffer->dstaddr;
			fprintf(stdout, "Destination Address: %s", inet_ntoa(ip));

			if (!fbuffer->dport[0])
				fprintf(stdout, "\tDestination Port: %s", TEXT("ALL"));
			else if (fbuffer->dport[0] && !fbuffer->dport[1])
				fprintf(stdout, "\tDestination Port: %d", ntohs(fbuffer->dport[0]));
			else
				fprintf(stdout, "\tDestination Port Range: %d - %d", ntohs(fbuffer->dport[0]), ntohs(fbuffer->dport[1]));

			ip.s_addr = fbuffer->dstmask;
			fprintf(stdout, "\tMask: %s\n", inet_ntoa(ip));

			fbuffer++;
			n--;
		}

	}

	if (start)
	{

#ifdef __DEBUG__
		fprintf(stderr, "IPFStartFilter()\n");
#endif

		if (!IPFStartFilter()) {
			fprintf(stderr, "Couldn't start the filter.\nErrorcode: %d\n", GetLastError());
			exit(1);
		}
		exit(0);
	}

	if (kill) {

#ifdef __DEBUG__
		fprintf(stderr, "IPFStopFilter()\n");
#endif

		if (!IPFStopFilter()) {
			fprintf(stderr, "Couldn't stop the filter.\n");
			exit(1);
		}
		exit(0);

	}

}

void check_args(INT argc, TCHAR **argv) {
	INT i;
	ULONG value;

	for (i = 1; i < argc; i++) 	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1]) {

			case '?':	usage(argv[0]);
			case 'A':	
				add = TRUE;
				continue;
			case 'D':	
				del = TRUE;
				continue;
			case 'L':	
				list = TRUE;
				continue;
			case 'S':	
				start = TRUE;
				continue;
			case 'K':	
				kill = TRUE;
				continue;
			case 'I':	
				adapters = TRUE;
				continue;
			case 'i':	i++;
				if (!argv[i])
					usage(argv[0]);
				add_filter.nic_idx = atoi(argv[i]);
				continue;
			case 'f':	
				force = TRUE;
				continue;
			case 'p':	
				i++;
				if (!argv[i])
					usage(argv[0]);

				if (!_strnicmp(argv[i], TEXT("tcp"), 3)) {
					add_filter.protocol = IP_PROTO_TCP;
					continue;
				}
				if (!_strnicmp(argv[i], TEXT("udp"), 3)) {
					add_filter.protocol = IP_PROTO_UDP;
					continue;
				}
				if (!_strnicmp(argv[i], TEXT("icmp"), 3)) {
					add_filter.protocol = IP_PROTO_ICMP;
					continue;
				}
				else
					usage(argv[0]);
			}

			if (!strcmp(argv[i], TEXT("-srcaddr"))) {
				i++;
				value = inet_addr(argv[i]);
				if (value == INADDR_NONE)
					usage(argv[0]);

				add_filter.srcaddr = value;
				continue;
			}

			if (!strcmp(argv[i], TEXT("-dstaddr"))) {
				i++;
				value = inet_addr(argv[i]);
				if (value == INADDR_NONE)
					usage(argv[0]);

				add_filter.dstaddr = value;
				continue;
			}

			if (!strcmp(argv[i], TEXT("-srcmask"))) {
				i++;
				value = inet_addr(argv[i]);
				if (value == INADDR_NONE)
					usage(argv[0]);

				add_filter.srcmask = value;
				continue;
			}

			if (!strcmp(argv[i], TEXT("-dstmask"))) {
				i++;
				value = inet_addr(argv[i]);
				if (value == INADDR_NONE)
					usage(argv[0]);

				add_filter.dstmask = value;
				continue;
			}

			if (!strcmp(argv[i], TEXT("-sp"))) {
				PCHAR	sep;
				UINT	ps, pe;
				i++;
				sep = strchr(argv[i], '-');
				if (sep) {
					*sep = '\0';
					ps = atoi(argv[i]);
					if (ps > MAX_PORT)
						usage(argv[0]);
					pe = atoi(++sep);
					if (pe > MAX_PORT)
						usage(argv[0]);

					add_filter.sport[0] = htons((USHORT)ps);
					add_filter.sport[1] = htons((USHORT)pe);
				}
				else {
					ps = atoi(argv[i]);
					if (ps > MAX_PORT)
						usage(argv[0]);

					add_filter.sport[0] = htons((USHORT)ps);
				}
				continue;
			}

			if (!strcmp(argv[i], TEXT("-dp"))) 	{
				PCHAR	sep;
				UINT	ps, pe;
				i++;
				sep = strchr(argv[i], '-');
				if (sep) {
					*sep = '\0';
					ps = atoi(argv[i]);
					if (ps > MAX_PORT)
						usage(argv[0]);
					pe = atoi(++sep);
					if (pe > MAX_PORT)
						usage(argv[0]);

					add_filter.dport[0] = htons((USHORT)ps);
					add_filter.dport[1] = htons((USHORT)pe);
				}
				else {
					ps = atoi(argv[i]);
					if (ps > MAX_PORT)
						usage(argv[0]);

					add_filter.dport[0] = htons((USHORT)ps);
				}
				continue;
			}

			fprintf(stderr, "Invalid argument.\n");
			exit(1);
		}
		else
			usage(argv[0]);
	}

}

void check_deps(void) {
	PIP_ADAPTER_INFO  list = NULL;

	if ((add && del) || (start && kill) ||
		(add && start) || (del && kill)) {
		fprintf(stderr, "Invalid argument(s)\n");
		exit(1);
	}

	if (add || del) {
		if (!add_filter.protocol) {
			fprintf(stderr, "Protocol expected\n");
			exit(1);
		}
	}

	if (!add_filter.srcaddr)
		add_filter.srcmask = 0;

	if (!add_filter.dstaddr)
		add_filter.dstmask = 0;

	if (add_filter.srcaddr && ((add_filter.srcaddr & 0xff000000) == 0)) {
		if (!(add_filter.srcaddr & 0x0000ff00) && !(add_filter.srcaddr & 0x00ff0000))
		{
			if (((add_filter.srcaddr & 0x000000ff) < 128)) {
				add_filter.srcmask = inet_addr("255.0.0.0"); //Class A		
			}
			else {
				fprintf(stderr, "Please specify a source netmask for this filter.\n");
				exit(1);
			}
		}
		else if (!(add_filter.srcaddr & 0x00ff0000)) {
			if (((add_filter.srcaddr & 0x000000ff) < 192)) {
				add_filter.srcmask = inet_addr("255.0.0.0"); //Class B				
			}
			else {
				fprintf(stderr, "Please specify a source netmask for this filter.\n");
				exit(1);
			}
		}
		else if (((add_filter.srcaddr & 0x000000ff) >= 192)) {
			add_filter.srcmask = inet_addr("255.255.255.0"); //Class C							
		}
		else {
			fprintf(stderr, "Please specify a source netmask for this filter.\n");
			exit(1);
		}
	}

	if (add_filter.dstaddr && ((add_filter.dstaddr & 0xff000000) == 0)) {
		if (!(add_filter.dstaddr & 0x0000ff00) && !(add_filter.dstaddr & 0x00ff0000)) {
			if (((add_filter.dstaddr & 0x000000ff) < 128)) {
				add_filter.dstmask = inet_addr("255.0.0.0"); //Class A		
			}
			else {
				fprintf(stderr, "Please specify a source netmask for this filter.\n");
				exit(1);
			}
		}
		else if (!(add_filter.dstaddr & 0x00ff0000)) {
			if (((add_filter.dstaddr & 0x000000ff) < 192)) {
				add_filter.dstmask = inet_addr("255.0.0.0"); //Class B				
			}
			else {
				fprintf(stderr, "Please specify a source netmask for this filter.\n");
				exit(1);
			}
		}
		else if (((add_filter.dstaddr & 0x000000ff) >= 192)) {
			add_filter.dstmask = inet_addr("255.255.255.0"); //Class C							
		}
		else {
			fprintf(stderr, "Please specify a source netmask for this filter.\n");
			exit(1);
		}
	}


	if (!add_filter.dstmask && add_filter.dstaddr)
		add_filter.dstmask = inet_addr(DEFAULT_MASK);

	if (!add_filter.srcmask && add_filter.srcaddr)
		add_filter.srcmask = inet_addr(DEFAULT_MASK);

	if (!force && add_filter.nic_idx) {
		for (list = adapter_info; list != NULL; list = list->Next) {
			if (add_filter.nic_idx == list->Index)
				break;
		}
		fprintf(stderr, "Wrong network adapter index.\n");
		exit(1);
	}

}

void get_adapters(void) {
	ULONG	size = 0;

	GetAdaptersInfo(NULL, &size);
	if (size <= 0) {
		fprintf(stderr, "No network interfaces active or installed.\n");
		exit(1);
	}

	adapter_info = (PIP_ADAPTER_INFO)malloc(size);
	if (!adapter_info) {
		fprintf(stderr, "Couldn't allocate memory.\n");
		exit(1);
	}

	if ((GetAdaptersInfo(adapter_info, &size)) != NO_ERROR) {
		fprintf(stderr, "Couldn't determine the network adapters.\n");
		exit(1);
	}

	ad_list_size = size;
}

void list_adapters(void) {
	PIP_ADAPTER_INFO		list = NULL;
	ULONG	n, i;
	TCHAR	ip[17], mask[17];

	n = ad_list_size / sizeof(IP_ADAPTER_INFO);

	list = adapter_info;

	while (n > 0) {
		fprintf(stderr, "Adapter: %s\n", list->Description);
		fprintf(stderr, "Index: %d\n", list->Index);

#ifdef __DEBUG__		
		fprintf(stderr, "Name: %s\n", list->AdapterName);
		fprintf(stderr, "MAC-Address: ");

		for (i = 0; i < list->AddressLength; i++) {
			if (i != 0 && i < list->AddressLength)
				fprintf(stderr, ":");
			if (list->Address[i] <= 0xf)
				fprintf(stderr, "0");
			fprintf(stderr, "%X", list->Address[i]);
		}
		fprintf(stderr, "\n");
#endif

		strncpy_s(ip, 17, (PCHAR)list->IpAddressList.IpAddress.String, 17);
		strncpy_s(mask, 17, (PCHAR)list->IpAddressList.IpMask.String, 17);

		fprintf(stderr, "IP Address: %s Netmask: %s\n", ip, mask);

		if (list->CurrentIpAddress) {
			fprintf(stderr, "IP Address: %s Netmask: %s\n", list->CurrentIpAddress->IpAddress,
				list->CurrentIpAddress->IpMask);
		}
		else {
			fprintf(stderr, "IP Address: ???\n");
		}

		list++;
		n--;
	}

	exit(0);
}

void usage(CONST PCHAR name) {
	fprintf(stderr, "ipfilter V1.0 (c) Winsoflabs 2002\n");
	fprintf(stderr, "usage: %s action [options]\n", name);
	fprintf(stderr, "Actions:\n");
	fprintf(stderr, "\t-A\tAdd a filter rule.\n");
	fprintf(stderr, "\t-D\tDelete a filter rule.\n");
	fprintf(stderr, "\t-L\tList all filter rules.\n");
	fprintf(stderr, "\t-S\tStart the packet filter.\n");
	fprintf(stderr, "\t-K\tStop the packet filter.\n\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-srcaddr\tSource address.\n");
	fprintf(stderr, "\t-dstaddr\tDestination address.\n");
	fprintf(stderr, "\t-srcmask\tSource address mask.\n");
	fprintf(stderr, "\t-dstmask\tDestination address mask.\n");
	fprintf(stderr, "\t-sp\t\tSource port (range).\n");
	fprintf(stderr, "\t-dp\t\tDestination port (range).\n");
	fprintf(stderr, "\t-p\t\tProtocol.\n");
	fprintf(stderr, "\t-i\t\tInterface.\n");
	fprintf(stderr, "\n");

	exit(1);
}

void cleanup(void) {
#ifdef __DEBUG__
	fprintf(stderr, "cleanup()\n");
#endif

	if (adapter_info)
		free(adapter_info);
}