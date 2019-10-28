

#define NT_DEVICE_NAME				L"\\Device\\ipfltr0"
#define DOS_DEVICE_NAME				L"\\DosDevices\\IPFLTR0"	

#define FILE_DEVICE_IPFLTR			0xFC01

#define IOCTL_IPF_START_FILTER		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x00, METHOD_BUFFERED, FILE_WRITE_ACCESS )
#define IOCTL_IPF_STOP_FILTER		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x01, METHOD_BUFFERED, FILE_WRITE_ACCESS )

#define IOCTL_IPF_SET_FILTER		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x02, METHOD_BUFFERED, FILE_WRITE_ACCESS )
#define IOCTL_IPF_UNSET_FILTER		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x03, METHOD_BUFFERED, FILE_WRITE_ACCESS )
#define IOCTL_IPF_GET_FILTER		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x04, METHOD_BUFFERED, FILE_WRITE_ACCESS )

#define IOCTL_IPF_START_LOGGING		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x05, METHOD_BUFFERED, FILE_WRITE_ACCESS ) 	
#define IOCTL_IPF_STOP_LOGGING		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x06, METHOD_BUFFERED, FILE_WRITE_ACCESS ) 	
#define IOCTL_IPF_SET_LOGFILTER		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x07, METHOD_BUFFERED, FILE_WRITE_ACCESS ) 	
#define IOCTL_IPF_GET_LOGBUFFER		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x08, METHOD_BUFFERED, FILE_WRITE_ACCESS ) 	

#define IOCTL_IPF_GET_VERSION		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x09, METHOD_BUFFERED, FILE_WRITE_ACCESS ) 	
#define IOCTL_IPF_GET_DEBUGINFO		(ULONG) CTL_CODE( FILE_DEVICE_IPFLTR, 0x0F, METHOD_BUFFERED, FILE_WRITE_ACCESS )

#define IPFILTER_VERSION			100

#define ntohs(x) (USHORT)( ((x) >> 8) + (((x) & 0xFF)  << 8) ) 

typedef int INT;
typedef unsigned int UINT;

typedef enum _NIC_INDEX {
	NIC_1	= 1,
	NIC_2,
	NIC_3,
	NIC_4
}NIC_INDEX;

#define DEFAULT_MASK	TEXT("255.255.255.255")
#define MAX_PORT 65535

#define	IP_PROTO_ICMP				1
#define	IP_PROTO_TCP				6
#define	IP_PROTO_UDP				17

#define IPFLTR_HASH_MASK			0x000000FF
#define MAX_FILTER_ENTRYS			256
#define MAX_FILTER					MAX_FILTER_ENTRYS * 256
#define LOG_BUFFER_LEN				128

#define IP_OFFSET					0x1FFF

/** main filter structure **/
typedef struct _FILTER {
	ULONG  srcaddr;					// source address
	ULONG  dstaddr;					// destination address
	ULONG  srcmask;					// source mask
	ULONG  dstmask;					// destination mask
	UINT   nic_idx;					// interface index
	USHORT sport[2];				// source port range
	USHORT dport[2];				// destination port range
	USHORT protocol;				// protocol
	struct _FILTER *next;			// next chain element
}FILTER, *PFILTER;

#define FILTER_SIZE sizeof(FILTER)

/** global icmp filter struture **/
typedef struct _ICMP_FILTER {
	UCHAR	type;					// icmp type 
	UCHAR	code[2];				// icmp code 
	struct _ICMP_FILTER *next;
}ICMP_FILTER, *PICMP_FILTER;

#define ICMP_FILTER_SIZE sizeof(ICMP_FILTER)

/** log entry structure **/
typedef struct _LOGBUF {
	struct _LOGBUF	*next;
	TCHAR	entry[LOG_BUFFER_LEN];
	HANDLE	phandle;
	UINT	len;
}LOGBUF, *PLOGBUF;

#define LOGBUF_SIZE	sizeof(LOGBUF)


/** debug structure **/
typedef struct _DEBUG_INFO {
	TCHAR dbg_message[128];
	ULONG  flags;
}DEBUG_INFO;

#define FIRST_QUAD(addr) ((UCHAR)(addr & IPFLTR_HASH_MASK))

/** forward declarations **/
BOOLEAN add_filter_entry(PFILTER);
BOOLEAN del_filter_entry(PFILTER);
PFILTER get_filter_list(ULONG,ULONG,USHORT);
VOID destroy_filter_entrys(VOID);
BOOLEAN add_log_entry(CONST PCHAR);
VOID del_log_entrys(PLOGBUF);
USHORT __ntohs(USHORT);