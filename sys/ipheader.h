#define		IP_PROTO_ICMP	1
#define		IP_PROTO_TCP	6
#define		IP_PROTO_UDP	17

/*IP-Header structure*/
typedef struct _IP_HEADER {
    UCHAR     iph_verlen;     // Version and length  
	UCHAR     iph_tos;        // Type of service 
    USHORT    iph_length;     // Total datagram length 
    USHORT    iph_id;         // Identification 
    USHORT    iph_froffset;   // Flags, fragment offset 
    UCHAR     iph_ttl;        // Time to live 
    UCHAR     iph_protocol;   // Protocol 
    USHORT    iph_xsum;       // Header checksum 
    ULONG     iph_src;        // Source address 
    ULONG     iph_dst;        // Destination address 
    ULONG     iph_options;    // Options
} IP_HEADER, *PIP_HEADER; 

#define IP_HEADER_SIZE		sizeof(IP_HEADER)

typedef struct _TCP_HEADER {
	USHORT	  tcph_src_port;
	USHORT	  tcph_dst_port;
	ULONG	  tcph_seq;
	ULONG	  tcph_ack;
	UCHAR	  tcph_length;
	UCHAR	  tcph_shit;
	USHORT	  tcph_window;
	USHORT	  tcph_xsum;
	USHORT	  tcph_urg;
	ULONG	  tcph_options;
} TCP_HEADER, *PTCP_HEADER;

#define TCP_HEADER_SIZE		sizeof(TCP_HEADER)

typedef struct _UDP_HEADER {
	USHORT		udph_sport;
	USHORT		udph_dport;
	USHORT		udph_length;
	USHORT		udph_xsum;
} UDP_HEADER, *PUDP_HEADER;

#define UDP_HEADER_SIZE		sizeof(UDP_HEADER)

typedef struct _ICMP_HEADER {
	UCHAR		icmph_type;
	UCHAR		icmph_code;
	USHORT		icmph_xsum;
} ICMP_HEADER, *PICMP_HEADER;

#define ICMP_HEADER_SIZE	sizeof(ICMP_HEADER)

#define MASK_ADDRESS(addr,mask) (addr & mask)
