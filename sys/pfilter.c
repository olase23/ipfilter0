#include "ntddk.h"
#include "stdarg.h"
#include "stdio.h"
#include "ntddndis.h"
#include "pfhook.h"

#include "ipfltr.h"
#include "ipheader.h"

static BOOLEAN filter_port(CONST USHORT, CONST USHORT, CONST USHORT *, CONST USHORT *);

extern PICMP_FILTER	 gl_icmp_filter;

/*
	This is the main filter for TCP packages. When the IP addresses match   
	check the ports either.  
*/
BOOLEAN TCP_Packet(
	CONST ULONG ip_src,
	CONST ULONG ip_dst,
	CONST PTCP_HEADER tcp_header,
	CONST PFILTER filter) {
	
	if ((filter->srcaddr) && (ip_src == (filter->srcaddr & filter->srcmask)))
		return(filter_port(tcp_header->tcph_src_port,
			tcp_header->tcph_dst_port,
			filter->sport,
			filter->dport));

	if ((filter->dstaddr) && (ip_dst == (filter->dstaddr & filter->dstmask)))
		return(filter_port(tcp_header->tcph_src_port,
			tcp_header->tcph_dst_port,
			filter->sport,
			filter->dport));

	return(FALSE);
}

/*
	This is the main filter for UDP packages. When the IP addresses match
	check the ports either.
*/
BOOLEAN UDP_Packet(
	CONST ULONG src,
	CONST ULONG dst,
	CONST PUDP_HEADER udp_header,
	CONST PFILTER filter) {
	
	if ((filter->srcaddr) && (src == (filter->srcaddr & filter->srcmask)))
		return(filter_port(udp_header->udph_sport,
			udp_header->udph_dport,
			filter->sport,
			filter->dport));

	if ((filter->dstaddr) && (dst == (filter->dstaddr & filter->dstmask)))
		return(filter_port(udp_header->udph_sport,
			udp_header->udph_dport,
			filter->sport,
			filter->dport));

	return(FALSE);
}

/*
	When ICMP filter are present check if there is an entry.  
*/
BOOLEAN ICMP_Packet(
	CONST ULONG src,
	CONST ULONG dst,
	CONST PICMP_HEADER icmp_header,
	CONST PFILTER filter) {
	PICMP_FILTER icmp_f=NULL;

	// iterate through the global filter list
	for (icmp_f = gl_icmp_filter; icmp_f != NULL; icmp_f = icmp_f->next) {
		if (icmp_header->icmph_type == icmp_f->type &&
			icmp_header->icmph_code >= icmp_f->code[0] &&
			icmp_header->icmph_code <= icmp_f->code[1])
			return(TRUE);
	}

	return(FALSE);
}

/*
 	This funtion compares source and destionation ports. It returns TRUE when 
	the dst or src port is filtered, otherwise FALSE.
 */

static BOOLEAN filter_port(CONST USHORT src_port,
	CONST USHORT dst_port,
	CONST USHORT *fsport,
	CONST USHORT *fdport) {
	
	if (!fdport[0] && !fdport[1] &&
		!fsport[0] && !fsport[1])
		return(TRUE);

	if (fdport[0] && fdport[1]) {
		if (dst_port >= fdport[0] &&
			dst_port <= fdport[1])
			return(TRUE);
	}

	if (dst_port == fdport[0])
		return(TRUE);

	if (fsport[0] && fsport[1]) {
		if (src_port >= fsport[0] &&
			src_port <= fsport[1])
			return(TRUE);
	}

	if (src_port == fsport[0])
		return(TRUE);

	return(FALSE);
}