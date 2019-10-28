/**
*	ipfltr.c 
*	IP package filter driver  
**/

#include "ntddk.h"
#include "stdarg.h"
#include "stdio.h"
#include "ntddndis.h"
#include "pfhook.h"
#include "ipfltr.h"
#include "ipheader.h"

BOOLEAN TCP_Packet(
	CONST ULONG,
	CONST ULONG,
	CONST PTCP_HEADER,
	CONST PFILTER);

BOOLEAN UDP_Packet(
	CONST ULONG,
	CONST ULONG,
	CONST PUDP_HEADER,
	CONST PFILTER);

BOOLEAN ICMP_Packet(
	CONST ULONG,
	CONST ULONG,
	CONST PICMP_HEADER,
	CONST PFILTER);

VOID LogPacket(
	ULONG src_addr,
	ULONG dst_addr,
	UCHAR  protocol,
	USHORT src_port,
	USHORT dst_port,
	UINT recv_idx,
	UINT send_idx);

PF_FORWARD_ACTION InPackets(
	unsigned char   *PacketHeader,
	unsigned char   *Packet,
	unsigned int    PacketLength,
	unsigned int    RecvInterfaceIndex,
	unsigned int    SendInterfaceIndex,
	IPAddr          RecvLinkNextHop,
	IPAddr          SendLinkNextHop);


NTSTATUS DriverDispatch(
		IN PDEVICE_OBJECT, 
		IN PIRP);

NTSTATUS Open(
		IN PDEVICE_OBJECT, 
		IN PIRP);

NTSTATUS Close(
		IN PDEVICE_OBJECT, 
		IN PIRP);

VOID Unload(
		IN PDRIVER_OBJECT );

NTSTATUS SetHookFilter(
		VOID);

NTSTATUS UnsetHookFilter(
		VOID);

PF_SET_EXTENSION_HOOK_INFO	hook_info;

KMUTEX						filter_mutex;
KMUTEX						log_mutex;
KMUTEX						disp_mutex;

DEBUG_INFO					debug_info;

FILTER						packet_filter;
PICMP_FILTER				gl_icmp_filter = NULL;
PFILTER						filter_table;

PLOGBUF						log_buf = NULL;
PLOGBUF						log_buf_old = NULL;

UINT						filter_count;
UINT						log_count;
UINT						log_count_old;
PFILE_OBJECT				ipf_file_obj = NULL;
PDEVICE_OBJECT				ipf_device_obj = NULL;

BOOLEAN						FilterOn = FALSE;
BOOLEAN						LogOn = FALSE;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	PDEVICE_OBJECT deviceObject = NULL;
	NTSTATUS status;
	UNICODE_STRING uniNtNameString;
	UNICODE_STRING uniWin32NameString;

#if DBG
	KdPrint(("IPFLTR0: Entering DriverEntry()\n"));
#endif
	//
	// Create counted string version of our device name.
	//

	RtlInitUnicodeString(&uniNtNameString, NT_DEVICE_NAME);

	//
	// Create the device object
	//

	status = IoCreateDevice(
		DriverObject,
		0,                     // We don't use a device extension
		&uniNtNameString,
		FILE_DEVICE_IPFLTR,
		0,                     // No standard device characteristics
		FALSE,                 // This isn't an exclusive device
		&deviceObject
	);

	if (!NT_SUCCESS(status)) {
#if DBG
		KdPrint(("IPFLTR0: Couldn't create the device\n"));
#endif
		return status;
	}

	//
	// Create dispatch points.
	//

	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] =
		DriverObject->MajorFunction[IRP_MJ_CREATE] =
		DriverObject->MajorFunction[IRP_MJ_CLOSE] =
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;

	DriverObject->DriverUnload = Unload;

	RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);
	status = IoCreateSymbolicLink(&uniWin32NameString, &uniNtNameString);
	if (!NT_SUCCESS(status)) {
#if DBG
		KdPrint(("IPFLTR0: Couldn't create the symbolic link\n"));
#endif
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	//
	// initizialize mutexes
	//

	KeInitializeMutex(&filter_mutex, 0);
	KeInitializeMutex(&disp_mutex, 0);
	KeInitializeMutex(&log_mutex, 0);

	//
	// initizialize the rest
	//

	RtlZeroMemory(&packet_filter, sizeof(FILTER));
	RtlZeroMemory(&debug_info, sizeof(DEBUG_INFO));
	filter_count = 0;

#if DBG
	KdPrint(("IPFLTR0: All initialized!\n"));
#endif

	return status;
}

NTSTATUS Open(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	PIO_STACK_LOCATION      irpStack;
	ULONG                   ioControlCode;
	ULONG					OutputBufferLength;
	ULONG					InputBufferLength;
	PVOID					OutputBuffer;
	PVOID					InputBuffer;
	STRING		  			string;
	NTSTATUS				ntStatus;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	irpStack = IoGetCurrentIrpStackLocation(Irp);

	switch (irpStack->MajorFunction) {
	case IRP_MJ_CREATE:
	case IRP_MJ_CLOSE:
	case IRP_MJ_SHUTDOWN:	break;
	case IRP_MJ_DEVICE_CONTROL:	{

		KeWaitForMutexObject(&disp_mutex, Executive, KernelMode, FALSE, NULL);

		OutputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
		InputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
		InputBuffer = Irp->AssociatedIrp.SystemBuffer;

		ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

#if DBG
		KdPrint(("IPFLTR0: ioControlCode --> %x\n", ioControlCode));
#endif

		switch (ioControlCode) {
		case IOCTL_IPF_GET_VERSION:

			if (OutputBufferLength != sizeof(ULONG) || OutputBuffer == NULL) {
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				break;
			}

			*(ULONG *)OutputBuffer = (ULONG)IPFILTER_VERSION;
			Irp->IoStatus.Information = sizeof(ULONG);
			break;

		case IOCTL_IPF_SET_FILTER:

			if (InputBufferLength != FILTER_SIZE || InputBuffer == NULL) {
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				break;
			}

			RtlCopyBytes(&packet_filter, InputBuffer, sizeof(FILTER));
			if (!add_filter_entry(&packet_filter)) {
				if (filter_count == MAX_FILTER)
					Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
				else
					Irp->IoStatus.Status = STATUS_NO_MEMORY;
			}

			RtlZeroMemory(&packet_filter, sizeof(FILTER));
			break;

		case IOCTL_IPF_UNSET_FILTER:

			if (InputBufferLength != FILTER_SIZE || InputBuffer == NULL) {
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (!filter_count) {
				Irp->IoStatus.Status = STATUS_NOT_FOUND;
				break;
			}

			RtlCopyBytes(&packet_filter, InputBuffer, sizeof(FILTER));
			if (!del_filter_entry(&packet_filter))
				Irp->IoStatus.Status = STATUS_NOT_FOUND;

			RtlZeroMemory(&packet_filter, sizeof(FILTER));
			break;

		case IOCTL_IPF_GET_FILTER: {
			INT	 i;
			PFILTER l, filter_buffer;

			if (!filter_count)
				break;

			KeWaitForMutexObject(&filter_mutex, Executive, KernelMode, FALSE, NULL);

			if (OutputBufferLength < filter_count * FILTER_SIZE || OutputBuffer == NULL) {
				Irp->IoStatus.Status = STATUS_MORE_ENTRIES;
				Irp->IoStatus.Information = (filter_count * FILTER_SIZE);
				KeReleaseMutex(&filter_mutex, FALSE);
				break;
			}

			filter_buffer = (PFILTER)OutputBuffer;

			for (i = 0; i < MAX_FILTER_ENTRYS; i++)	{
				for (l = filter_table; l != NULL; l = l->next) {
					memcpy(filter_buffer, l, FILTER_SIZE);
					filter_buffer++;
				}
			}

			RtlZeroMemory(&packet_filter, sizeof(FILTER));
			KeReleaseMutex(&filter_mutex, FALSE);
			Irp->IoStatus.Information = filter_count * FILTER_SIZE;
		}
		break;

		case IOCTL_IPF_START_FILTER:

#if DBG
			KdPrint(("IPFLTR0: IOCTL_START_FILTER\n"));
#endif
			if (FilterOn)	//Already on?
				break;

			Irp->IoStatus.Status = SetHookFilter();
			break;

		case IOCTL_IPF_STOP_FILTER:

#if DBG
			KdPrint(("IPFLTR0: IOCTL_STOP_FILTER\n"));
#endif
			if (!FilterOn)	//Already off?
				break;

			Irp->IoStatus.Status = UnsetHookFilter();
			break;

		case IOCTL_IPF_GET_LOGBUFFER: {
			PLOGBUF log = NULL, log_buffer = NULL;

			if (!LogOn)
				break;

			if (!log_buf && !log_buf_old)
				break;

			KeWaitForMutexObject(&log_mutex, Executive, KernelMode, FALSE, NULL);

			// First get the old log entrys
			if (log_buf_old) { 
							
				if (OutputBufferLength < log_count_old * LOGBUF_SIZE || OutputBuffer == NULL) {
					Irp->IoStatus.Status = STATUS_MORE_ENTRIES;
					Irp->IoStatus.Information = (log_count_old * LOGBUF_SIZE);
					KeReleaseMutex(&log_mutex, FALSE);
					break;
				}

				log_buffer = (PLOGBUF)OutputBuffer;

				for (log = log_buf_old; log != NULL; log = log->next) {
					memcpy(log_buffer, log, LOGBUF_SIZE);
					log_buffer = log_buffer + LOGBUF_SIZE;
					ExFreePool(log);
				}

				del_log_entrys(log_buf_old);

				Irp->IoStatus.Information = (log_count_old * LOGBUF_SIZE);
				log_buf_old = NULL;
				log_count_old = 0;
				KeReleaseMutex(&log_mutex, FALSE);
				break;
			}
			else {
				if (OutputBufferLength != log_count * LOGBUF_SIZE || OutputBuffer == NULL)	{
					Irp->IoStatus.Status = STATUS_MORE_ENTRIES;
					Irp->IoStatus.Information = (log_count * LOGBUF_SIZE);

					log_buf_old = log_buf;
					log_buf = NULL;
					log_count_old = log_count;
					log_count = 0;

					KeReleaseMutex(&log_mutex, FALSE);
					break;
				}
			}
		}

		KeReleaseMutex(&log_mutex, FALSE);
		break;

		case IOCTL_IPF_START_LOGGING:

			if (!LogOn)
				LogOn = TRUE;
			break;

		case IOCTL_IPF_STOP_LOGGING:

			if (LogOn) {
				LogOn = FALSE;

				// Clean up the stuff.

				if (log_buf_old) {
					del_log_entrys(log_buf_old);
					log_buf_old = NULL;
					log_count_old = 0;
				}

				if (log_buf) {
					del_log_entrys(log_buf);
					log_buf = NULL;
					log_count = 0;
				}
			}
			break;

		case IOCTL_IPF_GET_DEBUGINFO:

			if (OutputBufferLength < sizeof(DEBUG_INFO) || OutputBuffer == NULL) {
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				break;
			}

			debug_info.flags = (ULONG)FilterOn;
			RtlCopyBytes(OutputBuffer, &debug_info, sizeof(DEBUG_INFO));
			Irp->IoStatus.Information = sizeof(DEBUG_INFO);
			break;

		default: Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		KeReleaseMutex(&disp_mutex, FALSE);
	}
	break;

	default: Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;

	}
	ntStatus = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}

VOID Unload(IN PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING uniWin32NameString;

#if DBG
	KdPrint(("IPFLTR0: Entering Unload()\n"));
#endif 

	if (FilterOn)
		UnsetHookFilter();

	destroy_filter_entrys();
	del_log_entrys(log_buf);
	del_log_entrys(log_buf_old);

	RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&uniWin32NameString);

	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS SetHookFilter(VOID) {
	NTSTATUS			ntStatus;
	UNICODE_STRING		ipf_name;
	PIRP				irp = NULL;
	IO_STATUS_BLOCK     IoStatusBlock;
	KEVENT				event;

#if DBG
	KdPrint(("IPFLTR0: Entering SetHookFilter()\n"));
#endif 

	RtlInitUnicodeString(&ipf_name, DD_IPFLTRDRVR_DEVICE_NAME);

	ntStatus = IoGetDeviceObjectPointer(&ipf_name, FILE_READ_DATA, &ipf_file_obj, &ipf_device_obj);
	if (!NT_SUCCESS(ntStatus)) {
#if DBG
		KdPrint(("IPFLTR0: IoGetDeviceObjectPointer() failed!!!\n"));
#endif
		return(ntStatus);
	}

	hook_info.ExtensionPointer = InPackets;

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest(
		IOCTL_PF_SET_EXTENSION_POINTER,
		ipf_device_obj,
		&hook_info,
		sizeof(PF_SET_EXTENSION_HOOK_INFO),
		NULL,
		0,
		FALSE,
		&event,
		&IoStatusBlock
	);

	if (!irp) {
		strcpy(debug_info.dbg_message, "IoBuildDeviceIoControlRequest() failed!!!");

#if DBG
		KdPrint(("IPFLTR0: IoBuildDeviceIoControlRequest() failed!!!\n"));
#endif		

		return(STATUS_INVALID_PARAMETER);
	}

	ntStatus = IoCallDriver(ipf_device_obj, irp);
	if (ntStatus == STATUS_PENDING)	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
	}
	else if (!NT_SUCCESS(ntStatus))	{
		strcpy(debug_info.dbg_message, "IoCallDriver() failed!!!");

#if DBG		
		KdPrint(("IPFLTR0: IoCallDriver() failed!!!\n"));
#endif

		return(ntStatus);
	}

	if (!NT_SUCCESS(IoStatusBlock.Status)) {

#if DBG
		strcpy(debug_info.dbg_message, "Filter hook set failed!!!");
		KdPrint(("IPFLTR0: Filter hook set failed!!!\n"));
#endif 

		return(ntStatus);
	}
	FilterOn = TRUE;
	return(STATUS_SUCCESS);
}

NTSTATUS UnsetHookFilter(VOID) {
	NTSTATUS			ntStatus;
	PIRP				irp = NULL;
	IO_STATUS_BLOCK     IoStatusBlock;
	KEVENT				event;

#if DBG
	KdPrint(("IPFLTR0: Entering UnHookFilter()\n"));
#endif

	hook_info.ExtensionPointer = NULL;

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest(
		IOCTL_PF_SET_EXTENSION_POINTER,
		ipf_device_obj,
		&hook_info,
		sizeof(PF_SET_EXTENSION_HOOK_INFO),
		NULL,
		0,
		FALSE,
		&event,
		&IoStatusBlock
	);

	if (!irp) {
		strcpy(debug_info.dbg_message, "IoBuildDeviceIoControlRequest() failed!!!");

#if DBG
		KdPrint(("IPFLTR0: IoBuildDeviceIoControlRequest() failed!!!\n"));
#endif 
		return(STATUS_INVALID_PARAMETER);
	}

	ntStatus = IoCallDriver(ipf_device_obj, irp);
	if (ntStatus == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
	}
	else if (!NT_SUCCESS(ntStatus)) {
		strcpy(debug_info.dbg_message, "IoCallDriver() failed!!!");

#if DBG		
		KdPrint(("IPFLTR0: IoCallDriver() failed!!!\n"));
#endif

		return(ntStatus);
	}

	if (!NT_SUCCESS(IoStatusBlock.Status)) {
		strcpy(debug_info.dbg_message, "Filter hook unset failed!!!");

#if DBG	
		KdPrint(("IPFLTR0: Filter hook unset failed!!!\n"));
#endif

		return(ntStatus);
	}
	FilterOn = FALSE;
	return(STATUS_SUCCESS);
}

/*
	Hook function which gets called from the nt kernel for each IP package. 

	IRQL: DISPATCH_LEVEL
*/
PF_FORWARD_ACTION InPackets(
	unsigned char   *PacketHeader,
	unsigned char   *Packet,
	unsigned int    PacketLength,
	unsigned int    RecvInterfaceIndex,
	unsigned int    SendInterfaceIndex,
	IPAddr          RecvLinkNextHop,
	IPAddr          SendLinkNextHop) 
{
	PFILTER		pf = NULL;
	PIP_HEADER	iphdr = NULL;
	ULONG		src, dst;
	UCHAR		protocol;
	USHORT		offset;

	iphdr = (PIP_HEADER)PacketHeader;
	if (!iphdr)
		return PF_FORWARD;

	src = iphdr->iph_src;
	dst = iphdr->iph_dst;
	protocol = iphdr->iph_protocol;

#if DBG
	KdPrint(("IPFLTR0: Packet src--> %d\n dst--> %d\n protocol--> %d\n recvif--> %d\n sendif--> %d\n",
		src, 
		dst, 
		protocol, 
		RecvInterfaceIndex, 
		SendInterfaceIndex));
#endif 

	if (LogOn) {
		switch (protocol) {
		case IP_PROTO_TCP:
		case IP_PROTO_UDP:
		case IP_PROTO_ICMP:
			LogPacket(src, dst, protocol, 0, 0, RecvInterfaceIndex, SendInterfaceIndex);
			break;
		}
	}

	if (FilterOn == FALSE)
		return PF_FORWARD;

	offset = ntohs(iphdr->iph_froffset) & IP_OFFSET;
		
	if (offset == 1 && protocol == IP_PROTO_TCP) {

#if DBG
		KdPrint(("IPFLTR0: Suspect TCP packet!!!\n"));
#endif

		return(PF_DROP);
	}

	
	//	Iterate through the filter list and call the proper check function. 
	for (pf = filter_table; pf != NULL; pf = pf->next) {
		if ((src & pf->srcmask) == pf->srcaddr &&
			(dst & pf->dstmask) == pf->dstaddr) {
			
			// check the protocol 
			if (protocol != pf->protocol)
				continue;

			// check the interface 
			if (pf->nic_idx &&
				pf->nic_idx != RecvInterfaceIndex &&
				pf->nic_idx != SendInterfaceIndex)
				continue;

			switch (protocol) {
			case IP_PROTO_TCP:
				if (TCP_Packet(src, dst, (PTCP_HEADER)Packet, pf))
					return(PF_DROP);
				break;
			case IP_PROTO_UDP:
				if (UDP_Packet(src, dst, (PUDP_HEADER)Packet, pf))
					return(PF_DROP);
				break;
			case IP_PROTO_ICMP:
				if (ICMP_Packet(src, dst, (PICMP_HEADER)Packet, pf))
					return(PF_DROP);
				break;
			default:	break;
			}
		}
	}

	// Do we have a global ICMP filter? 
	if (protocol == IP_PROTO_ICMP && gl_icmp_filter != NULL) {
		if (ICMP_Packet(src, dst, (PICMP_HEADER)Packet, PacketLength, NULL))
			return(PF_DROP);
	}

	return PF_FORWARD;
}

VOID LogPacket(ULONG src_addr,
	ULONG dst_addr,
	UCHAR  protocol,
	USHORT src_port,
	USHORT dst_port,
	UINT recv_idx,
	UINT send_idx)
{
	TCHAR packet_log[128];

	switch (protocol) {
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:	sprintf(packet_log, "%s %s %u:%d > %u:%d ",
		((recv_idx != INVALID_PF_IF_INDEX) ? "Received" : "Send"),
		((protocol == IP_PROTO_TCP) ? "TCP" : "UDP"),
		src_addr, src_port,
		dst_addr, dst_port);
		break;

	case IP_PROTO_ICMP: sprintf(packet_log, "%s %s %u > %u",
		((recv_idx != INVALID_PF_IF_INDEX) ? "Received" : "Send"),
		"ICMP",
		src_addr,
		dst_addr);
		break;

	default:			sprintf(packet_log, "%s %d %u > %u",
		((recv_idx != INVALID_PF_IF_INDEX) ? "Received" : "Send"),
		protocol,
		src_addr,
		dst_addr);
	}

	add_log_entry(packet_log);
}