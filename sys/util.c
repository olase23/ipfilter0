#include "ntddk.h"
#include "ipfltr.h"

static UINT get_hash_key(UCHAR, UCHAR, USHORT);

extern PFILTER			filter_table;
extern KMUTEX			filter_mutex;
extern KMUTEX			log_mutex;
extern UINT				filter_count;
extern UINT				log_count;
extern PLOGBUF			log_buf;

BOOLEAN add_filter_entry(PFILTER new_entry) {
	PFILTER	 l, e, f_entry;

	KeWaitForMutexObject(&filter_mutex, Executive, KernelMode, FALSE, NULL);

	for (l = filter_table; l != NULL; l = l->next) {
		if (l->srcaddr == new_entry->srcaddr &&
			l->dport[0] == new_entry->dport[0] &&
			l->dport[1] == new_entry->dport[1] &&
			l->sport[0] == new_entry->sport[0] &&
			l->sport[1] == new_entry->sport[1] &&
			l->protocol == new_entry->protocol &&
			l->dstaddr == new_entry->dstaddr &&
			l->dstmask == new_entry->dstmask &&
			l->srcmask == new_entry->srcmask &&
			l->nic_idx == new_entry->nic_idx)
		{
			KeReleaseMutex(&filter_mutex, FALSE);
			return(TRUE);
		}
		e = l;
	}

	KdPrint(("DEBUG: filter_count: %d\n", filter_count));

	if (filter_count <= MAX_FILTER) {
		f_entry = ExAllocatePool(PagedPool, FILTER_SIZE);
		if (!f_entry) {
			KdPrint(("IPFLTR0: Couldn't get memory! ExAllocatePool()\n"));
			KeReleaseMutex(&filter_mutex, FALSE);
			return(FALSE);
		}

		memcpy(f_entry, new_entry, FILTER_SIZE);
		f_entry->next = NULL;

		/** The first entry **/
		if (l == NULL) {
			filter_table = f_entry;
			KdPrint(("IPFLTR0: ADDR %x %x\n", f_entry, filter_table));
		}
		else
		{
			e->next = f_entry;
			KdPrint(("IPFLTR0: Add on end ADDR %x %x\n", f_entry, e));
		}
		filter_count++;
		KeReleaseMutex(&filter_mutex, FALSE);
		return(TRUE);
	}
	KeReleaseMutex(&filter_mutex, FALSE);
	return(FALSE);
}

BOOLEAN del_filter_entry(PFILTER entry) {
	PFILTER	 l = NULL, last = NULL, f_entry = NULL;

	KeWaitForMutexObject(&filter_mutex, Executive, KernelMode, FALSE, NULL);

	for (l = filter_table; l != NULL; l = l->next) {
		if (l->srcaddr == entry->srcaddr &&
			l->sport[0] == entry->sport[0] &&
			l->sport[1] == entry->sport[1] &&
			l->dport[0] == entry->dport[0] &&
			l->dport[1] == entry->dport[1] &&
			l->protocol == entry->protocol &&
			l->dstmask == entry->dstmask &&
			l->srcmask == entry->srcmask &&
			l->nic_idx == entry->nic_idx &&
			l->dstaddr == entry->dstaddr)
		{
			if (l == filter_table) {
				if (l->next == NULL)
					filter_table = NULL;
				else
					filter_table = l->next;
			}
			else {
				if (l->next == NULL)
					last->next = NULL;
				else
					last->next = l->next;
			}
			ExFreePool(l);
			filter_count--;
			KeReleaseMutex(&filter_mutex, FALSE);
			return(TRUE);
		}
		last = l;
	}
	KeReleaseMutex(&filter_mutex, FALSE);
	return(FALSE);
}

VOID destroy_filter_entrys(VOID) {
	PFILTER	 l, tmp;

	KeWaitForMutexObject(&filter_mutex, Executive, KernelMode, FALSE, NULL);

	for (l = filter_table; l != NULL;) {
		tmp = l->next;
		ExFreePool(l);
		l = tmp;
	}
	filter_count = 0;
	KeReleaseMutex(&filter_mutex, FALSE);
}

BOOLEAN add_log_entry(CONST PCHAR log) {
	PLOGBUF s = NULL, l = NULL, n = NULL;

	if (!log)
		return(FALSE);

	KeWaitForMutexObject(&log_mutex, Executive, KernelMode, FALSE, NULL);

	for (s = log_buf; s != NULL; s = s->next) {
		l = s;
	}

	n = ExAllocatePool(PagedPool, LOGBUF_SIZE);
	if (!n) {
		KdPrint(("IPFLTR0: Couldn't get memory! ExAllocatePool()\n"));
		KeReleaseMutex(&log_mutex, FALSE);
		return(FALSE);
	}

	strncpy(n->entry, log, LOG_BUFFER_LEN);
	n->next = NULL;
	n->len = strlen(log);

	if (!log_buf)
		log_buf = n;
	else
		l->next = n;

	log_count++;
	KeReleaseMutex(&log_mutex, FALSE);

	return(TRUE);
}

VOID del_log_entrys(PLOGBUF log) {
	PLOGBUF s = NULL, tmp = NULL;

	if (!log)
		return;

	KeWaitForMutexObject(&log_mutex, Executive, KernelMode, FALSE, NULL);

	for (s = log; s != NULL;) {
		tmp = s->next;
		ExFreePool(s);
		s = tmp;
	}
	KeReleaseMutex(&log_mutex, FALSE);
}
