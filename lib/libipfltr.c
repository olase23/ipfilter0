#include "stdafx.h"
#include "..\sys\ipfltr.h"
#include "libipfltr.h"

extern BOOL IsDeviceUp(LPCSTR ServiceName);
extern BOOL LoadDeviceDriver(const TCHAR *Name, HANDLE *lphDevice, PDWORD Error);
extern BOOL OpenDevice(IN LPCTSTR DriverName, HANDLE * lphDevice);

extern HANDLE	DllMutex;
extern HANDLE	hDriver;

DWORD	error = 0;

ULONG WINAPI IPFGetVersion(VOID) {
	ULONG	len, version;

	if (hDriver == INVALID_HANDLE_VALUE) {
		if (IsDeviceUp(SERVICE_NAME))
		{
			if (!OpenDevice(SERVICE_NAME, &hDriver))
				return(IPF_ERROR);
		}
		else {
			if (!LoadDeviceDriver(SERVICE_NAME, &hDriver, &error)) {
				SetLastError(error);
				return(IPF_ERROR);
			}
		}
	}
	len = 0;

	if (!DeviceIoControl(hDriver, IOCTL_IPF_GET_VERSION, NULL, 0, &version, sizeof(ULONG), &len, NULL))
		return(IPF_ERROR);

	if (len != sizeof(DWORD))
		return(IPF_ERROR);

	return(version);
}

BOOL WINAPI IPFSetFilter(PFILTER pfilter, UINT size) {
	DWORD len;

	if (!pfilter || size != FILTER_SIZE) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return(FALSE);
	}

	if (DeviceIoControl(hDriver, IOCTL_IPF_SET_FILTER, (LPVOID)pfilter, FILTER_SIZE, NULL, 0, &len, NULL) == 0)
		return(FALSE);

	return(TRUE);
}

BOOL WINAPI IPFDelFilter(PFILTER pfilter, UINT size) {
	DWORD len;

	if (!pfilter || size != FILTER_SIZE) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return(FALSE);
	}

	if (DeviceIoControl(hDriver, IOCTL_IPF_UNSET_FILTER, (LPVOID)pfilter, FILTER_SIZE, NULL, 0, &len, NULL) == 0)
		return(FALSE);

	return(TRUE);
}

DWORD WINAPI IPFEnumFilter(LPVOID buffer, UINT size) {
	DWORD len;

	if (!buffer || !size) {
		if (DeviceIoControl(hDriver, IOCTL_IPF_GET_FILTER, NULL, 0, NULL, 0, &len, NULL))
			return(len);
		else
			return(0);
	}

	if (buffer && size) {
		if (DeviceIoControl(hDriver, IOCTL_IPF_GET_FILTER, NULL, 0, buffer, size, &len, NULL))
			return(len);
		else
			return(0);
	}

	SetLastError(ERROR_INVALID_PARAMETER);
	return(0);
}

BOOL WINAPI IPFStartFilter(VOID) {
	DWORD len;

	if (DeviceIoControl(hDriver, IOCTL_IPF_START_FILTER, NULL, 0, NULL, 0, &len, NULL) == 0)
		return(FALSE);

	return(TRUE);
}

BOOL WINAPI IPFStopFilter(VOID) {
	DWORD len;

	if (DeviceIoControl(hDriver, IOCTL_IPF_STOP_FILTER, NULL, 0, NULL, 0, &len, NULL) == 0)
		return(FALSE);

	return(TRUE);
}

BOOL WINAPI IPFStartLog(VOID) {
	DWORD len;

	if (DeviceIoControl(hDriver, IOCTL_IPF_START_LOGGING, NULL, 0, NULL, 0, &len, NULL) == 0)
		return(FALSE);

	return(TRUE);
}

BOOL WINAPI IPFStopLog(VOID) {
	DWORD len;

	if (DeviceIoControl(hDriver, IOCTL_IPF_STOP_LOGGING, NULL, 0, NULL, 0, &len, NULL) == 0)
		return(FALSE);

	return(TRUE);
}

BOOL WINAPI IPFSetLog(PLOGBUF plog_buffer, UINT size) {
	DWORD len;

	if (!plog_buffer || size != LOGBUF_SIZE) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return(FALSE);
	}

	if (DeviceIoControl(hDriver, IOCTL_IPF_SET_LOGFILTER, (LPVOID)plog_buffer, LOGBUF_SIZE, NULL, 0, &len, NULL) == 0)
		return(FALSE);

	return(TRUE);
}

DWORD WINAPI IPFGetLogBuffer(PLOGBUF plog_buffer, UINT size) {
	DWORD len;

	if (!plog_buffer || !size) {
		if (DeviceIoControl(hDriver, IOCTL_IPF_GET_LOGBUFFER, NULL, 0, NULL, 0, &len, NULL))
			return(len);
		else
			return(0);
	}

	if (plog_buffer && size) {
		if (DeviceIoControl(hDriver, IOCTL_IPF_GET_LOGBUFFER, NULL, 0, plog_buffer, size, &len, NULL))
			return(len);
		else
			return(0);
	}

	SetLastError(ERROR_INVALID_PARAMETER);
	return(0);
}

