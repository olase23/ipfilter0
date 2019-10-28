#include "stdafx.h"
#include "..\sys\ipfltr.h"
#include "libipfltr.h"
#include "libipfproto.h"


BOOL IsDeviceUp(LPCSTR ServiceName);
BOOL LoadDeviceDriver(const TCHAR *Name, HANDLE *lphDevice, PDWORD Error);
BOOL OpenDevice(IN LPCTSTR DriverName, HANDLE * lphDevice);

BOOL IsDeviceUp(LPCSTR ServiceName) {
	SC_HANDLE		schSCManager, sHandle;
	SERVICE_STATUS	device_status;
	BOOL			result = FALSE;

	if (!ServiceName)
		return(result);

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!schSCManager)
		return(result);

	sHandle = OpenService(schSCManager, ServiceName, SERVICE_QUERY_STATUS);
	if (!sHandle)
		return(result);

	if (QueryServiceStatus(sHandle, &device_status)) {
		if (device_status.dwCurrentState == SERVICE_RUNNING)
			result = TRUE;
	}

	CloseServiceHandle(sHandle);
	CloseServiceHandle(schSCManager);
	return(result);
}

BOOL StartDriver(IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName) {
	SC_HANDLE  schService;
	BOOL       ret;
	INT		   tmp;

	schService = OpenService(SchSCManager, DriverName, SERVICE_ALL_ACCESS);
	if (schService == NULL)
		return FALSE;

	ret = StartService(schService, 0, NULL)
		|| GetLastError() == ERROR_SERVICE_ALREADY_RUNNING
		|| GetLastError() == ERROR_SERVICE_DISABLED;

	tmp = GetLastError();

	CloseServiceHandle(schService);
	return ret;
}

BOOL StopDriver(IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName) {
	SC_HANDLE       schService;
	BOOL            ret;
	SERVICE_STATUS  serviceStatus;

	schService = OpenService(SchSCManager, DriverName, SERVICE_ALL_ACCESS);
	if (schService == NULL)
		return FALSE;

	ret = ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus);
	CloseServiceHandle(schService);
	return ret;
}

BOOL InstallDriver(IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName, IN LPCTSTR ServiceExe) {
	SC_HANDLE  schService;

	schService = CreateService(SchSCManager,          // SCManager database
		DriverName,            // name of service
		DriverName,            // name to display
		SERVICE_ALL_ACCESS,    // desired access
		SERVICE_KERNEL_DRIVER, // service type
		SERVICE_DEMAND_START,  // start type
		SERVICE_ERROR_NORMAL,  // error control type
		ServiceExe,            // service's binary
		NULL,                  // no load ordering group
		NULL,                  // no tag identifier
		NULL,                  // no dependencies
		NULL,                  // LocalSystem account
		NULL                   // no password
	);
	if (!schService) {
		switch (GetLastError()) {
		case ERROR_SERVICE_MARKED_FOR_DELETE:
		case ERROR_SERVICE_EXISTS: goto ok;
		default: CloseServiceHandle(schService);
			return FALSE;
		}
	}
ok:
	CloseServiceHandle(schService);
	return TRUE;
}

BOOL LoadDeviceDriver(const TCHAR *Name, HANDLE *lphDevice, PDWORD Error) {
	SC_HANDLE	schSCManager;
	BOOL		okay = FALSE;

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!schSCManager) goto err_hnd;
	
	if (!StartDriver(schSCManager, Name)) goto err_hnd;
	okay = OpenDevice(Name, lphDevice);

err_hnd:
	*Error = GetLastError();
	CloseServiceHandle(schSCManager);
	return okay;
}

BOOL OpenDevice(IN LPCTSTR DriverName, HANDLE * lphDevice) {
	TCHAR    completeDeviceName[64];
	HANDLE   hDevice;

	if (GetVersion() & 0xFF >= 5) 	{
		wsprintf(completeDeviceName, TEXT("\\\\.\\Global\\%s"), DriverName);
	}
	else 	{
		wsprintf(completeDeviceName, TEXT("\\\\.\\%s"), DriverName);
	}

	hDevice = CreateFile(completeDeviceName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hDevice == ((HANDLE)-1))
		return FALSE;

	if (lphDevice)
		*lphDevice = hDevice;
	else
		CloseHandle(hDevice);

	return TRUE;
}

DWORD WINAPI IsServiceInstalled(VOID) {
	HKEY	hKey;
	LONG	result;
	DWORD	start = ERROR_SERVICE_DOES_NOT_EXIST;
	DWORD	type;
	DWORD	size;
	
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, IPFILTER_REG_PATH, 0, KEY_READ, &hKey);
	if (result != ERROR_SUCCESS)
		goto out;

	type = REG_DWORD_LITTLE_ENDIAN;
	size = sizeof(DWORD);
	RegQueryValueEx(hKey, TEXT("Start"), NULL, &type, (LPBYTE)&start, &size);

out:
	RegCloseKey(hKey);
	return start;
}