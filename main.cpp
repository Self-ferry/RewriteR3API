#define  _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<Windows.h>

// �������ڴ棨�ж��ŵ��ã�
BOOL WINAPI HbgReadProcessMemory_INT(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead)
{
	LONG NtStatus;
	__asm
	{
		// ֱ��ģ�� KiIntSystemCall
		lea edx, hProcess; // Ҫ�� edx �洢�����ջ�Ĳ���
		mov eax, 0xBA;
		int 0x2E;
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesRead != NULL)
	{
		*lpNumberOfBytesRead = nSize;
	}
	// ������
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}

// �������ڴ棨���ٵ��ã�
BOOL WINAPI HbgReadProcessMemory_FAST(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead)
{
	LONG NtStatus;
	__asm
	{
		// ģ�� ReadProcessMemory
		lea eax, nSize;
		push eax;
		push nSize;
		push lpBuffer;
		push lpBaseAddress;
		push hProcess;
		sub esp, 0x04; // ģ�� ReadProcessMemory ��� CALL NtReadVirtualMemory
		// ģ�� NtReadVirtualMemory
		mov eax, 0xBA;
		push NtReadVirtualMemoryReturn; // ģ�� NtReadVirtualMemory ������� CALL [0x7FFE0300]
		// ģ�� KiFastSystemCall
		mov edx, esp;
		_emit 0x0F; // sysenter 
		_emit 0x34;
	NtReadVirtualMemoryReturn:
		add esp, 0x18; // ģ�� NtReadVirtualMemory ���ص� ReadProcessMemory ʱ�� RETN 0x14
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesRead != NULL)
	{
		*lpNumberOfBytesRead = nSize;
	}
	// ������
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}

// д�����ڴ棨�ж��ŵ��ã�
BOOL WINAPI HbgWriteProcessMemory_INT(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesWritten)
{
	LONG NtStatus;
	__asm
	{
		lea edx, hProcess;
		mov eax, 0x115;
		int 0x2E;
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesWritten != NULL)
	{
		*lpNumberOfBytesWritten = nSize;
	}
	// ������
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}

// д�����ڴ棨���ٵ��ã�
BOOL WINAPI HbgWriteProcessMemory_FAST(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesWritten)
{
	LONG NtStatus;
	__asm
	{
		// ģ�� WriteProcessMemory
		lea eax, nSize;
		push eax;
		push nSize;
		push lpBuffer;
		push lpBaseAddress;
		push hProcess;
		sub esp, 0x04; // ģ�� WriteProcessMemory ��� CALL NtWriteVirtualMemory
		// ģ�� NtWriteVirtualMemory
		mov eax, 0x115;
		push NtWriteVirtualMemoryReturn; // ģ�� NtWriteVirtualMemory ������� CALL [0x7FFE0300]
		// ģ�� KiFastSystemCall
		mov edx, esp;
		_emit 0x0F; // sysenter 
		_emit 0x34;
	NtWriteVirtualMemoryReturn:
		add esp, 0x18; // ģ�� NtWriteVirtualMemory ���ص� WriteProcessMemory ʱ�� RETN 0x14
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesWritten != NULL)
	{
		*lpNumberOfBytesWritten = nSize;
	}
	// ������
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}

// ��Ȩ����������ΪDEBUGȨ��
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

int main(int argc, char* argv[])
{
	EnableDebugPrivilege();

	DWORD pid, addr, dwRead, dwWritten;
	char buff[20] = { 0 };
	printf("��������PID��Ҫ�������Ե�ַ����Ϊ16���ƣ�...\n");
	scanf("%x %x", &pid, &addr);
	getchar();

	// ���������汾�� ReadProcessMemory
	HbgReadProcessMemory_INT(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)addr, buff, 4, &dwRead);
	printf("��ȡ��%d���ֽڣ�������: \"%s\"\n", dwRead, buff);
	HbgReadProcessMemory_FAST(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)(addr + 4), buff, 4, &dwRead);
	printf("��ȡ��%d���ֽڣ�������: \"%s\"\n", dwRead, buff);

	// ���������汾�� WriteProcessMemory
	HbgWriteProcessMemory_INT(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)addr, (LPVOID)"##", 2, &dwWritten);
	printf("д����%d�ֽ�.\n", dwWritten);
	HbgWriteProcessMemory_FAST(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)(addr + 4), (LPVOID)"**", 2, &dwWritten);
	printf("д����%d�ֽ�.\n", dwWritten);

	// �ٴζ�ȡ����֤д���Ƿ�ɹ�
	HbgReadProcessMemory_INT(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)addr, buff, 4, &dwRead);
	printf("��ȡ��%d���ֽڣ�������: \"%s\"\n", dwRead, buff);
	HbgReadProcessMemory_FAST(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)(addr + 4), buff, 4, &dwRead);
	printf("��ȡ��%d���ֽڣ�������: \"%s\"\n", dwRead, buff);

	printf("bye!\n");
	getchar();
	return 0;
}