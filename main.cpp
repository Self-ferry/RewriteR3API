#define  _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<Windows.h>

// 读进程内存（中断门调用）
BOOL WINAPI HbgReadProcessMemory_INT(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead)
{
	LONG NtStatus;
	__asm
	{
		// 直接模拟 KiIntSystemCall
		lea edx, hProcess; // 要求 edx 存储最后入栈的参数
		mov eax, 0xBA;
		int 0x2E;
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesRead != NULL)
	{
		*lpNumberOfBytesRead = nSize;
	}
	// 错误检查
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}

// 读进程内存（快速调用）
BOOL WINAPI HbgReadProcessMemory_FAST(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead)
{
	LONG NtStatus;
	__asm
	{
		// 模拟 ReadProcessMemory
		lea eax, nSize;
		push eax;
		push nSize;
		push lpBuffer;
		push lpBaseAddress;
		push hProcess;
		sub esp, 0x04; // 模拟 ReadProcessMemory 里的 CALL NtReadVirtualMemory
		// 模拟 NtReadVirtualMemory
		mov eax, 0xBA;
		push NtReadVirtualMemoryReturn; // 模拟 NtReadVirtualMemory 函数里的 CALL [0x7FFE0300]
		// 模拟 KiFastSystemCall
		mov edx, esp;
		_emit 0x0F; // sysenter 
		_emit 0x34;
	NtReadVirtualMemoryReturn:
		add esp, 0x18; // 模拟 NtReadVirtualMemory 返回到 ReadProcessMemory 时的 RETN 0x14
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesRead != NULL)
	{
		*lpNumberOfBytesRead = nSize;
	}
	// 错误检查
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}

// 写进程内存（中断门调用）
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
	// 错误检查
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}

// 写进程内存（快速调用）
BOOL WINAPI HbgWriteProcessMemory_FAST(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesWritten)
{
	LONG NtStatus;
	__asm
	{
		// 模拟 WriteProcessMemory
		lea eax, nSize;
		push eax;
		push nSize;
		push lpBuffer;
		push lpBaseAddress;
		push hProcess;
		sub esp, 0x04; // 模拟 WriteProcessMemory 里的 CALL NtWriteVirtualMemory
		// 模拟 NtWriteVirtualMemory
		mov eax, 0x115;
		push NtWriteVirtualMemoryReturn; // 模拟 NtWriteVirtualMemory 函数里的 CALL [0x7FFE0300]
		// 模拟 KiFastSystemCall
		mov edx, esp;
		_emit 0x0F; // sysenter 
		_emit 0x34;
	NtWriteVirtualMemoryReturn:
		add esp, 0x18; // 模拟 NtWriteVirtualMemory 返回到 WriteProcessMemory 时的 RETN 0x14
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesWritten != NULL)
	{
		*lpNumberOfBytesWritten = nSize;
	}
	// 错误检查
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}

// 提权函数：提升为DEBUG权限
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
	printf("依次输入PID和要读的线性地址（均为16进制）...\n");
	scanf("%x %x", &pid, &addr);
	getchar();

	// 测试两个版本的 ReadProcessMemory
	HbgReadProcessMemory_INT(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)addr, buff, 4, &dwRead);
	printf("读取了%d个字节，内容是: \"%s\"\n", dwRead, buff);
	HbgReadProcessMemory_FAST(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)(addr + 4), buff, 4, &dwRead);
	printf("读取了%d个字节，内容是: \"%s\"\n", dwRead, buff);

	// 测试两个版本的 WriteProcessMemory
	HbgWriteProcessMemory_INT(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)addr, (LPVOID)"##", 2, &dwWritten);
	printf("写入了%d字节.\n", dwWritten);
	HbgWriteProcessMemory_FAST(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)(addr + 4), (LPVOID)"**", 2, &dwWritten);
	printf("写入了%d字节.\n", dwWritten);

	// 再次读取，验证写入是否成功
	HbgReadProcessMemory_INT(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)addr, buff, 4, &dwRead);
	printf("读取了%d个字节，内容是: \"%s\"\n", dwRead, buff);
	HbgReadProcessMemory_FAST(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (LPCVOID)(addr + 4), buff, 4, &dwRead);
	printf("读取了%d个字节，内容是: \"%s\"\n", dwRead, buff);

	printf("bye!\n");
	getchar();
	return 0;
}