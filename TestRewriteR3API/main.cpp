#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>

int main(int argc, char* argv[])
{
    // ��ȡ��������� PID
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return 0;
    }
    PROCESSENTRY32 pi;
    pi.dwSize = sizeof(PROCESSENTRY32); // ��һ��ʹ�ñ����ʼ����Ա
    BOOL bRet = Process32First(hSnapshot, &pi);
    while (bRet)
    {
        if (strcmp("TestReWriteR3API.exe", pi.szExeFile) == 0)
        {
            printf("����ID = %X \r\n", pi.th32ProcessID);

            break;
        }
        bRet = Process32Next(hSnapshot, &pi);
    }
    CloseHandle(hSnapshot);

    char str[] = "�˾Ͷ�����";
    printf("%p--%s\n", str, str);
    getchar();

    return 0;
}