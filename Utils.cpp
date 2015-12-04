/********************************************************************************
模块名       : OnlineUpdateV2.0
文件名       : Utils.cpp
相关文件     : Utils.h
文件实现功能 : 通用函数
作者         : xiaolong.mo
--------------------------------------------------------------------------------
备注         : <其它说明>
--------------------------------------------------------------------------------
修改记录 : 
日 期        版本     修改人              修改内容
2014/05/30   1.0      xiaolong.mo         创建
*******************************************************************************/
#include "Utils.h"
#include <lmerr.h>
#include <tchar.h>
#include <Shlwapi.h>
#include <time.h>

#pragma comment(lib, "shlwapi.lib")

#define RTN_OK 0
#define RTN_USAGE 1
#define RTN_ERROR 13


BOOL IsNotDots(LPCWSTR lpFileName)
{
	return (lpFileName[0] != L'.'
		|| (lpFileName[1] != L'\0' && lpFileName[1] != L'.')
		|| (lpFileName[1] == L'.' && lpFileName[2] != L'\0'));
}


LPTSTR ErrorText(DWORD dwLastError)
{
	HMODULE hModule = NULL; // default to system source
	LPTSTR MessageBuffer = NULL;
	DWORD dwBufferLength;

	DWORD dwFormatFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_FROM_SYSTEM ;

	//
	// If dwLastError is in the network range,
	//  load the message source.
	//

	if(dwLastError >= NERR_BASE && dwLastError <= MAX_NERR) {
		hModule = LoadLibraryEx(
			TEXT("netmsg.dll"),
			NULL,
			LOAD_LIBRARY_AS_DATAFILE
			);

		if(hModule != NULL)
		{
			dwFormatFlags |= FORMAT_MESSAGE_FROM_HMODULE;
		}
	}

	//
	// Call FormatMessage() to allow for message
	//  text to be acquired from the system
	//  or from the supplied module handle.
	//

	dwBufferLength = FormatMessage(
		dwFormatFlags,
		hModule, // module to get message from (NULL == system)
		dwLastError,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
		(LPTSTR) &MessageBuffer,
		0,
		NULL
		);

	if (MessageBuffer)
	{
		if (MessageBuffer[_tcslen(MessageBuffer)-1] == _T('\n'))
		{
			MessageBuffer[_tcslen(MessageBuffer)-1] = 0;
		}

		LPVOID lpBuffer = LocalAlloc(LPTR,
			(dwBufferLength+13)*sizeof(TCHAR));

		if (lpBuffer)
		{
			_stprintf_s((LPTSTR)lpBuffer,
				dwBufferLength+13,
				_T("%s(0x%08x)"), MessageBuffer, dwLastError);
			LocalFree(MessageBuffer);
			MessageBuffer = (LPTSTR)lpBuffer;
		}
	}
	else
	{
		LPVOID lpBuffer = LocalAlloc(LPTR, 48);
		if (lpBuffer)
		{
			_stprintf_s((LPTSTR)lpBuffer,
				48/sizeof(TCHAR),
				_T("未知错误：%u"),
				dwLastError);
			MessageBuffer = (LPTSTR)lpBuffer;
		}
	}

	//
	// If we loaded a message source, unload it.
	//
	if(hModule != NULL)
	{
		FreeLibrary(hModule);
	}

	return MessageBuffer;
}


LPTSTR GetAbsPath(LPCTSTR lpPath)
{
	if (!PathIsRelative(lpPath))
	{
		LPTSTR szPath = new TCHAR[MAX_PATH];
		PathCanonicalize(szPath, lpPath);
		return (LPTSTR)szPath;
	}

	TCHAR szFmt[MAX_PATH] = {0};
	_tcscpy_s(szFmt, lpPath);

	LPTSTR lpCan = szFmt;
	while (lpCan = _tcschr(lpCan, _T('/')))
	{
		lpCan[0] = _T('\\');
	}

	LPTSTR szPath = new TCHAR[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	LPTSTR p = wcsrchr(szPath, _T('\\'));
	if (p)
	{
		p[1] = 0;
	}

	PathAppend(szPath, szFmt);
	return szPath;
}


LPTSTR GetAbsPath(TCHAR (&szPath)[MAX_PATH], LPCTSTR lpPath, LPCTSTR szAccording /*= NULL*/)
{
	if (!PathIsRelative(lpPath))
	{
		PathCanonicalize(szPath, lpPath);
		return (LPTSTR)lpPath;
	}

	TCHAR szFmt[MAX_PATH] = {0};
	_tcscpy_s(szFmt, lpPath);

	LPTSTR lpCan = szFmt;
	while (lpCan = _tcschr(lpCan, _T('/')))
	{
		lpCan[0] = _T('\\');
	}

	if (szAccording)
	{
		_tcscpy_s(szPath, szAccording);
	}
	else
	{
		GetModuleFileName(NULL, szPath, MAX_PATH);
	}
	LPTSTR p = wcsrchr(szPath, _T('\\'));
	if (p)
	{
		p[1] = 0;
	}

	PathAppend(szPath, szFmt);
	return p;
}


BOOL CreateDirectoryChain(LPTSTR lpDir)
{
	if (PathFileExists(lpDir))
	{
		return PathIsDirectory(lpDir);
	}

	LPTSTR lpCur = _tcsrchr(lpDir, _T('\\'));

	if (lpCur)
	{
		lpCur[0] = 0;
		if (!CreateDirectoryChain(lpDir))
		{
			lpCur[0] = _T('\\');
			return FALSE;
		}
		lpCur[0] = _T('\\');
	}
	return CreateDirectory(lpDir, NULL);
}


BOOL CreateDirectoryChain(LPCTSTR lpDir)
{
	if (!lpDir)
	{
		return FALSE;
	}

	if (PathFileExists(lpDir))
	{
		return PathIsDirectory(lpDir);
	}

	size_t length = _tcslen(lpDir)+1;
	LPTSTR lpDirReal = new TCHAR[length];
	_tcscpy_s(lpDirReal, length, lpDir);

	BOOL res = CreateDirectoryChain(lpDirReal);
	delete [] lpDirReal;
	return res;
}


BOOL ClearDirectory(LPTSTR lpDir)
{
	WIN32_FIND_DATAW wfd = {0};
	int len = _tcslen(lpDir);
	_tcscat_s(lpDir, MAX_PATH, _T("\\*.*"));
	HANDLE hFind = FindFirstFile(lpDir, &wfd);
	BOOL bRes = TRUE;
	do 
	{
		lpDir[len+1] = 0;
		_tcscat_s(lpDir, MAX_PATH, wfd.cFileName);
		if (PathIsDirectory(lpDir))
		{
			if (IsNotDots(wfd.cFileName))
			{
				wcscat_s(lpDir, MAX_PATH, wfd.cFileName);
				bRes &= (ClearDirectory(lpDir) && RemoveDirectory(lpDir));
			}
		}
		else
		{
			bRes &= DeleteFile(lpDir);
		}
	} while (FindNextFile(hFind, &wfd));
	FindClose(hFind);
	lpDir[len] = 0;
	return bRes;
}


BOOL ClearDirectory(LPCTSTR lpDir)
{
	TCHAR szPath[MAX_PATH];
	_tcscpy_s(szPath, lpDir);
	return ClearDirectory(szPath);
}


void GenerateRandomMem(char* p, int bytes)
{
	srand((unsigned)time(NULL));
	for(int i = 0; i < bytes; i++)
	{
		p[i] = (char)(rand()%0x100);
	}
}


BOOL IsValidIpv4(LPCTSTR lpIp)
{
	if (lpIp == NULL)
	{
		return FALSE;
	}
	int nField[4] = {0};
	if (_stscanf_s(lpIp, _T("%d.%d.%d.%d"), &nField[0], &nField[1], &nField[2], &nField[3]) != 4
		|| nField[0] >255 || nField[0]<0
		|| nField[1] >255 || nField[1]<0
		|| nField[2] >255 || nField[2]<0
		|| nField[3] >255 || nField[3]<0)
	{
		return FALSE;
	}
	TCHAR szConfirm[16] = {0};
	_stprintf_s(szConfirm, _T("%d.%d.%d.%d"), nField[0], nField[1], nField[2], nField[3]);
	return _tcscmp(szConfirm, lpIp) == 0;
}

#if 0
std::string GetIpFromDomain( LPCTSTR lpDomain )
{
	int WSA_return;
	WSADATA WSAData;

	WSA_return=WSAStartup(0x0101,&WSAData);

	HOSTENT *host_entry;

	std::string str;

	if(WSA_return==0 && lpDomain != NULL)
	{
#ifdef _UNICODE
		int nLen = WideCharToMultiByte(CP_ACP, 0, lpDomain, (int)_tcslen(lpDomain), NULL, 0, NULL, NULL);
		char* p = new char[nLen+1];
		memset(p, 0, sizeof(char)*(nLen+1));
		WideCharToMultiByte(CP_ACP, 0, lpDomain, (int)_tcslen(lpDomain), p, nLen, NULL, NULL);
		host_entry = gethostbyname(p);
		delete [] p;
#else
		host_entry=gethostbyname(lpDomain);
#endif
		if(host_entry!=0)
		{
			str = inet_ntoa(*(in_addr*)host_entry->h_addr);
		}
	}
	WSACleanup();
	return str;
}

#endif


BOOL ExecCmdline(LPCTSTR szCmd, LPCTSTR szDir /*= NULL*/, LPPROCESS_INFORMATION ppi /*= NULL*/)
{
	STARTUPINFO si = {0};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	int exeLen = wcslen(szCmd)+wcslen(L"cmd.exe /c ")+1;
	if (wcschr(szCmd, L' ') != NULL)
	{
		exeLen += 2;
	}
	wchar_t *pexe = new wchar_t[exeLen];
	if (wcschr(szCmd, L' ') != NULL)
	{
		swprintf_s(pexe, exeLen, L"cmd.exe /c \"%s\"", (LPCWSTR)szCmd);
	}
	else
	{
		swprintf_s(pexe, exeLen, L"cmd.exe /c %s", (LPCWSTR)szCmd);
	}
	LPPROCESS_INFORMATION ppiReal = ppi;
	if (ppi == NULL)
	{
		ppiReal = new PROCESS_INFORMATION;
		memset(ppiReal, 0, sizeof(PROCESS_INFORMATION));
	}
	if (!CreateProcess(NULL, pexe, NULL, NULL, FALSE, 0, NULL,
		szDir, &si, ppiReal))
	{
		if (ppi == NULL)
		{
			delete ppiReal;
		}
		delete [] pexe;
		return FALSE;
	}
	if (ppi == NULL)
	{
		CloseHandle(ppiReal->hThread);
		CloseHandle(ppiReal->hProcess);
		delete ppiReal;
	}
	delete [] pexe;
	return TRUE;
}
