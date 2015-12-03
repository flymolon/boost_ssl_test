/********************************************************************************
模块名       : OnlineUpdateV2.0
文件名       : Utils.h
相关文件     : Utils.cpp
文件实现功能 : 通用函数
作者         : xiaolong.mo
--------------------------------------------------------------------------------
备注         : <其它说明>
--------------------------------------------------------------------------------
修改记录 : 
日 期        版本     修改人              修改内容
2014/05/30   1.0      xiaolong.mo         创建
*******************************************************************************/
#pragma once
#include <WTypes.h>
#include <xstring>

#ifndef _WIN64
#pragma warning(disable:4312)
#endif

LPTSTR ErrorText(DWORD dwLastError);
LPTSTR GetAbsPath(LPCTSTR lpPath);
LPTSTR GetAbsPath(TCHAR (&szPath)[MAX_PATH], LPCTSTR lpPath, LPCTSTR szAccording = NULL);
BOOL CreateDirectoryChain(LPTSTR lpDir);
BOOL CreateDirectoryChain(LPCTSTR lpDir);
BOOL ClearDirectory(LPCTSTR lpDir);
BOOL IsValidIpv4(LPCTSTR lpIp);
std::string GetIpFromDomain(LPCTSTR lpDomain);
BOOL IsNotDots(LPCWSTR lpFileName);

void GenerateRandomMem(char* p, int bytes);

BOOL ExecCmdline(LPCTSTR szCmd, LPCTSTR szDir = NULL, LPPROCESS_INFORMATION ppi = NULL);
class tempW2A
{
public:
	tempW2A(LPCWSTR lpSrc, DWORD dwCodePage = CP_UTF8)
	{
		int len = WideCharToMultiByte(dwCodePage, 0, lpSrc, -1, 0, 0, 0, 0);
		if (!len)
		{
			m_lpVal = NULL;
			return ;
		}
		m_lpVal = new char[len];
		WideCharToMultiByte(dwCodePage, 0, lpSrc, -1, m_lpVal, len, 0, 0);
	}

	~tempW2A()
	{
		if (m_lpVal)
		{
			delete [] m_lpVal;
		}
	}

	LPSTR Detach(){return (LPSTR)InterlockedExchangePointer((void**)&m_lpVal, 0);}

	operator const char* ()
	{
		return m_lpVal;
	}

private:
	tempW2A& operator = (tempW2A &);

	tempW2A(tempW2A& rs){}

	volatile LPSTR m_lpVal;
};

class tempA2W
{
public:
	tempA2W(LPCSTR lpSrc, DWORD dwCodePage = CP_UTF8)
	{
		int len = MultiByteToWideChar(dwCodePage, 0, lpSrc, -1, 0, 0);
		if (!len)
		{
			m_lpVal = NULL;
			return ;
		}
		m_lpVal = new wchar_t[len];
		MultiByteToWideChar(dwCodePage, 0, lpSrc, -1, m_lpVal, len);
	}

	~tempA2W()
	{
		if (m_lpVal){delete [] m_lpVal;}
	}

	LPWSTR Detach(){return (LPWSTR)InterlockedExchangePointer((void**)&m_lpVal, 0);}

	operator const wchar_t *()
	{
		return m_lpVal;
	}

private:
	tempA2W& operator = (tempA2W &);
	tempA2W(tempA2W& rs){}

	LPWSTR m_lpVal;
};

class tempA2A
{
public:
	tempA2A(LPCSTR lpSrc, DWORD = CP_UTF8)
	{
		m_lpVal = lpSrc;
	}

	operator const char* ()
	{
		return m_lpVal;
	}

	LPSTR Detach(){
		size_t len = strlen(m_lpVal)+1;
		LPSTR p = new char[len];
		strcpy_s(p, len, m_lpVal);
		return p;
	}

private:

	tempA2A& operator = (tempA2A &);

	tempA2A(tempA2A& rs){}

	volatile LPCSTR m_lpVal;
};


class tempW2W
{
public:
	tempW2W(LPCWSTR lpSrc, DWORD = CP_UTF8)
	{
		m_lpVal = lpSrc;
	}

	operator const wchar_t* ()
	{
		return m_lpVal;
	}

	LPWSTR Detach(){
		size_t len = wcslen(m_lpVal)+1;
		LPWSTR p = new wchar_t[len];
		wcscpy_s(p, len, m_lpVal);
		return p;
	}

private:

	tempW2W& operator = (tempW2W &);

	tempW2W(tempW2W& rs){}

	volatile LPCWSTR m_lpVal;
};

#ifdef _UNICODE
typedef tempA2W tempA2T;
typedef tempW2A tempT2A;
typedef tempW2W tempW2T;
typedef tempW2W tempT2W;
#else
typedef tempW2A tempW2T;
typedef tempA2W tempT2W;
typedef tempA2A tempA2T;
typedef tempA2A tempT2A;
#endif
