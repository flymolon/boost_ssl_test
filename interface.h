#pragma once

#define _interface struct __declspec(novtable)

namespace server
{

	_interface INetworkSink;

	_interface INetwork
	{
		virtual BOOL Initialize(LPCTSTR *szError, INetworkSink *pSink) = 0;
		virtual BOOL LoadCert(LPCTSTR szCertPath) = 0;
		virtual BOOL Start(int nPort) = 0;
		virtual void Shutdown(DWORD dwWait) = 0;
		virtual void Destroy() = 0;
	};

	_interface ISession
	{
		virtual LPCTSTR GetPeerName() = 0;
		virtual void SetUserInfo(LPVOID) = 0;
		virtual void* GetUserInfo() = 0;
		virtual bool Answer(LPCSTR szCmd, LPCSTR fmt, ...) = 0;
		virtual bool StartSendFile(LPCTSTR szFilePath, __int64 offset) = 0;
	};

	_interface INetworkSink
	{
		virtual BOOL OnNewConnection(ISession *session) = 0;
		virtual void OnException(ISession *session, LPCTSTR szError) = 0;
		virtual void OnCommand(ISession *session, LPCSTR szCmd, LPCSTR szContent) = 0;
		virtual void OnDisconnection(ISession *session) = 0;
		virtual void OnFileSendComplete(ISession *session) = 0;
	};
}


namespace client
{
	_interface INetworkSink;

	_interface INetwork
	{
		virtual BOOL Initialize(LPCTSTR *szError, INetworkSink *pSink) = 0;
		virtual BOOL LoadCert(LPCTSTR szCertPath) = 0;
		virtual BOOL Connect(LPCSTR szAddr, int nPort) = 0;
		virtual void Close() = 0;
		virtual void Destroy() = 0;
		virtual BOOL Send(LPCSTR szCmd, LPCSTR szContent) = 0;
	};

	_interface INetworkSink
	{
		virtual void OnConnect() = 0;
		virtual void OnConnectFailed(LPCTSTR szError) = 0;
		virtual void OnDisconnect() = 0;

		virtual void OnReceive(LPCSTR szCmd, LPCSTR szContent) = 0;
	};
}

//#define CERT_PATH _T("D:\\ssltest\\")
//#define CERT_PATH _T("E:\\codes\\Company\\svn\\NasSysScan\\SysScanEngine")\
//	_T("\\misc\\libnasmgr\\new_projects\\tcptest\\Debug\\keygen\\")
#define CERT_PATH _T("")