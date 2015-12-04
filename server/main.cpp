// server.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <WTypes.h>
#include "../interface.h"
#include <locale>
#include "../utils.h"

using namespace server;

class CServer : public INetworkSink
{
public:

	void Run()
	{
		LPCTSTR szError;
		extern INetwork * CreateBoostNetworkInstance();
		INetwork *network = CreateBoostNetworkInstance();

		if (!network->Initialize(&szError, this))
		{
			_tprintf(_T("初始化失败:%s\n"), szError);
			network->Destroy();
			return;
		}

		if (!network->LoadCert(CERT_PATH _T("server.pfx")))
		{
			_tprintf(_T("加载证书失败\n"));
			network->Destroy();
			return;
		}

		if (!network->Start(9466))
		{
			_tprintf(_T("监听失败\n"));
			network->Destroy();
			return;
		}

		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0))
		{
		}

		printf("shutting down...\n");
		network->Shutdown(6000);
		network->Destroy();
	}

	virtual BOOL OnNewConnection(ISession *session)
	{
		_tprintf_s(_T("新连接：%s\n"), session->GetPeerName());
		return TRUE;
	}

	virtual void OnException(ISession *session, LPCTSTR szError)
	{
		_tprintf_s(_T("异常[%s]：%s\n"), session->GetPeerName(), szError);
	}

	virtual void OnCommand(ISession *session, LPCSTR szCmd, LPCSTR szContent)
	{
		_tprintf_s(_T("命令[%s]：%s[%s]\n"),
			session->GetPeerName(), tempA2T(szCmd), tempA2T(szContent));
	}

	virtual void OnDisconnection(ISession *session)
	{
		_tprintf_s(_T("连接[%s]已断开\n"), session->GetPeerName());
	}

	virtual void OnFileSendComplete(ISession *session)
	{
		_tprintf_s(_T("已发送\n"));
	}
};

int _tmain(int argc, _TCHAR* argv[])
{
	setlocale(LC_ALL, "chs");

	std::locale::global(std::locale("chs"));
	CServer server;
	server.Run();
	return 0;
}

