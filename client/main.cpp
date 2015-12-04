#include "stdafx.h"
#include <wtypes.h>

#include "../interface.h"

using namespace client;

class CClient : public INetworkSink
{
public:
	// INetworkSink methods
	virtual void OnConnect()
	{
		printf("��������������\n");
	}

	virtual void OnConnectFailed(LPCTSTR szError)
	{
		_tprintf_s(_T("����������ʧ��,%s\n"), szError);
	}

	virtual void OnDisconnect()
	{
		_tprintf_s(_T("�������ѶϿ�\n"));
	}

	virtual void OnReceive(LPCSTR szCmd, LPCSTR szContent)
	{
		_tprintf_s(_T("�յ���Ϣ<%s>:%s\n"), szCmd, szContent);
	}


	void Run()
	{
		LPCTSTR szError = NULL;
		extern INetwork *CreateClientInstance();
		INetwork *network = CreateClientInstance();
		if (!network)
		{
			printf("�������ʧ��\n");
			return;
		}
		if (!network->Initialize(&szError, this))
		{
			printf("�����ʼ��ʧ��\n");
			network->Destroy();
			return;
		}
		if (!network->LoadCert(CERT_PATH _T("client.pfx")))
		{
			printf("����֤��ʧ��\n");
			network->Destroy();
			return;
		}
		if (!network->Connect("127.0.0.1", 9466))
		{
			printf("���ӷ�����ʧ��\n");
			network->Destroy();
			return;
		}

		Sleep(4000);
		network->Send("cmd_verify", "please verify me!!\n");
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0))
		{
		}

		network->Close();
		network->Destroy();
	}
};


int _tmain(int argc, _TCHAR* argv[])
{
	CClient client;
	client.Run();
	system("pause");
	return 0;
}
