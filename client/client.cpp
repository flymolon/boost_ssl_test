#include "stdafx.h"
#include "../boostssl.hpp"
#include <WTypes.h>
#include "../interface.h"
#include "../Utils.h"
#include <boost/shared_ptr.hpp>


using namespace client;

struct client_io_service
{
	client_io_service(boost::asio::ssl::context &context)
		: resolver_(io_service_)
		, socket_(io_service_, context)
		, work_(io_service_)
	{
		socket_.set_verify_mode(boost::asio::ssl::verify_peer);
	}

	boost::asio::io_service io_service_;
	boost::asio::ip::tcp::resolver resolver_;
	ssl_socket socket_;
	boost::asio::io_service::work work_;
};

class CBoostNetwork : public INetwork
{
public:
	CBoostNetwork()
		: io_thread_(NULL)
		, context_(boost::asio::ssl::context::sslv2_client)
		, connected_(false)
		, msg_(NULL)
	{
	}

	virtual ~CBoostNetwork() { if (msg_) { free(msg_); msg_ = NULL; } }

	virtual BOOL Initialize(LPCTSTR *szError, INetworkSink *pSink)
	{
		sink_ = pSink;
		return TRUE;
	}

	virtual BOOL LoadCert(LPCTSTR path)
	{
		try
		{
			context_.set_password_callback(boost::bind(&CBoostNetwork::get_password, this));
			context_.load_verify_file("servercert.pem");
			context_.use_certificate_file("clientcert.pem", boost::asio::ssl::context_base::pem);
			context_.use_private_key_file("clientkey.pem", boost::asio::ssl::context_base::pem);
		}
		catch (boost::system::error_code & ec)
		{
			printf("err> %s\n", ec.message().c_str());
			return FALSE;
		}
		return TRUE;
		return load_pfx(context_, path, "test");
	}

	std::string get_password() const
	{
		return "test";
	}

	virtual BOOL Connect(LPCSTR addr, int port)
	{
		char sport[6];
		if (port <= 0 || port >= 65535)
			return FALSE;

		io_.reset(new client_io_service(context_));
		if (!io_.get())
			return FALSE;
		io_->socket_.set_verify_callback(
			boost::bind(&CBoostNetwork::verify_certificate, this, _1, _2));

		_itoa_s(port, sport, 10);
		boost::asio::ip::tcp::resolver::query query(addr, sport);
		boost::asio::ip::tcp::resolver::iterator iterator =
			io_->resolver_.resolve(query);

		boost::asio::async_connect(io_->socket_.lowest_layer(), iterator,
			boost::bind(&CBoostNetwork::handle_connect, this,
				boost::asio::placeholders::error));

		io_thread_ = CreateThread(NULL, 0,
			(LPTHREAD_START_ROUTINE)&CBoostNetwork::_ThreadProc,
			this, 0, NULL);

		if (!io_thread_)
		{
			_tprintf_s(_T("启动网络接收失败\n"));
			return FALSE;
		}

		DWORD dwExit = 0;
		if (WaitForSingleObject(io_thread_, 100) != WAIT_TIMEOUT
			&& GetExitCodeThread(io_thread_, &dwExit)
			&& dwExit != STILL_ACTIVE)
		{
			_tprintf_s(_T("网络启动后立即停止了\n"));
			CloseHandle(io_thread_);
			io_thread_ = NULL;
			return FALSE;
		}

		return TRUE;
	}

	virtual void Destroy()
	{
		delete this;
	}

	virtual void Close()
	{
		if (connected_)
			sink_->OnDisconnect();
		io_.reset();
		if (io_thread_)
		{
			if (WaitForSingleObject(io_thread_, 1000) == WAIT_TIMEOUT)
				TerminateThread(io_thread_, 0xdead);
			CloseHandle(io_thread_);
			io_thread_ = NULL;
		}
	}

	virtual BOOL Send(LPCSTR szCmd, LPCSTR szContent)
	{
		if (!message::format(msg_, szCmd, "%s", szContent))
			return FALSE;
		printf("将发送%u\n", msg_->length);
		//io_->socket_.write_some(msg_buffer(msg_));
		boost::asio::async_write(io_->socket_, msg_buffer(msg_),
			boost::asio::transfer_at_least(msg_->length),
			boost::bind(&CBoostNetwork::handle_write, this,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
		return TRUE;
	}

	void handle_write(const boost::system::error_code &ec,
		size_t bytes_transferred)
	{
		printf("发送%u/%u[%02X %02X %02X %02X %02X]\n",
			bytes_transferred, msg_->length,
			msg_->msg[0], msg_->msg[1], msg_->msg[2],
			msg_->msg[3], msg_->msg[4]);
		if (bytes_transferred < msg_->length)
		{
			boost::asio::transfer_at_least(msg_->length);
			io_->socket_.async_write_some(msg_buffer(msg_),
				boost::bind(&CBoostNetwork::handle_write, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
		else if (bytes_transferred == msg_->length)
		{
			printf("message sending complete %u\n", msg_->length);
		}
	}

	void handle_connect(const boost::system::error_code& error)
	{
		if (!error)
		{
			io_->socket_.async_handshake(boost::asio::ssl::stream_base::client,
				boost::bind(&CBoostNetwork::handle_handshake, this,
					boost::asio::placeholders::error));
		}
		else
		{
			sink_->OnConnectFailed(tempA2T(error.message().c_str(), CP_ACP));
		}
	}

	void handle_handshake(const boost::system::error_code& error)
	{
		if (!error)
		{
// 			std::cin.getline(request_, max_length);
// 			size_t request_length = strlen(request_);
// 
// 			boost::asio::async_write(socket_,
// 				boost::asio::buffer(request_, request_length),
// 				boost::bind(&client::handle_write, this,
// 					boost::asio::placeholders::error,
// 					boost::asio::placeholders::bytes_transferred));
			connected_ = true;
			sink_->OnConnect();
		}
		else
		{
			sink_->OnConnectFailed(tempA2T(error.message().c_str(), CP_ACP));
			//std::cout << "Handshake failed: " << error.message() << "\n";
		}
	}


public:
	bool verify_certificate(bool preverified,
		boost::asio::ssl::verify_context& ctx)
	{
		// The verify callback can be used to check whether the certificate that is
		// being presented is valid for the peer. For example, RFC 2818 describes
		// the steps involved in doing this for HTTPS. Consult the OpenSSL
		// documentation for more details. Note that the callback is called once
		// for each certificate in the certificate chain, starting from the root
		// certificate authority.

		// In this example we will simply print the certificate's subject name.
		char subject_name[256];
		X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
		X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
		std::cout << "Verifying " << subject_name << "\n";
		std::cout << "Result: " << preverified << "\n";

		return preverified;
	}

protected:
	static DWORD __stdcall _ThreadProc(CBoostNetwork *pthis)
	{
		try
		{
			pthis->io_->io_service_.run();
		}
		catch (boost::system::error_code &ec)
		{
			printf_s("IO运行异常:%s\n", ec.message().c_str());
		}
		catch (boost::system::system_error const& e)
		{
			if (e.code().value() != ERROR_ABANDONED_WAIT_0)
				printf_s("IO系统运行异常:%s\n", e.what());
		}
		_tprintf_s(_T("IO线程退出\n"));
		return 0;
	}

protected:
	HANDLE io_thread_;
	boost::shared_ptr<client_io_service> io_;
	boost::asio::ssl::context context_;
	INetworkSink *sink_;
	bool connected_;
	message *msg_;
};

INetwork *CreateClientInstance()
{
	return new CBoostNetwork;
}

