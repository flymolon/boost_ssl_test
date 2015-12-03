#include "stdafx.h"
#include <cstdlib>
#include <iostream>
#include "../boostssl.hpp"
#include <WTypes.h>
#include "../interface.h"
#include "../Utils.h"
#include <boost/shared_ptr.hpp>

#define CERT_KEY "test"

// boost implementation
using namespace server;


static LPTSTR GetHostName(SOCKET s)
{
	sockaddr_in sockAddr;
	int nSockAddrLen = sizeof(sockAddr);
	memset(&sockAddr, 0, nSockAddrLen);
	BOOL bResult = getpeername(s, (SOCKADDR*)&sockAddr, &nSockAddrLen);
	if (bResult == INVALID_SOCKET)
		return NULL;
	int len = _sctprintf(_T("<%d>%hs:%d"),
		s, inet_ntoa(sockAddr.sin_addr), sockAddr.sin_port);
	LPTSTR p = new TCHAR[len + 1];
	_stprintf_s(p, len + 1, _T("<%d>%hs:%d"),
		s, inet_ntoa(sockAddr.sin_addr), sockAddr.sin_port);
	return p;
}

class overlapped_file : public boost::asio::windows::random_access_handle
{
public:
	overlapped_file(boost::asio::io_service& io_service)
		: boost::asio::windows::random_access_handle(io_service)
	{}

	template<typename Handler>
	bool transmit(boost::asio::ip::tcp::socket& socket, __int64 offset,
		Handler handler)
	{
		LARGE_INTEGER liSize = { 0 };
		DWORD send_size = 0;

		if (!GetFileSizeEx(native_handle(), &liSize))
			return false;

		if (offset != 0)
		{
			if (liSize.QuadPart <= offset)
				return false;

			liOffset.QuadPart = offset;
			overlapped_.get()->Offset = liOffset.LowPart;
			overlapped_.get()->OffsetHigh = liOffset.HighPart;
		}

		overlapped_.reset(get_io_service(), handler);
	}

	boost::asio::windows::overlapped_ptr overlapped_;
};

template <typename Handler>
bool transmit_file(boost::asio::ip::tcp::socket& socket,
				   boost::asio::windows::random_access_handle& file, __int64 offset,
				   Handler handler)
{
	// Construct an OVERLAPPED-derived object to contain the handler.
	boost::asio::windows::overlapped_ptr overlapped(
		socket.get_io_service(), handler);
	LARGE_INTEGER liSize = { 0 };
	DWORD send_size_ = 0;

	if (!GetFileSizeEx(file.native_handle(), &liSize))
		return false;

	if (offset != 0)
	{
		if (liSize.QuadPart <= offset)
			return false;

		LARGE_INTEGER liOffset;
		liOffset.QuadPart = offset;
		overlapped.get()->Offset = liOffset.LowPart;
		overlapped.get()->OffsetHigh = liOffset.HighPart;
	}

	if (liSize.QuadPart > 0x7FFFFFFE)
		send_size_ = 0x7FFFFFFE;

	// Initiate the TransmitFile operation.
	BOOL ok = ::TransmitFile(socket.native_handle(),
		file.native_handle(), send_size_, 0, overlapped.get(), 0, 0);
	DWORD last_error = ::GetLastError();

	// Check if the operation completed immediately.
	if (!ok && last_error != ERROR_IO_PENDING)
	{
		// The operation completed immediately, so a completion notification needs
		// to be posted. When complete() is called, ownership of the OVERLAPPED-
		// derived object passes to the io_service.
		boost::system::error_code ec(last_error,
			boost::asio::error::get_system_category());
		overlapped.complete(ec, 0);
	}
	else
	{
		// The operation was successfully initiated, so ownership of the
		// OVERLAPPED-derived object has passed to the io_service.
		overlapped.release();
	}
	return true;
}

class session : public ISession
{
#define read_buffer msg_buffer(message_read_)
#define write_buffer msg_buffer(message_write_)

	enum session_state {
		// session state, value means timeouts
#ifdef _DEBUG
		none = 0,
		handshaking = 2000,
		receiving_fist_req = 60000,
		receiving_common_req = 80000,
		sendingfile = 15000,// while sending file, Answer() would fail
		shuttingdown = 1000,
#else
		handshaking = 5000,
		receiving_fist_req = 10000,
		receiving_common_req = 180000,
		sendingfile = 15000,// while sending file, Answer() would fail
		shuttingdown = 2000,
#endif
	};

public:
	// ISession methods
	virtual LPCTSTR GetPeerName()
	{
		if (!peer_name_)
		{
			LPTSTR p = GetHostName(socket_.lowest_layer().native_handle());
			if (InterlockedCompareExchangePointer(
				(volatile LPVOID*)&peer_name_, p, NULL) == NULL)
				return peer_name_;
			delete[] p;
		}
		return peer_name_;
	}

	virtual void SetUserInfo(LPVOID data) { user_info_ = data; }
	virtual LPVOID GetUserInfo() { return user_info_; }
	virtual bool Answer(LPCSTR cmd, LPCSTR fmt, ...)
	{
		va_list ap;
		if (state_ == sendingfile)
			return false;

		va_start(ap, fmt);
		if (!message::formatv(message_write_, cmd, fmt, ap))
			return false;
		return (boost::asio::write(socket_, write_buffer)
			== message_write_->length);
	}

	virtual bool StartSendFile(LPCTSTR path, __int64 offset)
	{
		boost::system::error_code ec;
		HANDLE hFile = ::CreateFile(path, GENERIC_READ, 0, 0, OPEN_EXISTING,
			FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL
			| FILE_FLAG_OVERLAPPED, 0);
		if (!hFile)
		{
			TCHAR msg[64+MAX_PATH];
			_stprintf_s(msg, _T("打开文件[%s]失败，错误码%u"), path);
			sink_->OnException(this, msg);
			return false;
		}

		file_.assign(hFile, ec);
		if (file_.is_open())
		{
			state_ = sendingfile;
			do_async_wait();
			transmit_file(socket_.next_layer(), file_, offset,
				boost::bind(&session::handle_send_file, this,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
			return true;
		}
		return false;
	}


public:
	session(boost::asio::io_service& io_service,
		boost::asio::ssl::context& context, INetworkSink *pSink)
		: fconnected_(FALSE)
		, sink_(pSink)
		, socket_(io_service, context)
		, message_read_(NULL)
		, message_write_(NULL)
		, user_info_(NULL)
		, peer_name_(NULL)
		, timer_(io_service)
		, file_(io_service)
		, state_(none)
	{
	}

	~session()
	{
		if (fconnected_)
			sink_->OnDisconnection(this);
		if (message_read_)
		{
			free(message_read_);
			message_read_ = NULL;
		}
		if (message_write_)
		{
			free(message_write_);
			message_write_ = NULL;
		}
		if (peer_name_)
		{
			delete[] peer_name_;
			peer_name_ = NULL;
		}
		_tprintf_s(_T("session destruct\n"));
	}

	ssl_socket::lowest_layer_type& socket()
	{
		return socket_.lowest_layer();
	}

	void do_async_wait()
	{
		timer_.expires_from_now(boost::posix_time::milliseconds(state_));
		timer_.async_wait(boost::bind(&session::handle_wait, this,
			boost::asio::placeholders::error, state_));
	}

	void start()
	{
		fconnected_ = TRUE;
		if (!sink_->OnNewConnection(this))
		{
			socket_.lowest_layer().close();
			return;
		}
		state_ = handshaking;
		do_async_wait();
		socket_.async_handshake(boost::asio::ssl::stream_base::server,
			boost::bind(&session::handle_handshake, this,
			boost::asio::placeholders::error));
	}

	void handle_wait(const boost::system::error_code &error,
		session_state state)
	{
		if (error || state_ != state)
			return;

		switch (state)
		{
		case handshaking:
			sink_->OnException(this, _T("握手已超时"));
			socket_.async_shutdown(boost::bind(&session::handle_shutdown,
				this));
			break;
		case receiving_fist_req:
			sink_->OnException(this, _T("第一个请求已超时"));
			socket_.async_shutdown(boost::bind(&session::handle_shutdown,
				this));
			break;
		case receiving_common_req:
			sink_->OnException(this, _T("已超时"));
			socket_.async_shutdown(boost::bind(&session::handle_shutdown,
				this));
			break;
		case shuttingdown:
			socket_.lowest_layer().close();
		case sendingfile:
		default:
			break;
		}
	}

	void handle_shutdown()
	{
		state_ = shuttingdown;
		do_async_wait();
	}

	bool assure_buffer_size(message *&msg, size_t size, LPCTSTR when)
	{
		if (!message::reserve(msg, size))
		{
			TCHAR err_[128];
			_stprintf_s(err_, _T("%s分配[%u]内存失败"), when, size);
			sink_->OnException(this, err_);
			socket_.shutdown();
			return false;
		}
		return true;
	}

	void handle_handshake(const boost::system::error_code& error)
	{
		timer_.cancel();
		if (!error)
		{
			if (!assure_buffer_size(message_read_, default_length,
				_T("为握手后准备接收消息时")))
			{
				socket_.lowest_layer().close();
				return;
			}

			state_ = receiving_fist_req;
			do_async_wait();
			socket_.async_read_some(read_buffer, boost::bind(
				&session::handle_read, this,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred,
				message_read_->length));
		}
		else
		{
			sink_->OnException(this, tempA2T(error.message().c_str(),
				CP_ACP));
			delete this;
		}
	}

	void handle_read(const boost::system::error_code& error,
		size_t bytes_transferred, size_t offset)
	{
		do_async_wait();
		if (!error)
		{
			offset += bytes_transferred;
			if (offset < sizeof(size_t))
			{
				// 				socket_.async_read_some(
				// 					msg_buffer_offset(message_read_, offset),
				// 					boost::bind(&session::handle_read, this, _1, offset));
				return;
			}

			if (offset - bytes_transferred < sizeof(size_t)// 第一次超过size_t的时候申请内存
				&& !assure_buffer_size(message_read_,
					message_read_->length, _T("读取数据时")))
				return;

			if (offset < message_read_->length)
			{
				// 				socket_.async_read_some(
				// 					msg_buffer_offset(message_read_, offset),
				// 					boost::bind(&session::handle_read, this, _1, offset));
				return;
			}

			size_t nlen = strnlen(message_read_->buffer,
				max_cmd_size + 1);

			if (nlen > message::max_cmd_length)
			{
				TCHAR szMsg[64];
				_stprintf_s(szMsg, _T("命令超长：%u/%u"),
					nlen, message::max_cmd_length);
				sink_->OnException(this, szMsg);
				if (!message::format(message_read_, "error",
					"<result code=\"-1\">too long command(max %u)"
					"</result>", message::max_cmd_length))
				{
					socket_.shutdown();
					return;
				}
				boost::asio::write(socket_, read_buffer);// reuse read memory to avoid allocation
				return;
			}

			((char*)message_read_)[message_read_->length - 1] = 0;

			// user should call Answer in OnCommand
			sink_->OnCommand(this, message_read_->buffer,
				message_read_->buffer + nlen + 1);

			state_ = receiving_common_req;
			do_async_wait();
			// 			socket_.async_read_some(read_buffer,
			// 				boost::bind(&session::handle_read, this,
			// 				boost::asio::placeholders::error,
			// 				boost::asio::placeholders::bytes_transferred));
		}
		else
		{
			switch (error.value())
			{
			case boost::asio::error::eof:
				break;
			default:
				_tprintf_s(_T("读取网络数据异常：%s\n"),
					tempA2T(error.message().c_str(), CP_ACP));
			}
			delete this;
		}
	}

	void handle_send_file(const boost::system::error_code& error,
		size_t transferred)
	{
		if (!error)
		{
			sink_->OnFileSendComplete(this);
		}
		else
		{
			switch (error.value())
			{
			case boost::asio::error::eof:
				break;
			default:
				_tprintf_s(_T("发送网络数据异常：%s\n"),
					tempA2T(error.message().c_str(), CP_ACP));
			}
			delete this;
		}
	}

private:
	BOOL fconnected_;
	INetworkSink *sink_;
	ssl_socket socket_;
	enum { max_cmd_size = 32, default_length = 1024 };
	message *message_read_;
	message *message_write_;
	void *user_info_;
	LPTSTR peer_name_;
	boost::asio::deadline_timer timer_;
	boost::asio::windows::random_access_handle file_;
	session_state state_;
	HANDLE sending_file_;
};


struct server_io_service
{
	server_io_service() 
		: acceptor_(io_service_, boost::asio::ip::tcp::v4())
	{
		acceptor_.set_option(
			boost::asio::socket_base::reuse_address(true));
	}

	boost::asio::io_service io_service_;
	boost::asio::ip::tcp::acceptor acceptor_;
};


class CBoostNetwork : public INetwork
{
public:
	CBoostNetwork()
		: io_thread_(NULL)
		, context_(boost::asio::ssl::context::sslv2_server)
	{
		context_.set_options(
			boost::asio::ssl::context::default_workarounds);
		context_.set_verify_mode(boost::asio::ssl::verify_peer
			| boost::asio::ssl::verify_fail_if_no_peer_cert);
		context_.set_verify_callback(
			boost::bind(&CBoostNetwork::verify_certificate,
				this, _1, _2));
	}

	virtual ~CBoostNetwork()
	{
	}

	virtual BOOL Initialize(LPCTSTR *szError, INetworkSink *pSink)
	{
		sink_ = pSink;
		io_.reset(new server_io_service);
		if (!io_.get())
			return FALSE;
		return TRUE;
	}

	virtual BOOL LoadCert(LPCTSTR szCertPath)
	{
		return load_pfx(context_, szCertPath, "test");
	}

	virtual BOOL Start(int nPort)
	{
		boost::system::error_code ec;
		io_->acceptor_.bind(boost::asio::ip::tcp::endpoint(
			boost::asio::ip::tcp::v4(), nPort), ec);
		if (ec)
		{
			_tprintf_s(_T("绑定端口[%n]出错：%s\n"), nPort,
				tempA2T(ec.message().c_str(), CP_ACP));
			return FALSE;
		}
		io_->acceptor_.listen(boost::asio::socket_base::max_connections, ec);
		if (ec)
		{
			_tprintf_s(_T("监听端口[%n]出错：%s\n"), nPort,
				tempA2T(ec.message().c_str(), CP_ACP));
			return FALSE;
		}

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

	virtual void Shutdown(DWORD dwWait)
	{
		io_.reset();
		if (io_thread_)
		{
			if (WaitForSingleObject(io_thread_, dwWait) == WAIT_TIMEOUT)
				TerminateThread(io_thread_, 0xdead);
			CloseHandle(io_thread_);
			io_thread_ = NULL;
		}
	}

	virtual void Destroy()
	{
		delete this;
	}

	void start_accept()
	{
		session* new_session = new session(io_->io_service_, context_, sink_);
		io_->acceptor_.async_accept(new_session->socket(),
			boost::bind(&CBoostNetwork::handle_accept, this, new_session,
			boost::asio::placeholders::error));
	}

	void handle_accept(session* new_session,
		const boost::system::error_code& error)
	{
		if (!error)
		{
			new_session->start();
			start_accept();
		}
		else
		{
			delete new_session;
		}
	}

	bool verify_certificate(bool preverified,
		boost::asio::ssl::verify_context& ctx)
	{
		char subject_name[256];
		X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
		X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
		std::cout << "Verifying " << subject_name << "\n";
		cert = X509_STORE_CTX_get0_current_issuer(ctx.native_handle());
		X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
		std::cout << "Target " << subject_name << "\n";
		std::cout << "Result: " << preverified << "\n";

		return preverified;
	}


protected:
	static DWORD __stdcall _ThreadProc(CBoostNetwork *pthis)
	{
		try
		{
			pthis->start_accept();
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
	boost::shared_ptr<server_io_service> io_;
	boost::asio::ssl::context context_;
	INetworkSink *sink_;
};


INetwork * CreateBoostNetworkInstance()
{
	return new CBoostNetwork;
}

