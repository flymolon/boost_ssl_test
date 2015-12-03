#pragma once
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/pkcs12.h>

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;


#pragma pack(push)
#pragma pack(1)
struct message
{
	size_t memory_length;
	union {
		size_t length;
		char msg[1];
	};
	char buffer[1];

	static bool reserve(message *&msg, size_t size)
	{
		if (!msg || msg->memory_length < size)
		{
			message *p = (message*)realloc(msg, size + sizeof(size_t) * 2);
			if (!p)
				return false;
			msg = p;
			msg->memory_length = size + sizeof(size_t)*2;
		}
		msg->length = size + sizeof(size_t);
		return true;
	}

	static bool formatv(message *&msg, const char *cmd, const char *fmt,
		va_list &ap)
	{
		size_t cmdlen;
		int bufferlen = 0;
		if (!cmd || (cmdlen = strlen(cmd)) == 0 || cmdlen > max_cmd_length)
			return false;

		bufferlen = _vscprintf(fmt, ap);
		if (!reserve(msg, bufferlen + cmdlen + 2))
			return false;

		strcpy_s(msg->buffer, cmdlen + 1, cmd);
		return (vsprintf_s(msg->buffer + cmdlen + 1, bufferlen + 1, fmt, ap)
			> 0);
	}

	static bool format(message *&msg, const char *cmd, const char *fmt, ...)
	{
		va_list ap;
		va_start(ap, fmt);
		return formatv(msg, cmd, fmt, ap);
	}

	enum { max_cmd_length = 32 };
};

#define msg_buffer(x) \
	boost::asio::buffer((char*)x->msg, x->length)
#define msg_buffer_offset(x, offset)\
	boost::asio::buffer((char*)x->msg+offset, x->length-offset)

#pragma pack(pop)



bool load_pfx(boost::asio::ssl::context &context, LPCTSTR file, LPCSTR key)
{
	PKCS12 *p12;
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *ca = NULL;
	FILE *fp;
	_tfopen_s(&fp, file, _T("rb"));

	if (!fp)
		return false;

	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);

	if (!p12)
		return false;

	if (!PKCS12_parse(p12, key, &pkey, &cert, &ca))
	{
		PKCS12_free(p12);
		return false;
	}

	fp = 0;
	PKCS12_free(p12);

	if (!pkey || !cert || !ca)
		goto pfx_cleanup;

	if (1 != ::SSL_CTX_use_PrivateKey(context.native_handle(), pkey))
		goto pfx_cleanup;

	if (1 != SSL_CTX_use_certificate(context.native_handle(), cert))
		goto pfx_cleanup;

	if (!ca || !sk_X509_num(ca))
		goto pfx_cleanup;

	X509_free(cert);
	cert = sk_X509_pop(ca);
	if (1 != X509_STORE_add_cert(
		SSL_CTX_get_cert_store(context.native_handle()), cert))
		goto pfx_cleanup;

	fp = (FILE*)1;
pfx_cleanup:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (cert)
		X509_free(cert);
	if (ca)
		sk_X509_pop_free(ca, X509_free);

	return (fp != 0) ? true : false;
}
