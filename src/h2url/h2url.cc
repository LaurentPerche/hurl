//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    h2url.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/08/2017
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "http_parser/http_parser.h"
#include "nghttp2/nghttp2.h"
#include "ndebug/ndebug.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

// openssl
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

// For errx
#include <err.h>

// For sleep
#include <unistd.h>

// socket support
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>

#include <string>

//: ----------------------------------------------------------------------------
//: Macros
//: ----------------------------------------------------------------------------
#ifndef _U_
#define _U_ __attribute__((unused))
#endif
#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))
//: ----------------------------------------------------------------------------
//: support routines
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details: Host info
//: ----------------------------------------------------------------------------
struct host_info {
        struct sockaddr_storage m_sa;
        int m_sa_len;
        int m_sock_family;
        int m_sock_type;
        int m_sock_protocol;
        host_info():
                m_sa(),
                m_sa_len(16),
                m_sock_family(AF_UNSPEC),
                m_sock_type(SOCK_STREAM),
                m_sock_protocol(IPPROTO_TCP)
        {((struct sockaddr_in *)(&m_sa))->sin_family = AF_INET;}
};
//: ----------------------------------------------------------------------------
//: \details: slow resolution
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int32_t nlookup(const std::string &a_host, uint16_t a_port, host_info &ao_host_info)
{
        // Initialize...
        ao_host_info.m_sa_len = sizeof(ao_host_info.m_sa);
        memset((void*) &(ao_host_info.m_sa), 0, ao_host_info.m_sa_len);

        // ---------------------------------------
        // get address...
        // ---------------------------------------
        struct addrinfo l_hints;
        memset(&l_hints, 0, sizeof(l_hints));
        l_hints.ai_family = PF_UNSPEC;
        l_hints.ai_socktype = SOCK_STREAM;
        char portstr[10];
        snprintf(portstr, sizeof(portstr), "%d", (int) a_port);
        struct addrinfo* l_addrinfo;

        int l_gaierr;
        l_gaierr = getaddrinfo(a_host.c_str(), portstr, &l_hints, &l_addrinfo);
        if (l_gaierr != 0)
        {
                //printf("Error getaddrinfo '%s': %s\n",
                //           a_host.c_str(), gai_strerror(l_gaierr));
                return -1;
        }

        // Find the first IPv4 and IPv6 entries.
        struct addrinfo* l_addrinfo_v4 = NULL;
        struct addrinfo* l_addrinfo_v6 = NULL;
        for (struct addrinfo* i_addrinfo = l_addrinfo;
             i_addrinfo != (struct addrinfo*) 0;
             i_addrinfo = i_addrinfo->ai_next)
        {
                switch (i_addrinfo->ai_family)
                {
                case AF_INET:
                {
                        if (l_addrinfo_v4 == (struct addrinfo*) 0)
                                l_addrinfo_v4 = i_addrinfo;
                        break;
                }
                case AF_INET6:
                {
                        if (l_addrinfo_v6 == (struct addrinfo*) 0)
                                l_addrinfo_v6 = i_addrinfo;
                        break;
                }
                }
        }
        //printf("RESOLVE:\n");
        // If there's an IPv4 address, use that, otherwise try IPv6.
        if (l_addrinfo_v4 != NULL)
        {
                if (sizeof(ao_host_info.m_sa) < l_addrinfo_v4->ai_addrlen)
                {
                        printf("Error %s - sockaddr too small (%lu < %lu)\n",
                                   a_host.c_str(),
                              (unsigned long) sizeof(ao_host_info.m_sa),
                              (unsigned long) l_addrinfo_v4->ai_addrlen);
                        return -1;
                }
                ao_host_info.m_sock_family = l_addrinfo_v4->ai_family;
                ao_host_info.m_sock_type = l_addrinfo_v4->ai_socktype;
                ao_host_info.m_sock_protocol = l_addrinfo_v4->ai_protocol;
                ao_host_info.m_sa_len = l_addrinfo_v4->ai_addrlen;
                //printf("memmove: addrlen: %d\n", l_addrinfo_v4->ai_addrlen);
                //ns_hlx::mem_display((const uint8_t *)l_addrinfo_v4->ai_addr,
                //                   l_addrinfo_v4->ai_addrlen);
                //show_host_info();
                memmove(&(ao_host_info.m_sa),
                        l_addrinfo_v4->ai_addr,
                        l_addrinfo_v4->ai_addrlen);
                // Set the port
                ((sockaddr_in *)(&(ao_host_info.m_sa)))->sin_port = htons(a_port);
                freeaddrinfo(l_addrinfo);
        }
        else if (l_addrinfo_v6 != NULL)
        {
                if (sizeof(ao_host_info.m_sa) < l_addrinfo_v6->ai_addrlen)
                {
                        printf("Error %s - sockaddr too small (%lu < %lu)\n",
                                   a_host.c_str(),
                              (unsigned long) sizeof(ao_host_info.m_sa),
                              (unsigned long) l_addrinfo_v6->ai_addrlen);
                        return -1;
                }
                ao_host_info.m_sock_family = l_addrinfo_v6->ai_family;
                ao_host_info.m_sock_type = l_addrinfo_v6->ai_socktype;
                ao_host_info.m_sock_protocol = l_addrinfo_v6->ai_protocol;
                ao_host_info.m_sa_len = l_addrinfo_v6->ai_addrlen;
                //printf("memmove: addrlen: %d\n", l_addrinfo_v6->ai_addrlen);
                //ns_hlx::mem_display((const uint8_t *)l_addrinfo_v6->ai_addr,
                //                    l_addrinfo_v6->ai_addrlen);
                //show_host_info();
                memmove(&ao_host_info.m_sa,
                        l_addrinfo_v6->ai_addr,
                        l_addrinfo_v6->ai_addrlen);
                // Set the port
                ((sockaddr_in6 *)(&(ao_host_info.m_sa)))->sin6_port = htons(a_port);
                freeaddrinfo(l_addrinfo);
        }
        else
        {
                printf("Error no valid address found for host %s\n",
                           a_host.c_str());
                return -1;
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void tls_init(void)
{
        // Initialize the OpenSSL library
        SSL_library_init();
        // Bring in and register error messages
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        // TODO Deprecated???
        //SSLeay_add_tls_algorithms();
        OpenSSL_add_all_algorithms();

        // We MUST have entropy, or else there's no point to crypto.
        if (!RAND_poll())
        {
                return;
        }
        // TODO Old method???
#if 0
        // Random seed
        if (! RAND_status())
        {
                unsigned char bytes[1024];
                for (size_t i = 0; i < sizeof(bytes); ++i)
                        bytes[i] = random() % 0xff;
                RAND_seed(bytes, sizeof(bytes));
        }
#endif
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t parse_url(const std::string &a_url, std::string &ao_host, uint16_t &ao_port, std::string &ao_path)
{
        std::string l_url_fixed = a_url;
        // Find scheme prefix "://"
        if(a_url.find("://", 0) == std::string::npos)
        {
                l_url_fixed = "http://" + a_url;
        }
        http_parser_url l_url;
        http_parser_url_init(&l_url);
        int l_status;
        l_status = http_parser_parse_url(l_url_fixed.c_str(), l_url_fixed.length(), 0, &l_url);
        if(l_status != 0)
        {
                printf("Error parsing url: %s\n", l_url_fixed.c_str());
                // TODO get error msg from http_parser
                return -1;
        }
        // Set no port
        bool l_is_ssl = true;
        ao_port = 0;
        for(uint32_t i_part = 0; i_part < UF_MAX; ++i_part)
        {
                if(l_url.field_data[i_part].len &&
                  // TODO Some bug with parser -parsing urls like "http://127.0.0.1" sans paths
                  ((l_url.field_data[i_part].len + l_url.field_data[i_part].off) <= l_url_fixed.length()))
                {
                        switch(i_part)
                        {
                        case UF_SCHEMA:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                //printf("l_part: %s\n", l_part.c_str());
                                if(l_part == "http")
                                {
                                        l_is_ssl = false;
                                }
                                else if(l_part == "https")
                                {
                                        l_is_ssl = true;
                                }
                                else
                                {
                                        printf("Error schema[%s] is unsupported\n", l_part.c_str());
                                        return -1;
                                }
                                break;
                        }
                        case UF_HOST:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                ao_host = l_part;
                                break;
                        }
                        case UF_PORT:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                ao_port = (uint16_t)strtoul(l_part.c_str(), NULL, 10);
                                break;
                        }
                        case UF_PATH:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                ao_path = l_part;
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
        }
        if(!ao_port)
        {
                if(l_is_ssl) ao_port = 443;
                else ao_port = 80;
        }
        if (l_status != 0)
        {
                printf("Error parsing url: %s.\n", l_url_fixed.c_str());
                return -1;
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details: Create tls ctx
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
SSL_CTX *tls_create_ctx(void)
{
        // No validation... for now...
        SSL_CTX *l_ctx;
        l_ctx = SSL_CTX_new(SSLv23_client_method());
        // leaks...
        if (l_ctx == NULL)
        {
                ERR_print_errors_fp(stderr);
                printf("SSL_CTX_new Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
                return NULL;
        }
        SSL_CTX_set_options(l_ctx,
                            SSL_OP_ALL |
                            SSL_OP_NO_SSLv2 |
                            SSL_OP_NO_SSLv3 |
                            SSL_OP_NO_COMPRESSION |
                            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

        SSL_CTX_set_mode(l_ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_mode(l_ctx, SSL_MODE_RELEASE_BUFFERS);

        return l_ctx;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int tcp_connect(const std::string &a_host, uint16_t a_port)
{
#if 1
        // Lookup host
        int32_t l_s;
        host_info l_hi;
        l_s = nlookup(a_host, a_port, l_hi);
        if(l_s != 0)
        {
                printf("Error performing nslookup host: %s port: %u\n",a_host.c_str(), a_port);
                return -1;
        }

        // tcp socket
        int l_fd;
        l_fd = ::socket(l_hi.m_sock_family,
                        l_hi.m_sock_type,
                        l_hi.m_sock_protocol);
        if (l_fd < 0)
        {
                printf("Error creating socket. Reason: %s\n", ::strerror(errno));
                return -1;
        }

        // connect
        l_s = ::connect(l_fd,
                        ((struct sockaddr*) &(l_hi.m_sa)),
                        (l_hi.m_sa_len));
        if (l_s < 0)
        {
                printf("Error performing connect. Reason: %s\n", ::strerror(errno));
                return -1;
        }
        return l_fd;
#else
        struct addrinfo hints;
        int fd = -1;
        int rv;
        char service[NI_MAXSERV];
        struct addrinfo *res, *rp;
        snprintf(service, sizeof(service), "%u", port);
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        rv = getaddrinfo(host, service, &hints, &res);
        if (rv != 0) {
          dief("getaddrinfo", gai_strerror(rv));
        }
        for (rp = res; rp; rp = rp->ai_next) {
          printf("loopin\n");
          fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
          if (fd == -1) {
            continue;
          }
          while ((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
                 errno == EINTR)
            ;
          if (rv == 0) {
            break;
          }
          close(fd);
          fd = -1;
        }
        freeaddrinfo(res);
        return fd;
#endif
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
SSL *tls_connect(SSL_CTX *a_tls_ctx, const std::string &a_host, uint16_t a_port)
{
        int32_t l_fd;
        l_fd = tcp_connect(a_host, a_port);
        if(l_fd == -1)
        {
                return NULL;
        }

        //printf("Connected\n");
        // Create TLS Context
        SSL *l_tls = NULL;
        l_tls = ::SSL_new(a_tls_ctx);
        // TODO Check for NULL

        ::SSL_set_fd(l_tls, l_fd);
        // TODO Check for Errors

        // ssl_connect
        int l_s;
        ERR_clear_error();
        l_s = SSL_connect(l_tls);
        if (l_s <= 0)
        {
                printf("Error performing SSL_connect.\n");
                // TODO Reason...
                if(l_tls) {SSL_free(l_tls); l_tls = NULL;}
                return NULL;
        }
        return l_tls;
}
//: ----------------------------------------------------------------------------
//: nghttp2 support routines
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details: NPN TLS extension client callback. We check that server advertised
//:           the HTTP/2 protocol the nghttp2 library supports. If not, exit
//:           the program.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int select_next_proto_cb(SSL *a_ssl _U_,
                                unsigned char **a_out,
                                unsigned char *a_outlen,
                                const unsigned char *a_in,
                                unsigned int a_inlen,
                                void *a_arg _U_)
{
        if (nghttp2_select_next_protocol(a_out, a_outlen, a_in, a_inlen) <= 0)
        {
                errx(1, "Server did not advertise " NGHTTP2_PROTO_VERSION_ID);
        }
        return SSL_TLSEXT_ERR_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void print_header(FILE *f,
                         const uint8_t *name,
                         size_t namelen,
                         const uint8_t *value,
                         size_t valuelen)
{
        fprintf(f, "%s", ANSI_COLOR_FG_BLUE);
        fwrite(name, namelen, 1, f);
        fprintf(f, "%s", ANSI_COLOR_OFF);
        fprintf(f, ": ");
        fprintf(f, "%s", ANSI_COLOR_FG_GREEN);
        fwrite(value, valuelen, 1, f);
        fprintf(f, "%s", ANSI_COLOR_OFF);
        fprintf(f, "\n");
}
//: ----------------------------------------------------------------------------
//: \details: Print HTTP headers to |f|. Please note that this function does not
//:           take into account that header name and value are sequence of
//:           octets, therefore they may contain non-printable characters.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen)
{
        size_t i;
        for (i = 0; i < nvlen; ++i)
        {
                print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
        }
        fprintf(f, "\n");
}
//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------
// ---------------------------------------------------------
// TODO
// ---------------------------------------------------------
typedef struct
{
        int32_t m_id;
        bool m_closed;
} ngxxx_stream;
// ---------------------------------------------------------
// TODO
// ---------------------------------------------------------
typedef struct
{
        SSL *m_tls;
        nghttp2_session *m_session;
        ngxxx_stream *m_stream;
} ngxxx_session;
//: ----------------------------------------------------------------------------
//: \details: nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
//:           to the network. Because we are using libevent bufferevent, we just
//:           write those bytes into bufferevent buffer
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static ssize_t ngxxx_send_cb(nghttp2_session *a_session _U_,
                             const uint8_t *a_data,
                             size_t a_length,
                             int a_flags _U_,
                             void *a_user_data)
{
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        UNUSED(l_session);
        //NDBG_PRINT("SEND_CB\n");
        //mem_display(a_data, a_length);
        int l_s;
        l_s = SSL_write(l_session->m_tls, a_data, a_length);
        //NDBG_PRINT("%sWRITE%s: l_s: %d\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF, l_s);
        if((l_s < 0) ||
           ((size_t)l_s < a_length))
        {
                NDBG_PRINT("Error performing SSL_write: l_s: %d\n", l_s);
                return -1;
        }
        return (ssize_t)l_s;
}
//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_frame_recv_callback: Called when nghttp2 library
//:           received a complete frame from the remote peer.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_frame_recv_cb(nghttp2_session *a_session,
                               const nghttp2_frame *a_frame,
                               void *a_user_data)
{
        //NDBG_PRINT("%sFRAME%s: TYPE[%6u]\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF, a_frame->hd.type);
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        switch (a_frame->hd.type)
        {
        case NGHTTP2_HEADERS:
        {
                if ((a_frame->headers.cat == NGHTTP2_HCAT_RESPONSE) &&
                    (l_session->m_stream->m_id == a_frame->hd.stream_id))
                {
                        //fprintf(stderr, "All headers received\n");
                }
                break;
        }
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
//:           received from the remote peer. In this implementation, if the frame
//:           is meant to the stream we initiated, print the received data in
//:           stdout, so that the user can redirect its output to the file
//:           easily.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_data_chunk_recv_cb(nghttp2_session *a_session _U_,
                                    uint8_t a_flags _U_,
                                    int32_t a_stream_id,
                                    const uint8_t *a_data,
                                    size_t a_len,
                                    void *a_user_data)
{
        //NDBG_PRINT("%sCHUNK%s: \n", ANSI_COLOR_BG_BLUE, ANSI_COLOR_OFF);
        ngxxx_session *l_session = (ngxxx_session *) a_user_data;
        if (l_session->m_stream->m_id == a_stream_id)
        {
                fwrite(a_data, a_len, 1, stdout);
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_stream_close_callback: Called when a stream is about to
//:           closed. This example program only deals with 1 HTTP request (1
//:           stream), if it is closed, we send GOAWAY and tear down the
//:           session
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_stream_close_cb(nghttp2_session *a_session,
                                 int32_t a_stream_id,
                                 uint32_t a_error_code,
                                 void *a_user_data)
{
        //NDBG_PRINT("%sCLOSE%s: \n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
        ngxxx_session *l_session = (ngxxx_session *) a_user_data;
        int l_rv;
        l_session->m_stream->m_closed = true;
        if (l_session->m_stream->m_id == a_stream_id)
        {
                //fprintf(stderr, "Stream %d closed with error_code=%d\n", a_stream_id, a_error_code);
                l_rv = nghttp2_session_terminate_session(a_session, NGHTTP2_NO_ERROR);
                if (l_rv != 0)
                {
                        return NGHTTP2_ERR_CALLBACK_FAILURE;
                }
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_header_callback: Called when nghttp2 library emits
//:           single header name/value pair
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_header_cb(nghttp2_session *a_session _U_,
                           const nghttp2_frame *a_frame,
                           const uint8_t *a_name,
                           size_t a_namelen,
                           const uint8_t *a_value,
                           size_t a_valuelen,
                           uint8_t a_flags _U_,
                           void *a_user_data)
{
        //NDBG_PRINT("%sHEADER%s: \n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF);
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        switch (a_frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if ((a_frame->headers.cat == NGHTTP2_HCAT_RESPONSE) &&
                    (l_session->m_stream->m_id == a_frame->hd.stream_id))
                {
                        // Print response headers for the initiated request.
                        print_header(stdout, a_name, a_namelen, a_value, a_valuelen);
                        break;
                }
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_begin_headers_callback:
//:           Called when nghttp2 library gets started to receive header block.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_begin_headers_cb(nghttp2_session *a_session _U_,
                                  const nghttp2_frame *a_frame,
                                  void *a_user_data)
{
        //NDBG_PRINT("%sBEGIN_HEADERS%s: \n", ANSI_COLOR_BG_WHITE, ANSI_COLOR_OFF);
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        switch (a_frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if ((a_frame->headers.cat == NGHTTP2_HCAT_RESPONSE) &&
                     (l_session->m_stream->m_id == a_frame->hd.stream_id))
                {
                        //fprintf(stderr, "Response headers for stream ID=%d:\n", a_frame->hd.stream_id);
                }
                break;
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void ngxxx_init_nghttp2_session(ngxxx_session *a_session)
{
        nghttp2_session_callbacks *l_cb;
        nghttp2_session_callbacks_new(&l_cb);
        nghttp2_session_callbacks_set_send_callback(l_cb, ngxxx_send_cb);
        nghttp2_session_callbacks_set_on_frame_recv_callback(l_cb, ngxxx_frame_recv_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(l_cb, ngxxx_data_chunk_recv_cb);
        nghttp2_session_callbacks_set_on_stream_close_callback(l_cb, ngxxx_stream_close_cb);
        nghttp2_session_callbacks_set_on_header_callback(l_cb, ngxxx_header_cb);
        nghttp2_session_callbacks_set_on_begin_headers_callback(l_cb, ngxxx_begin_headers_cb);
        nghttp2_session_client_new(&(a_session->m_session), l_cb, a_session);
        nghttp2_session_callbacks_del(l_cb);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void ngxxx_send_client_connection_header(ngxxx_session *a_session)
{
        nghttp2_settings_entry iv[1] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 } };
        int rv;

        /* client 24 bytes magic string will be sent by nghttp2 library */
        rv = nghttp2_submit_settings(a_session->m_session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
        if (rv != 0)
        {
                errx(1, "Could not submit SETTINGS: %s", nghttp2_strerror(rv));
        }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#define MAKE_NV(NAME, VALUE, VALUELEN) {\
                (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,\
                NGHTTP2_NV_FLAG_NONE\
        }

#define MAKE_NV2(NAME, VALUE) {\
                (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,\
                NGHTTP2_NV_FLAG_NONE\
          }

//: ----------------------------------------------------------------------------
//: \details: Send HTTP request to the remote peer
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void ngxxx_submit_request(ngxxx_session *a_session,
                                 const std::string &a_schema,
                                 const std::string &a_host,
                                 const std::string &a_path)
{
        int32_t l_id;
        ngxxx_stream *l_stream = a_session->m_stream;
        //printf("[INFO] path      = %s\n", a_path.c_str());
        //printf("[INFO] authority = %s\n", a_host.c_str());
        // -------------------------------------------------
        // authority note:
        // -------------------------------------------------
        // is the concatenation of host and port with ":" in
        // between.
        // -------------------------------------------------
        nghttp2_nv l_hdrs[] = {
                MAKE_NV2( ":method", "GET"),
                MAKE_NV(  ":path",   a_path.c_str(), a_path.length()),
                MAKE_NV2( ":scheme", "https"),
                MAKE_NV(  ":authority", a_host.c_str(), a_host.length()),
                MAKE_NV2( "accept", "*/*"),
                MAKE_NV2( "user-agent", "nghttp2/" NGHTTP2_VERSION)
        };
        //fprintf(stderr, "Request headers:\n");
        print_headers(stdout, l_hdrs, ARRLEN(l_hdrs));
        l_id = nghttp2_submit_request(a_session->m_session, NULL, l_hdrs, ARRLEN(l_hdrs), NULL, l_stream);
        if (l_id < 0)
        {
                errx(1, "Could not submit HTTP request: %s", nghttp2_strerror(l_id));
        }
        //printf("[INFO] Stream ID = %d\n", l_id);
        l_stream->m_id = l_id;
}
//: ----------------------------------------------------------------------------
//: \details: Print the version.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "nghttp2 client example.\n");
        fprintf(a_stream, "               Version: %s\n", "0.0.0");
        exit(a_exit_code);
}
//: ----------------------------------------------------------------------------
//: \details: Print the command line help.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: nghttp2_client_ex [http[s]://]hostname[:port]/path [options]\n");
        fprintf(a_stream, "Options are:\n");
        fprintf(a_stream, "  -h, --help           Display this help and exit.\n");
        fprintf(a_stream, "  -V, --version        Display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        exit(a_exit_code);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        // -------------------------------------------------
        // Get args...
        // -------------------------------------------------
        char l_opt;
        std::string l_argument;
        int l_option_index = 0;
        bool l_input_flag = false;
        struct option l_long_options[] =
                {
                { "help",           0, 0, 'h' },
                { "version",        0, 0, 'V' },
                // list sentinel
                { 0, 0, 0, 0 }
        };
        // -------------------------------------------------
        // Assume unspecified arg url...
        // TODO Unsure if good way to allow unspecified
        // arg...
        // -------------------------------------------------
        std::string l_url;
        bool is_opt = false;
        for(int i_arg = 1; i_arg < argc; ++i_arg) {
                if(argv[i_arg][0] == '-') {
                        is_opt = true;
                }
                else if(argv[i_arg][0] != '-' && is_opt == false) {
                        l_url = std::string(argv[i_arg]);
                        l_input_flag = true;
                        break;
                } else {
                        is_opt = false;
                }
        }
        // -------------------------------------------------
        // Args...
        // -------------------------------------------------
        char l_short_arg_list[] = "hV";
        while ((l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_options, &l_option_index)) != -1)
        {

                if (optarg)
                {
                        l_argument = std::string(optarg);
                }
                else
                {
                        l_argument.clear();
                }
                //printf("arg[%c=%d]: %s\n", l_opt, l_option_index, l_argument.c_str());
                switch (l_opt)
                {
                // -----------------------------------------
                // Help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // Version
                // -----------------------------------------
                case 'V':
                {
                        print_version(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // What???
                // -----------------------------------------
                case '?':
                {
                        // Required argument was missing
                        // '?' is provided when the 3rd arg to getopt_long does not begin with a ':', and is preceeded
                        // by an automatic error message.
                        printf("  Exiting.\n");
                        print_usage(stdout, -1);
                        break;
                }
                // -----------------------------------------
                // Huh???
                // -----------------------------------------
                default:
                {
                        printf("Unrecognized option.\n");
                        print_usage(stdout, -1);
                        break;
                }
                }
        }
        // -------------------------------------------------
        // verify input
        // -------------------------------------------------
        if(!l_input_flag)
        {
                printf("Error: url required.");
                print_usage(stdout, -1);
        }
        // -------------------------------------------------
        // init tls...
        // -------------------------------------------------
        tls_init();
        SSL_CTX *l_ctx = NULL;
        l_ctx = tls_create_ctx();
        if(!l_ctx)
        {
                printf("Error performing tls_create_ctx\n");
                return -1;
        }
        SSL_CTX_set_next_proto_select_cb(l_ctx, select_next_proto_cb, NULL);
        // -------------------------------------------------
        // Get host/path
        // -------------------------------------------------
        std::string l_host;
        std::string l_path;
        uint16_t l_port = 443;
        int32_t l_s;
        l_s = parse_url(l_url, l_host, l_port, l_path);
        if(l_s != 0)
        {
                printf("Error performing parse_url.\n");
        }
        // set path to / if empty
        if(l_path.empty())
        {
                l_path = "/";
        }
        // -------------------------------------------------
        // connect
        // -------------------------------------------------
        SSL *l_tls = NULL;
        l_tls = tls_connect(l_ctx, l_host, l_port);
        if(!l_tls)
        {
                printf("Error performing ssl_connect\n");
                return -1;
        }
        // -------------------------------------------------
        // create session/stream
        // -------------------------------------------------
        ngxxx_session *l_session = NULL;
        l_session = (ngxxx_session *)calloc(1, sizeof(ngxxx_session));
        l_session->m_stream = (ngxxx_stream *)calloc(1, sizeof(ngxxx_stream));
        l_session->m_stream->m_id = -1;
        l_session->m_stream->m_closed = false;
        l_session->m_tls = l_tls;
        // -------------------------------------------------
        // init session...
        // -------------------------------------------------
        ngxxx_init_nghttp2_session(l_session);
        // -------------------------------------------------
        // send connection header
        // -------------------------------------------------
        ngxxx_send_client_connection_header(l_session);
        // -------------------------------------------------
        // send request
        // -------------------------------------------------
        ngxxx_submit_request(l_session, "https", l_host, l_path);
        // -------------------------------------------------
        // read response
        // -------------------------------------------------
        while(!l_session->m_stream->m_closed)
        {
                // -----------------------------------------
                // session send???
                // -----------------------------------------
                l_s = nghttp2_session_send(l_session->m_session);
                if (l_s != 0)
                {
                        warnx("Fatal error: %s", nghttp2_strerror(l_s));
                        // TODO
                        //delete_http2_session_data(session_data);
                        return -1;
                }
                //NDBG_PRINT("nghttp2_session_send: %d\n", l_s);
                // -----------------------------------------
                // read response...
                // -----------------------------------------
                char l_buf[16384];
                l_s = SSL_read(l_tls, l_buf, 16384);
                //NDBG_PRINT("%sREAD%s: l_s: %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_s);
                //if(l_s > 0) mem_display((uint8_t *)l_buf, l_s);
                ssize_t l_rl;
                l_rl = nghttp2_session_mem_recv(l_session->m_session, (const uint8_t *)l_buf, l_s);
                if(l_rl < 0)
                {
                        warnx("Fatal error: %s", nghttp2_strerror((int) l_rl));
                        // TODO
                        //delete_http2_session_data(session_data);
                        return -1;
                }
        }
        // -------------------------------------------------
        // Cleanup...
        // -------------------------------------------------
        SSL_shutdown(l_tls);
        SSL_CTX_free(l_ctx);
        //printf("Cleaning up...\n");
        return 0;
}
