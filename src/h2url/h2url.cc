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

#include "hurl/status.h"
#include "hurl/nconn/scheme.h"
#include "hurl/nconn/host_info.h"
#include "hurl/support/kv_map_list.h"
#include "hurl/support/string_util.h"

// internal
#include "support/ndebug.h"
#include "support/file_util.h"

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
//: request object/meta
//: ----------------------------------------------------------------------------
class request {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        request():
                m_scheme(ns_hurl::SCHEME_TCP),
                m_host(),
                m_url(),
                m_url_path(),
                m_url_query(),
                m_verb("GET"),
                m_headers(),
                m_body_data(NULL),
                m_body_data_len(0),
                m_port(0),
                m_expect_resp_body_flag(true),
                m_host_info()
        {};
        int set_header(const std::string &a_key, const std::string &a_val);
        int32_t init_with_url(const std::string &a_url);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        ns_hurl::scheme_t m_scheme;
        std::string m_host;
        std::string m_url;
        std::string m_url_path;
        std::string m_url_query;
        std::string m_verb;
        ns_hurl::kv_map_list_t m_headers;
        char *m_body_data;
        uint32_t m_body_data_len;
        uint16_t m_port;
        bool m_expect_resp_body_flag;
        ns_hurl::host_info m_host_info;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // Disallow copy/assign
        request(const request &);
        request& operator=(const request &);
};
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int request::set_header(const std::string &a_key, const std::string &a_val)
{
        ns_hurl::kv_map_list_t::iterator i_obj = m_headers.find(a_key);
        if(i_obj != m_headers.end())
        {
                // Special handling for Host/User-agent/referer
                bool l_replace = false;
                bool l_remove = false;
                if(!strcasecmp(a_key.c_str(), "User-Agent") ||
                   !strcasecmp(a_key.c_str(), "Referer") ||
                   !strcasecmp(a_key.c_str(), "Accept") ||
                   !strcasecmp(a_key.c_str(), "Host"))
                {
                        l_replace = true;
                        if(a_val.empty())
                        {
                                l_remove = true;
                        }
                }
                if(l_replace)
                {
                        i_obj->second.pop_front();
                        if(!l_remove)
                        {
                                i_obj->second.push_back(a_val);
                        }
                }
                else
                {
                        i_obj->second.push_back(a_val);
                }
        }
        else
        {
                ns_hurl::str_list_t l_list;
                l_list.push_back(a_val);
                m_headers[a_key] = l_list;
        }
        return HURL_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t request::init_with_url(const std::string &a_url)
{
        std::string l_url_fixed = a_url;
        // Find scheme prefix "://"
        if(a_url.find("://", 0) == std::string::npos)
        {
                l_url_fixed = "http://" + a_url;
        }
        //NDBG_PRINT("Parse url:           %s\n", a_url.c_str());
        //NDBG_PRINT("Parse a_wildcarding: %d\n", a_wildcarding);
        http_parser_url l_url;
        http_parser_url_init(&l_url);
        // silence bleating memory sanitizers...
        //memset(&l_url, 0, sizeof(l_url));
        int l_status;
        l_status = http_parser_parse_url(l_url_fixed.c_str(), l_url_fixed.length(), 0, &l_url);
        if(l_status != 0)
        {
                NDBG_PRINT("Error parsing url: %s\n", l_url_fixed.c_str());
                // TODO get error msg from http_parser
                return HURL_STATUS_ERROR;
        }
        // Set no port
        m_port = 0;
        for(uint32_t i_part = 0; i_part < UF_MAX; ++i_part)
        {
                //NDBG_PRINT("i_part: %d offset: %d len: %d\n", i_part, l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                //NDBG_PRINT("len+off: %d\n",       l_url.field_data[i_part].len + l_url.field_data[i_part].off);
                //NDBG_PRINT("a_url.length(): %d\n", (int)a_url.length());
                if(l_url.field_data[i_part].len &&
                  // TODO Some bug with parser -parsing urls like "http://127.0.0.1" sans paths
                  ((l_url.field_data[i_part].len + l_url.field_data[i_part].off) <= l_url_fixed.length()))
                {
                        switch(i_part)
                        {
                        case UF_SCHEMA:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                //NDBG_PRINT("l_part: %s\n", l_part.c_str());
                                if(l_part == "http")
                                {
                                        m_scheme = ns_hurl::SCHEME_TCP;
                                }
                                else if(l_part == "https")
                                {
                                        m_scheme = ns_hurl::SCHEME_TLS;
                                }
                                else
                                {
                                        NDBG_PRINT("Error schema[%s] is unsupported\n", l_part.c_str());
                                        return HURL_STATUS_ERROR;
                                }
                                break;
                        }
                        case UF_HOST:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                //NDBG_PRINT("l_part[UF_HOST]: %s\n", l_part.c_str());
                                m_host = l_part;
                                break;
                        }
                        case UF_PORT:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                //NDBG_PRINT("l_part[UF_PORT]: %s\n", l_part.c_str());
                                m_port = (uint16_t)strtoul(l_part.c_str(), NULL, 10);
                                break;
                        }
                        case UF_PATH:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                //NDBG_PRINT("l_part[UF_PATH]: %s\n", l_part.c_str());
                                m_url_path = l_part;
                                break;
                        }
                        case UF_QUERY:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                //NDBG_PRINT("l_part[UF_QUERY]: %s\n", l_part.c_str());
                                m_url_query = l_part;
                                break;
                        }
                        case UF_FRAGMENT:
                        {
                                //std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                //NDBG_PRINT("l_part[UF_FRAGMENT]: %s\n", l_part.c_str());
                                //m_fragment = l_part;
                                break;
                        }
                        case UF_USERINFO:
                        {
                                //std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                //sNDBG_PRINT("l_part[UF_USERINFO]: %s\n", l_part.c_str());
                                //m_userinfo = l_part;
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
        }
        // Default ports
        if(!m_port)
        {
                switch(m_scheme)
                {
                case ns_hurl::SCHEME_TCP:
                {
                        m_port = 80;
                        break;
                }
                case ns_hurl::SCHEME_TLS:
                {
                        m_port = 443;
                        break;
                }
                default:
                {
                        m_port = 80;
                        break;
                }
                }
        }
        //m_num_to_req = m_path_vector.size();
        //NDBG_PRINT("Showing parsed url.\n");
        //m_url.show();
        if (HURL_STATUS_OK != l_status)
        {
                // Failure
                NDBG_PRINT("Error parsing url: %s.\n", l_url_fixed.c_str());
                return HURL_STATUS_ERROR;
        }
        //NDBG_PRINT("Parsed url: %s\n", l_url_fixed.c_str());
        return HURL_STATUS_OK;
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
        if(!RAND_poll())
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
                if((l_url.field_data[i_part].len == 0) ||

                  // TODO Some bug with parser -parsing urls like "http://127.0.0.1" sans paths
                  ((l_url.field_data[i_part].len + l_url.field_data[i_part].off) > l_url_fixed.length()))
                {
                        continue;
                }
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
                        fprintf(stdout, "%s%.*s%s: %s%.*s%s\n",
                                ANSI_COLOR_FG_BLUE, (int)a_namelen, a_name, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_GREEN, (int)a_valuelen, a_value, ANSI_COLOR_OFF);
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
//: \details: Print the version.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "h2url: http2 curl utility\n");
        fprintf(a_stream, "Copyright (C) 2017 Verizon Digital Media.\n");
        fprintf(a_stream, "               Version: %s\n", HURL_VERSION);
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
        fprintf(a_stream, "Settings:\n");
      //fprintf(a_stream, "  -d, --data           HTTP body data -supports curl style @ file specifier\n");
        fprintf(a_stream, "  -H, --header         Request headers -can add multiple ie -H<> -H<>...\n");
        fprintf(a_stream, "  -X, --verb           Request command -HTTP verb to use -GET/PUT/etc. Default GET\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "TLS Settings:\n");
        fprintf(a_stream, "  -y, --cipher         Cipher --see \"openssl ciphers\" for list.\n");
        fprintf(a_stream, "  -O, --tls_options    SSL Options string.\n");
        fprintf(a_stream, "  -K, --tls_verify     Verify server certificate.\n");
        fprintf(a_stream, "  -N, --tls_sni        Use SSL SNI.\n");
        fprintf(a_stream, "  -B, --tls_self_ok    Allow self-signed certificates.\n");
        fprintf(a_stream, "  -M, --tls_no_host    Skip host name checking.\n");
        fprintf(a_stream, "  -F, --tls_ca_file    SSL CA File.\n");
        fprintf(a_stream, "  -L, --tls_ca_path    SSL CA Path.\n");
        fprintf(a_stream, "Print Options:\n");
      //fprintf(a_stream, "  -v, --verbose        Verbose logging\n");
        fprintf(a_stream, "  -c, --no_color       Turn off colors\n");
        fprintf(a_stream, "  \n");
      //fprintf(a_stream, "Debug Options:\n");
      //fprintf(a_stream, "  -r, --trace          Turn on tracing (error/warn/debug/verbose/all)\n");
      //fprintf(a_stream, "  \n");
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
        // Subrequest settings
        // -------------------------------------------------
        request *l_request = new request();
        // -------------------------------------------------
        // Get args...
        // -------------------------------------------------
        char l_opt;
        std::string l_arg;
        int l_option_index = 0;
        bool l_input_flag = false;
        struct option l_long_options[] =
                {
                { "help",           0, 0, 'h' },
                { "version",        0, 0, 'V' },
                { "data",           1, 0, 'd' },
                { "header",         1, 0, 'H' },
                { "verb",           1, 0, 'X' },
                { "cipher",         1, 0, 'y' },
                { "tls_options",    1, 0, 'O' },
                { "tls_verify",     0, 0, 'K' },
                { "tls_sni",        0, 0, 'N' },
                { "tls_self_ok",    0, 0, 'B' },
                { "tls_no_host",    0, 0, 'M' },
                { "tls_ca_file",    1, 0, 'F' },
                { "tls_ca_path",    1, 0, 'L' },
                { "verbose",        0, 0, 'v' },
                { "no_color",       0, 0, 'c' },
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
        char l_short_arg_list[] = "hVd:H:X:y:O:KNBMF:L:vc";
        while ((l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_options, &l_option_index)) != -1)
        {

                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                //printf("arg[%c=%d]: %s\n", l_opt, l_option_index, l_arg.c_str());
                switch (l_opt)
                {
                // -----------------------------------------
                // help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // version
                // -----------------------------------------
                case 'V':
                {
                        print_version(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // data
                // -----------------------------------------
                case 'd':
                {
                        // TODO Size limits???
                        int32_t l_s;
                        // If a_data starts with @ assume file
                        if(l_arg[0] == '@')
                        {
                                char *l_buf;
                                uint32_t l_len;
                                l_s = ns_hurl::read_file(l_arg.data() + 1, &(l_buf), &(l_len));
                                if(l_s != 0)
                                {
                                        printf("Error reading body data from file: %s\n", l_arg.c_str() + 1);
                                        return HURL_STATUS_ERROR;
                                }
                                l_request->m_body_data = l_buf;
                                l_request->m_body_data_len = l_len;
                        }
                        else
                        {
                                char *l_buf;
                                uint32_t l_len;
                                l_len = l_arg.length() + 1;
                                l_buf = (char *)malloc(sizeof(char)*l_len);
                                l_request->m_body_data = l_buf;
                                l_request->m_body_data_len = l_len;
                        }

                        // Add content length
                        char l_len_str[64];
                        sprintf(l_len_str, "%u", l_request->m_body_data_len);
                        l_request->set_header("Content-Length", l_len_str);
                        break;
                }
                // -----------------------------------------
                // header
                // -----------------------------------------
                case 'H':
                {
                        int32_t l_s;
                        std::string l_key;
                        std::string l_val;
                        l_s = ns_hurl::break_header_string(l_arg, l_key, l_val);
                        if (l_s != 0)
                        {
                                printf("Error breaking header string: %s -not in <HEADER>:<VAL> format?\n", l_arg.c_str());
                                return HURL_STATUS_ERROR;
                        }
                        l_s = l_request->set_header(l_key, l_val);
                        if (l_s != 0)
                        {
                                printf("Error performing set_header: %s\n", l_arg.c_str());
                                return HURL_STATUS_ERROR;
                        }
                        break;
                }
                // -----------------------------------------
                // verb
                // -----------------------------------------
                case 'X':
                {
                        if(l_arg.length() > 64)
                        {
                                printf("Error verb string: %s too large try < 64 chars\n", l_arg.c_str());
                                return HURL_STATUS_ERROR;
                        }
                        l_request->m_verb = l_arg;
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
        nghttp2_session_callbacks *l_cb;
        nghttp2_session_callbacks_new(&l_cb);
        nghttp2_session_callbacks_set_send_callback(l_cb, ngxxx_send_cb);
        nghttp2_session_callbacks_set_on_frame_recv_callback(l_cb, ngxxx_frame_recv_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(l_cb, ngxxx_data_chunk_recv_cb);
        nghttp2_session_callbacks_set_on_stream_close_callback(l_cb, ngxxx_stream_close_cb);
        nghttp2_session_callbacks_set_on_header_callback(l_cb, ngxxx_header_cb);
        nghttp2_session_callbacks_set_on_begin_headers_callback(l_cb, ngxxx_begin_headers_cb);
        nghttp2_session_client_new(&(l_session->m_session), l_cb, l_session);
        nghttp2_session_callbacks_del(l_cb);
        // -------------------------------------------------
        // send connection header
        // -------------------------------------------------
        nghttp2_settings_entry l_iv[1] = {
                { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
        };
        int l_rv;
        /* client 24 bytes magic string will be sent by nghttp2 library */
        l_rv = nghttp2_submit_settings(l_session->m_session, NGHTTP2_FLAG_NONE, l_iv, ARRLEN(l_iv));
        if(l_rv != 0)
        {
                errx(1, "Could not submit SETTINGS: %s", nghttp2_strerror(l_rv));
        }
        // -------------------------------------------------
        // send request
        // -------------------------------------------------
        int32_t l_id;
        ngxxx_stream *l_stream = l_session->m_stream;
        //printf("[INFO] path      = %s\n", a_path.c_str());
        //printf("[INFO] authority = %s\n", a_host.c_str());
        // -------------------------------------------------
        // authority note:
        // -------------------------------------------------
        // is the concatenation of host and port with ":" in
        // between.
        // -------------------------------------------------
#define MAKE_NV(NAME, VALUE, VALUELEN) {(uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN, NGHTTP2_NV_FLAG_NONE}
#define MAKE_NV2(NAME, VALUE)          {(uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE}

        nghttp2_nv l_hdrs[] = {
                MAKE_NV2( ":method", "GET"),
                MAKE_NV(  ":path",   l_path.c_str(), l_path.length()),
                MAKE_NV2( ":scheme", "https"),
                MAKE_NV(  ":authority", l_host.c_str(), l_host.length()),
                MAKE_NV2( "accept", "*/*"),
                MAKE_NV2( "user-agent", "nghttp2/" NGHTTP2_VERSION)
        };
        // print headers
        for(size_t i_h = 0; i_h < ARRLEN(l_hdrs); ++i_h)
        {
                fprintf(stdout, "%s%.*s%s: %s%.*s%s\n",
                        ANSI_COLOR_FG_BLUE, (int)l_hdrs[i_h].namelen, l_hdrs[i_h].name, ANSI_COLOR_OFF,
                        ANSI_COLOR_FG_GREEN, (int)l_hdrs[i_h].valuelen, l_hdrs[i_h].value, ANSI_COLOR_OFF);
        }
        fprintf(stdout, "\n");
        //fprintf(stderr, "Request headers:\n");
        l_id = nghttp2_submit_request(l_session->m_session, NULL, l_hdrs, ARRLEN(l_hdrs), NULL, l_stream);
        if (l_id < 0)
        {
                errx(1, "Could not submit HTTP request: %s", nghttp2_strerror(l_id));
        }
        //printf("[INFO] Stream ID = %d\n", l_id);
        l_stream->m_id = l_id;
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
        if(l_request) {delete l_request; l_request = NULL;}
        SSL_shutdown(l_tls);
        SSL_CTX_free(l_ctx);
        //printf("Cleaning up...\n");
        return 0;
}
