//: ----------------------------------------------------------------------------
//: Copyright (C) 2014 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    t_hlx.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    10/05/2015
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
#include "ndebug.h"
#include "nbq.h"
#include "nconn_tcp.h"
#include "nconn_tls.h"
#include "time_util.h"
#include "stat_util.h"
#include "url_router.h"
#include "resolver.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "t_hlx.h"

namespace ns_hlx {

//: ----------------------------------------------------------------------------
//: Macros
//: ----------------------------------------------------------------------------
#define T_HTTP_PROXY_SET_NCONN_OPT(_conn, _opt, _buf, _len) \
        do { \
                int _status = 0; \
                _status = _conn.set_opt((_opt), (_buf), (_len)); \
                if (_status != nconn::NC_STATUS_OK) { \
                        NDBG_PRINT("STATUS_ERROR: Failed to set_opt %d.  Status: %d.\n", _opt, _status); \
                        return STATUS_ERROR;\
                } \
        } while(0)

#define CHECK_FOR_NULL_ERROR_DEBUG(_data) \
        do {\
                if(!_data) {\
                        NDBG_PRINT("Error.\n");\
                        return STATUS_ERROR;\
                }\
        } while(0);

#define CHECK_FOR_NULL_ERROR(_data) \
        do {\
                if(!_data) {\
                        return STATUS_ERROR;\
                }\
        } while(0);

//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------
typedef obj_pool <nbq> nbq_pool_t;

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
template <typename T> bool get_from_pool_if_null(T* &ao_obj, obj_pool<T> &a_pool)
{
        bool l_new = false;
        if(!ao_obj)
        {
                // TODO Make function
                ao_obj = a_pool.get_free();
                if(!ao_obj)
                {
                        ao_obj = new T();
                        a_pool.add(ao_obj);
                        l_new = true;
                }
        }
        return l_new;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
template <>
bool get_from_pool_if_null<nbq>(nbq* &ao_obj, obj_pool<nbq> &a_pool)
{
        bool l_new = false;
        if(!ao_obj)
        {
                // TODO Make function
                ao_obj = a_pool.get_free();
                if(!ao_obj)
                {
                        ao_obj = new nbq(16384);
                        a_pool.add(ao_obj);
                        l_new = true;
                }
        }
        return l_new;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
t_hlx::t_hlx(const t_conf *a_t_conf):
        m_t_run_thread(),
        m_t_conf(a_t_conf),
        m_nconn_pool(-1),
        m_nconn_proxy_pool(a_t_conf->m_num_parallel),
        m_stopped(false),
        m_start_time_s(0),
        m_evr_loop(NULL),
        m_scheme(SCHEME_TCP),
        m_listening_nconn_list(),
        m_subr_queue(),
        m_default_rqst_h(),
        m_hconn_pool(),
        m_resp_pool(),
        m_rqst_pool(),
        m_nbq_pool(),
        m_stat(),
        m_subr_q_fd(-1),
        m_subr_q_nconn(NULL),
        m_is_initd(false)
{
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
t_hlx::~t_hlx()
{
        if(m_subr_q_nconn)
        {
                delete m_subr_q_nconn;
                m_subr_q_nconn = NULL;
        }
        if(m_evr_loop)
        {
                delete m_evr_loop;
        }
        for(listening_nconn_list_t::iterator i_conn = m_listening_nconn_list.begin();
                        i_conn != m_listening_nconn_list.end();
                        ++i_conn)
        {
                if(*i_conn)
                {
                        delete *i_conn;
                        *i_conn = NULL;
                }
        }
        while(!m_subr_queue.empty())
        {
                subr *l_subr = m_subr_queue.front();
                if(l_subr)
                {
                        delete l_subr;
                }
                m_subr_queue.pop();
        }
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::init(void)
{
        if(m_is_initd)
        {
                return STATUS_OK;
        }

        // Create loop
        m_evr_loop = new evr_loop(evr_loop_file_readable_cb,
                                  evr_loop_file_writeable_cb,
                                  evr_loop_file_error_cb,
                                  m_t_conf->m_evr_loop_type,
                                  // TODO Need to make epoll vector resizeable...
                                  512,
                                  false);

        // ---------------------------------------
        // Subrequest support
        // Fake nconn -for subreq notifications
        // ---------------------------------------
        m_subr_q_nconn = m_nconn_pool.create_conn(SCHEME_TCP);
        m_subr_q_nconn->set_idx(sc_subr_q_conn_idx);
        m_subr_q_fd = m_evr_loop->add_event(m_subr_q_nconn);
        if(m_subr_q_fd == STATUS_ERROR)
        {
                NDBG_PRINT("Error performing m_evr_loop->add_event\n");
                return STATUS_ERROR;
        }

        m_is_initd = true;
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::add_lsnr(lsnr &a_lsnr)
{
        int32_t l_status;
        l_status = init();
        if(l_status != STATUS_OK)
        {
                NDBG_PRINT("Error performing init.\n");
                return STATUS_ERROR;
        }
        nconn *l_nconn = NULL;
        l_nconn = m_nconn_pool.create_conn(a_lsnr.get_scheme());
        l_status = config_conn(*l_nconn, a_lsnr.get_url_router(), DATA_TYPE_SERVER, false, false);
        if(l_status != STATUS_OK)
        {
                if(l_nconn)
                {
                        delete l_nconn;
                        l_nconn = NULL;
                }
                NDBG_PRINT("Error: performing config_conn\n");
                return STATUS_ERROR;
        }
        hconn *l_hconn = get_hconn(a_lsnr.get_url_router(), DATA_TYPE_SERVER, false);
        if(!l_hconn)
        {
                if(l_nconn)
                {
                        delete l_nconn;
                        l_nconn = NULL;
                }
                NDBG_PRINT("Error: performing config_conn\n");
                return STATUS_ERROR;
        }
        l_nconn->set_data(l_hconn);
        l_hconn->m_nconn = l_nconn;
        l_status = l_nconn->nc_set_listening(m_evr_loop, a_lsnr.get_fd());
        if(l_status != STATUS_OK)
        {
                if(l_nconn)
                {
                        delete l_nconn;
                        l_nconn = NULL;
                }
                NDBG_PRINT("Error performing nc_set_listening.\n");
                return STATUS_ERROR;
        }
        m_listening_nconn_list.push_back(l_nconn);
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::add_subr(subr &a_subr)
{
        //NDBG_PRINT("Adding subreq.\n");
        m_subr_queue.push(&a_subr);
        if(m_evr_loop)
        {
                m_evr_loop->signal_control();
        }
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::queue_api_resp(api_resp &a_api_resp, hconn &a_hconn)
{
        if(!get_from_pool_if_null(a_hconn.m_out_q, m_nbq_pool))
        {
                a_hconn.m_out_q->reset_write();
        }
        a_api_resp.serialize(*a_hconn.m_out_q);
        evr_loop_file_writeable_cb(a_hconn.m_nconn);
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::queue_output(hconn &a_hconn)
{
        evr_loop_file_writeable_cb(a_hconn.m_nconn);
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
nconn *t_hlx::get_proxy_conn(const host_info_t &a_host_info,
                             const std::string &a_label,
                             scheme_t a_scheme,
                             bool a_save,
                             bool a_connect_only)
{
        int32_t l_status;
        nconn *l_nconn = NULL;
        //NDBG_PRINT("a_subr.m_keepalive: %d\n", a_subr.m_keepalive);
        //NDBG_PRINT("m_idle size: %u\n", (int)m_nconn_proxy_pool.num_idle());
        l_nconn = m_nconn_proxy_pool.get_idle(a_label);
        if(!l_nconn)
        {
                // Try get a connection
                l_nconn = m_nconn_proxy_pool.get(a_scheme);
                if(!l_nconn)
                {
                        return NULL;
                }
                // Configure connection
                l_status = config_conn(*l_nconn,
                                       NULL,
                                       DATA_TYPE_CLIENT,
                                       a_save,
                                       a_connect_only);
                if(l_status != STATUS_OK)
                {
                        m_nconn_proxy_pool.release(l_nconn);
                        NDBG_PRINT("Error performing config_conn\n");
                        return NULL;
                }
                // -----------------------------------------
                // TODO Make configurable...
                // m_num_reqs_per_proxy_conn
                // -----------------------------------------
                l_nconn->set_num_reqs_per_conn(-1);
                l_nconn->set_host_info(a_host_info);
        }
        return l_nconn;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::start_subr(subr &a_subr, hconn &a_hconn, nconn &a_nconn)
{
        int32_t l_status;
        //NDBG_PRINT("TID[%lu]: %sSTART%s: Host: %s l_nconn: %p\n",
        //                pthread_self(),
        //                ANSI_COLOR_BG_BLUE, ANSI_COLOR_OFF,
        //                a_subr.get_label().c_str(),
        //                &a_nconn);
        resp *l_resp = static_cast<resp *>(a_hconn.m_hmsg);
        if(a_subr.get_detach_resp())
        {
                if(!l_resp)
                {
                        l_resp = new resp();
                }
                else
                {
                        l_resp->clear();
                }
        }
        else
        {
                if(!get_from_pool_if_null(l_resp, m_resp_pool))
                {
                        l_resp->clear();
                }
        }
        a_hconn.m_hmsg = l_resp;

        // Create request
        if(!a_subr.get_connect_only())
        {
                if(!get_from_pool_if_null(a_hconn.m_in_q, m_nbq_pool))
                {
                        a_hconn.m_in_q->reset_write();
                }

                a_hconn.m_hmsg->set_q(a_hconn.m_in_q);

                if(!a_hconn.m_out_q)
                {
                        if(!get_from_pool_if_null(a_hconn.m_out_q, m_nbq_pool))
                        {
                                a_hconn.m_out_q->reset_write();
                        }
                        subr::create_req_cb_t l_create_req_cb = a_subr.get_create_req_cb();
                        if(l_create_req_cb)
                        {
                                l_status = l_create_req_cb(*(m_t_conf->m_hlx), a_subr, *a_hconn.m_out_q);
                                if(STATUS_OK != l_status)
                                {
                                        return STATUS_ERROR;
                                }
                        }
                }
                else
                {
                        if(a_subr.get_is_multipath())
                        {
                                // Reset in data
                                a_hconn.m_out_q->reset_write();
                                subr::create_req_cb_t l_create_req_cb = a_subr.get_create_req_cb();
                                if(l_create_req_cb)
                                {
                                        l_status = l_create_req_cb(*(m_t_conf->m_hlx), a_subr, *a_hconn.m_out_q);
                                        if(STATUS_OK != l_status)
                                        {
                                                return STATUS_ERROR;
                                        }
                                }
                        }
                        else
                        {
                                a_hconn.m_out_q->reset_read();
                        }
                }

                // Display data from out q
                if(m_t_conf->m_verbose)
                {
                        if(m_t_conf->m_color) NDBG_OUTPUT("%s", ANSI_COLOR_FG_YELLOW);
                        a_hconn.m_out_q->print();
                        if(m_t_conf->m_color) NDBG_OUTPUT("%s", ANSI_COLOR_OFF);
                }
        }

        // Set subreq
        //l_hconn->m_rqst.m_subr = &a_subr;

        l_status = m_evr_loop->add_timer(a_subr.get_timeout_s()*1000, evr_loop_file_timeout_cb, &a_nconn, &(a_hconn.m_timer_obj));
        if(l_status != STATUS_OK)
        {
                //NDBG_PRINT("Error: Performing add_timer\n");
                return STATUS_ERROR;
        }

        //NDBG_PRINT("g_client_req_num: %d\n", ++g_client_req_num);
        //NDBG_PRINT("%sCONNECT%s: %s --data: %p\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF, a_subr.m_host.c_str(), a_nconn.get_data());
        ++m_stat.m_num_conn_started;
        l_status = a_nconn.nc_run_state_machine(m_evr_loop, nconn::NC_MODE_WRITE, a_hconn.m_in_q, a_hconn.m_out_q);
        a_nconn.bump_num_requested();
        if(l_status == nconn::NC_STATUS_ERROR)
        {
                //NDBG_PRINT("Error: Performing nc_run_state_machine. l_status: %d\n", l_status);
                cleanup_hconn(a_hconn);
                return STATUS_OK;
        }
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
nconn *t_hlx::get_new_client_conn(int a_fd, scheme_t a_scheme, url_router *a_url_router)
{
        nconn *l_nconn;
        l_nconn = m_nconn_pool.get(a_scheme);
        if(!l_nconn)
        {
                NDBG_PRINT("Error: performing m_nconn_pool.get\n");
                return NULL;
        }
        //NDBG_PRINT("%sGET_NEW%s: %u a_nconn: %p\n", ANSI_COLOR_BG_BLUE, ANSI_COLOR_OFF, (uint32_t)l_nconn->get_idx(), l_nconn);
        // Config
        int32_t l_status;
        l_status = config_conn(*l_nconn, a_url_router, DATA_TYPE_SERVER, true, false);
        if(l_status != STATUS_OK)
        {
                NDBG_PRINT("Error: performing config_conn\n");
                return NULL;
        }
        hconn *l_hconn = static_cast<hconn *>(l_nconn->get_data());
        if(!l_hconn)
        {
                l_hconn = get_hconn(a_url_router, DATA_TYPE_SERVER, true);
                if(!l_hconn)
                {
                        NDBG_PRINT("Error: performing config_conn\n");
                        return NULL;
                }
        }
        l_nconn->set_data(l_hconn);
        l_nconn->set_read_cb(http_parse);
        l_hconn->m_nconn = l_nconn;
        rqst *l_rqst = static_cast<rqst *>(l_hconn->m_hmsg);
        if(!get_from_pool_if_null(l_rqst, m_rqst_pool))
        {
                l_rqst->clear();
        }
        l_hconn->m_hmsg = l_rqst;

        if(!get_from_pool_if_null(l_hconn->m_in_q, m_nbq_pool))
        {
                l_hconn->m_in_q->reset_write();
        }
        l_hconn->m_hmsg->set_q(l_hconn->m_in_q);
        ++m_stat.m_cur_conn_count;
        ++m_stat.m_num_conn_started;
        return l_nconn;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int t_hlx::run(void)
{
        int32_t l_pthread_error = 0;
        l_pthread_error = pthread_create(&m_t_run_thread,
                        NULL,
                        t_run_static,
                        this);
        if (l_pthread_error != 0)
        {
                // failed to create thread
                NDBG_PRINT("Error: creating thread.  Reason: %s\n.", strerror(l_pthread_error));
                return STATUS_ERROR;
        }
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void t_hlx::stop(void)
{
        // Cleanup server connection
        //cleanup_hconn(m_listening_nconn, NULL, 200);
        m_stopped = true;
        int32_t l_status;
        l_status = m_evr_loop->signal_control();
        if(l_status != STATUS_OK)
        {
                NDBG_PRINT("Error performing stop.\n");
        }
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void t_hlx::get_stats_copy(t_stat_t &ao_stat)
{
        ao_stat = m_stat;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
bool t_hlx::subr_complete(hconn &a_hconn)
{
        subr *l_subr = a_hconn.m_subr;
        nconn *l_nconn = a_hconn.m_nconn;
        resp *l_resp = static_cast<resp *>(a_hconn.m_hmsg);

        bool l_complete = false;
        l_subr->bump_num_completed();
        subr::completion_cb_t l_completion_cb = l_subr->get_completion_cb();
        // Call completion handler
        if(l_completion_cb)
        {
                l_completion_cb(*(m_t_conf->m_hlx), *l_subr, *l_nconn, *l_resp);
        }
        // Connect only
        if(l_subr->get_connect_only())
        {
                l_complete = true;
        }
        if(a_hconn.m_subr->get_detach_resp())
        {
                a_hconn.m_subr = NULL;
                a_hconn.m_hmsg = NULL;
                a_hconn.m_in_q = NULL;
        }
        else
        {
                if(a_hconn.m_subr->get_type() != SUBR_TYPE_DUPE)
                {
                        delete a_hconn.m_subr;
                        a_hconn.m_subr = NULL;
                }
        }
        return l_complete;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::evr_loop_file_writeable_cb(void *a_data)
{
        //NDBG_PRINT("%sWRITEABLE%s %p\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF, a_data);
        if(!a_data)
        {
                //NDBG_PRINT("a_data == NULL\n");
                return STATUS_OK;
        }
        nconn* l_nconn = static_cast<nconn*>(a_data);
        CHECK_FOR_NULL_ERROR(l_nconn->get_data());
        hconn *l_hconn = static_cast<hconn *>(l_nconn->get_data());
        CHECK_FOR_NULL_ERROR(l_hconn->m_t_hlx);
        t_hlx *l_t_hlx = static_cast<t_hlx *>(l_hconn->m_t_hlx);

        if(l_hconn->m_type == DATA_TYPE_SERVER)
        {
                if(l_nconn->is_free())
                {
                        return STATUS_OK;
                }
        }

        // Cancel last timer
        l_t_hlx->m_evr_loop->cancel_timer(l_hconn->m_timer_obj);
        l_hconn->m_timer_obj = NULL;

        // Get timeout ms
        uint32_t l_timeout_ms = 0;
        if(l_hconn->m_subr)
        {
                l_timeout_ms = l_hconn->m_subr->get_timeout_s()*1000;
        }
        else
        {
                l_timeout_ms = l_t_hlx->get_timeout_s()*1000;
        }

        int32_t l_status = STATUS_OK;
        do {
                l_status = l_nconn->nc_run_state_machine(l_t_hlx->m_evr_loop, nconn::NC_MODE_WRITE, l_hconn->m_in_q, l_hconn->m_out_q);
                //NDBG_PRINT("l_status: %d\n", l_status);
                if(l_hconn->m_fs)
                {
                        if(!l_hconn->m_out_q->read_avail())
                        {
                                l_hconn->m_fs->fsread(*(l_hconn->m_out_q), 32768);
                                if(l_hconn->m_fs->fsdone())
                                {
                                        delete l_hconn->m_fs;
                                        l_hconn->m_fs = NULL;
                                }
                        }
                }
                else if(l_hconn->m_subr)
                {
                        // Get request time
                        if(!l_nconn->get_request_start_time_us() && l_nconn->get_collect_stats_flag())
                        {
                                l_nconn->set_request_start_time_us(get_time_us());
                        }
                        if(l_status == nconn::NC_STATUS_ERROR)
                        {
                                subr::error_cb_t l_error_cb = l_hconn->m_subr->get_error_cb();
                                if(l_error_cb)
                                {
                                        l_error_cb(*(l_t_hlx->m_t_conf->m_hlx), *l_hconn->m_subr, *l_nconn);
                                }
                                l_t_hlx->cleanup_hconn(*l_hconn);
                                return STATUS_ERROR;
                        }
                        else if(l_nconn->is_done())
                        {
                                bool l_complete = l_t_hlx->subr_complete(*l_hconn);
                                if(l_complete)
                                {
                                        l_t_hlx->cleanup_hconn(*l_hconn);
                                        return STATUS_OK;
                                }
                                else
                                {
                                        return STATUS_OK;
                                }
                        }
                } else
                {
                        if(l_status == nconn::NC_STATUS_ERROR)
                        {
                                l_t_hlx->cleanup_hconn(*l_hconn);
                                return STATUS_ERROR;
                        }
                }

                if(l_nconn->is_done() || (l_status == nconn::NC_STATUS_EOF))
                {
                        l_t_hlx->cleanup_hconn(*l_hconn);
                        return STATUS_OK;
                }

                if(!l_hconn->m_out_q->read_avail() && (l_hconn->m_type == DATA_TYPE_SERVER))
                {
                        if(!l_hconn->m_hmsg->m_supports_keep_alives)
                        {
                                l_t_hlx->cleanup_hconn(*l_hconn);
                                return STATUS_OK;
                        }
                        // No data left to send
                        break;
                }
                else
                {
                        if(l_status == 0)
                        {
                                break;
                        }
                }
        } while((l_status != nconn::NC_STATUS_AGAIN) && (!l_t_hlx->m_stopped));

        // Add idle timeout
        l_t_hlx->m_evr_loop->add_timer(l_timeout_ms, evr_loop_file_timeout_cb, l_nconn, &(l_hconn->m_timer_obj));
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::evr_loop_file_readable_cb(void *a_data)
{
        //NDBG_PRINT("%sREADABLE%s %p\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF, a_data);
        if(!a_data)
        {
                return STATUS_OK;
        }
        nconn* l_nconn = static_cast<nconn*>(a_data);
        CHECK_FOR_NULL_ERROR(l_nconn->get_data());
        hconn *l_hconn = static_cast<hconn *>(l_nconn->get_data());
        CHECK_FOR_NULL_ERROR(l_hconn->m_t_hlx);
        t_hlx *l_t_hlx = static_cast<t_hlx *>(l_hconn->m_t_hlx);

        // Cancel last timer
        l_t_hlx->m_evr_loop->cancel_timer(l_hconn->m_timer_obj);
        l_hconn->m_timer_obj = NULL;

        int32_t l_retval = STATUS_OK;
        int32_t l_status = STATUS_OK;

        //NDBG_PRINT("%sREADABLE%s l_nconn->is_listening(): %d\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF, l_nconn->is_listening());
        if(l_nconn->is_listening())
        {
                // Returns new client fd on success
                l_status = l_nconn->nc_run_state_machine(l_t_hlx->m_evr_loop, nconn::NC_MODE_NONE, NULL, NULL);
                if(l_status == nconn::NC_STATUS_ERROR)
                {
                        return STATUS_ERROR;
                }

                int l_fd = l_status;
                // Get new connected client conn
                nconn *l_new_nconn = NULL;
                l_new_nconn = l_t_hlx->get_new_client_conn(l_fd, l_nconn->get_scheme(), l_hconn->m_url_router);
                if(!l_new_nconn)
                {
                        //NDBG_PRINT("Error performing get_new_client_conn");
                        return STATUS_ERROR;
                }

                if(!get_from_pool_if_null(l_hconn->m_in_q, l_t_hlx->m_nbq_pool))
                {
                        l_hconn->m_in_q->reset();
                }

                // Set connected
                l_status = l_new_nconn->nc_set_accepting(l_t_hlx->m_evr_loop, l_fd);
                if(l_status != STATUS_OK)
                {
                        //NDBG_PRINT("Error: performing run_state_machine\n");
                        // 1000 apologies :)
                        l_t_hlx->cleanup_hconn(*(static_cast<hconn *>(l_new_nconn->get_data())));
                        return STATUS_ERROR;
                }

                return STATUS_OK;
        }

        //NDBG_PRINT("nconn host: %s --l_hconn->m_type: %d\n", l_nconn->m_host.c_str(), l_hconn->m_type);

        // Get timeout ms
        uint32_t l_timeout_ms = 0;
        if(l_hconn->m_subr)
        {
                l_timeout_ms = l_hconn->m_subr->get_timeout_s()*1000;
        }
        else
        {
                l_timeout_ms = l_t_hlx->get_timeout_s()*1000;
        }

        if(l_hconn->m_subr)
        {
                resp *l_resp = static_cast<resp *>(l_hconn->m_hmsg);
                int32_t l_status = STATUS_OK;
                do {
                        nconn::mode_t l_mode = nconn::NC_MODE_READ;
                        nbq *l_out_q = l_hconn->m_out_q;
                        if(l_out_q && l_out_q->read_avail())
                        {
                                l_mode = nconn::NC_MODE_WRITE;
                        }
                        l_status = l_nconn->nc_run_state_machine(l_t_hlx->m_evr_loop, l_mode, l_hconn->m_in_q, l_hconn->m_out_q);
                        if(l_status >= 0)
                        {
                                l_t_hlx->m_stat.m_num_bytes_read += l_status;
                        }
                        if(l_status == nconn::NC_STATUS_EOF)
                        {
                                l_t_hlx->cleanup_hconn(*l_hconn);
                                return STATUS_OK;
                        }

                        l_timeout_ms = l_hconn->m_subr->get_timeout_s()*1000;

                        //NDBG_PRINT("l_status:                %d\n", l_status);
                        //NDBG_PRINT("l_nconn->is_done():      %d\n", l_nconn->is_done());
                        //NDBG_PRINT("l_http_resp->m_complete: %d\n", l_hconn->m_hmsg->m_complete);
                        if((l_nconn->is_done()) ||
                           (l_hconn->m_hmsg->m_complete) ||
                           (l_status == nconn::NC_STATUS_ERROR))
                        {

                                //NDBG_PRINT("l_done: %d -- l_status: %d --proxy size: %d\n", l_done, l_status, (int)l_t_hlx->m_nconn_proxy_pool.get_nconn_obj_pool().used_size());
                                // Get request time
                                if(l_nconn->get_collect_stats_flag())
                                {
                                        l_nconn->set_stat_tt_completion_us(get_delta_time_us(l_nconn->get_request_start_time_us()));
                                }
                                l_t_hlx->add_stat_to_agg(l_nconn->get_stats(), l_hconn->m_status_code);
                                l_nconn->reset_stats();
                                if(l_status == nconn::NC_STATUS_ERROR)
                                {
                                        subr::error_cb_t l_error_cb = l_hconn->m_subr->get_error_cb();
                                        if(l_error_cb)
                                        {
                                                l_error_cb(*(l_t_hlx->m_t_conf->m_hlx), *l_hconn->m_subr, *l_nconn);
                                        }
                                        l_resp->set_status(901);
                                        ++(l_t_hlx->m_stat.m_num_errors);
                                        l_t_hlx->cleanup_hconn(*l_hconn);
                                        return STATUS_ERROR;
                                }
                                else
                                {
                                        bool l_subr_is_done = l_hconn->m_subr->get_is_done();
                                        bool l_subr_is_pending_done = l_hconn->m_subr->get_is_pending_done();
                                        bool l_complete = l_t_hlx->subr_complete(*l_hconn);
                                        if(l_complete)
                                        {
                                                l_t_hlx->cleanup_hconn(*l_hconn);
                                                return STATUS_OK;
                                        }
                                        // Display...
                                        if(l_t_hlx->m_t_conf->m_verbose)
                                        {
                                                if(l_t_hlx->m_t_conf->m_color) NDBG_OUTPUT("%s", ANSI_COLOR_FG_CYAN);
                                                l_resp->show();
                                                if(l_t_hlx->m_t_conf->m_color) NDBG_OUTPUT("%s", ANSI_COLOR_OFF);
                                        }

                                        // TODO REMOVE
                                        //NDBG_PRINT("CONN %sREUSE%s: l_nconn->can_reuse():           %d\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF, l_nconn->can_reuse());
                                        //NDBG_PRINT("CONN %sREUSE%s: l_hconn->m_supports_keep_alive: %d\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF, l_hconn->m_supports_keep_alives);
                                        //NDBG_PRINT("CONN %sREUSE%s: l_hconn->m_subr->get_is_done(): %d\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF, l_hconn->m_subr->get_is_done());
                                        //NDBG_PRINT("CONN %sREUSE%s: m_use_persistent_pool:          %d\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF, l_t_hlx->m_t_conf->m_use_persistent_pool);
                                        if(!l_nconn->can_reuse() ||
                                           !l_hconn->m_supports_keep_alives ||
                                           (l_subr_is_done && !l_t_hlx->m_t_conf->m_use_persistent_pool))
                                        {
                                                if(l_resp->get_status() >= 500)
                                                {
                                                        //++(l_t_client->m_num_error);
                                                }
                                                l_t_hlx->cleanup_hconn(*l_hconn);
                                                return STATUS_OK;
                                        }

                                        // Cancel last timer
                                        l_t_hlx->m_evr_loop->cancel_timer(l_hconn->m_timer_obj);
                                        l_hconn->m_timer_obj = NULL;
                                        uint64_t l_last_connect_us = l_nconn->get_stat_tt_connect_us();
                                        l_nconn->reset_stats();
                                        l_nconn->set_stat_tt_connect_us(l_last_connect_us);

                                        // -------------------------------------------
                                        // If not using pool try resend on same
                                        // connection.
                                        // NOTE:
                                        // This is an optimization meant for load
                                        // testing -whereas pool is used if hlx
                                        // used as proxy.
                                        // -------------------------------------------
                                        //NDBG_PRINT("l_t_hlx->m_t_conf->m_use_persistent_pool: %d\n", l_t_hlx->m_t_conf->m_use_persistent_pool);
                                        if(l_hconn->m_subr &&
                                           (l_hconn->m_subr->get_type() == SUBR_TYPE_DUPE) &&
                                           !l_t_hlx->m_t_conf->m_use_persistent_pool)
                                        {
                                                if((!l_subr_is_pending_done) &&
                                                   !l_t_hlx->m_stopped)
                                                {
                                                        // Get request time
                                                        if(l_nconn->get_collect_stats_flag())
                                                        {
                                                                l_nconn->set_request_start_time_us(get_time_us());
                                                        }
                                                        // Send request again...
                                                        l_status = l_t_hlx->start_subr(*(l_hconn->m_subr), *l_hconn, *l_nconn);
                                                        if(l_status != STATUS_OK)
                                                        {
                                                                //NDBG_PRINT("Error: performing request\n");
                                                                ++(l_t_hlx->m_stat.m_num_errors);
                                                                l_t_hlx->cleanup_hconn(*l_hconn);
                                                                return STATUS_ERROR;
                                                        }
                                                        l_hconn->m_subr->bump_num_requested();
                                                        if(l_hconn->m_subr->get_is_pending_done())
                                                        {
                                                                l_t_hlx->m_subr_queue.pop();
                                                        }
                                                }
                                                else
                                                {
                                                        l_t_hlx->cleanup_hconn(*l_hconn);
                                                        return STATUS_OK;
                                                }
                                        }
                                        else
                                        {
                                                l_status = l_t_hlx->m_nconn_proxy_pool.add_idle(l_nconn);
                                                if(l_status != STATUS_OK)
                                                {
                                                        //NDBG_PRINT("Error: performing l_t_client->m_nconn_pool.add_idle l_status: %d\n", l_status);
                                                        ++(l_t_hlx->m_stat.m_num_errors);
                                                        l_t_hlx->cleanup_hconn(*l_hconn);
                                                        return STATUS_ERROR;
                                                }
                                        }
                                        return STATUS_OK;
                                }
                                return STATUS_OK;
                        }
                } while((l_status != nconn::NC_STATUS_AGAIN) && (!l_t_hlx->m_stopped));
        }
        else
        {
                do {
                        l_status = l_nconn->nc_run_state_machine(l_t_hlx->m_evr_loop, nconn::NC_MODE_READ, l_hconn->m_in_q, l_hconn->m_out_q);
                        if(l_status > 0)
                        {
                                l_t_hlx->m_stat.m_num_bytes_read += l_status;
                        }
                        //NDBG_PRINT("l_status: %d\n", l_status);
                        if(l_status == nconn::NC_STATUS_EOF)
                        {
                                l_t_hlx->cleanup_hconn(*l_hconn);
                                return STATUS_OK;
                        }
                        else if(l_status == nconn::NC_STATUS_ERROR)
                        {
                                l_t_hlx->cleanup_hconn(*l_hconn);
                                return STATUS_ERROR;
                        }

                        //NDBG_PRINT("l_hconn->m_hmsg->m_complete: %d\n", l_hconn->m_hmsg->m_complete);
                        if(l_hconn->m_hmsg->m_complete)
                        {
                                //NDBG_PRINT("g_req_num: %d\n", ++g_req_num);
                                ++l_t_hlx->m_stat.m_num_reqs;

                                // Reset out q
                                //l_hconn->m_out_q->reset_write();

                                // -----------------------------------------------------
                                // main loop request handling...
                                // -----------------------------------------------------
                                if(l_t_hlx->handle_req(*l_hconn, l_hconn->m_url_router) != STATUS_OK)
                                {
                                        //NDBG_PRINT("Error performing handle_req\n");
                                        l_t_hlx->cleanup_hconn(*l_hconn);
                                        return STATUS_ERROR;
                                }

                                l_hconn->m_hmsg->clear();
                                if(l_status != nconn::NC_STATUS_EOF)
                                {
                                        // Reset input q
                                        l_hconn->m_in_q->reset();
                                }
                        }
                } while(l_status != nconn::NC_STATUS_AGAIN && (!l_t_hlx->m_stopped));
        }

        // Add idle timeout
        l_t_hlx->m_evr_loop->add_timer(l_timeout_ms, evr_loop_file_timeout_cb, l_nconn, &(l_hconn->m_timer_obj));

        // Normal return
        return l_retval;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::evr_loop_file_timeout_cb(void *a_data)
{
        //NDBG_PRINT("%sTIMEOUT%s %p\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, a_data);
        CHECK_FOR_NULL_ERROR(a_data);
        nconn* l_nconn = static_cast<nconn*>(a_data);
        CHECK_FOR_NULL_ERROR(l_nconn->get_data());
        hconn *l_hconn = static_cast<hconn *>(l_nconn->get_data());
        CHECK_FOR_NULL_ERROR(l_hconn->m_t_hlx);
        t_hlx *l_t_hlx = static_cast<t_hlx *>(l_hconn->m_t_hlx);
        //NDBG_PRINT("%sTIMEOUT%s HOST: %s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_nconn->m_host.c_str());
        if(l_nconn->is_free())
        {
                return STATUS_OK;
        }
        ++(l_t_hlx->m_stat.m_num_errors);
        ++l_t_hlx->m_stat.m_num_idle_killed;
        if(l_hconn->m_type == DATA_TYPE_CLIENT)
        {
                if(l_hconn->m_subr)
                {
                        l_hconn->m_subr->bump_num_completed();
                        subr::error_cb_t l_error_cb = l_hconn->m_subr->get_error_cb();
                        if(l_error_cb)
                        {
                                //NDBG_PRINT_BT();
                                l_error_cb(*(l_t_hlx->m_t_conf->m_hlx), *l_hconn->m_subr, *l_nconn);
                        }
                }
        }
        l_t_hlx->cleanup_hconn(*l_hconn);
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::evr_loop_timer_cb(void *a_data)
{
        //NDBG_PRINT("%sTIMER%s %p\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, a_data);
        if(!a_data)
        {
                //NDBG_PRINT("a_data == NULL\n");
                return STATUS_OK;
        }
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::evr_loop_file_error_cb(void *a_data)
{
        //NDBG_PRINT("%sERROR%s %p\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, a_data);
        CHECK_FOR_NULL_ERROR(a_data);
        nconn* l_nconn = static_cast<nconn*>(a_data);
        CHECK_FOR_NULL_ERROR(l_nconn->get_data());
        hconn *l_hconn = static_cast<hconn *>(l_nconn->get_data());
        CHECK_FOR_NULL_ERROR(l_hconn->m_t_hlx);
        t_hlx *l_t_hlx = static_cast<t_hlx *>(l_hconn->m_t_hlx);
        //if(l_nconn->is_free())
        //{
        //        return STATUS_OK;
        //}
        ++l_t_hlx->m_stat.m_num_errors;
        if(l_hconn->m_type == DATA_TYPE_CLIENT)
        {
                l_hconn->m_subr->bump_num_completed();
                //NDBG_PRINT("l_hconn->m_rqst.m_subr->get_num_completed(): %d\n", l_hconn->m_rqst.m_subr->get_num_completed());
                subr::error_cb_t l_error_cb = l_hconn->m_subr->get_error_cb();
                if(l_error_cb)
                {
                        //NDBG_PRINT_BT();
                        l_error_cb(*(l_t_hlx->m_t_conf->m_hlx), *l_hconn->m_subr, *l_nconn);
                }
        }
        l_t_hlx->cleanup_hconn(*l_hconn);
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::try_deq_subr(void)
{
        //NDBG_PRINT("Dequeue: m_subr_queue.size(): %d\n", (int)m_subr_queue.size());
        uint32_t l_queue_size = m_subr_queue.size();
        while(l_queue_size && !m_stopped)
        {
                --l_queue_size;
                //NDBG_PRINT("Dequeue: m_subr_queue.size(): %d --proxy size: %d\n", (int)m_subr_queue.size(), (int)m_nconn_proxy_pool.get_nconn_obj_pool().used_size());
                // Start subreq
                subr *l_subr = m_subr_queue.front();
                // Only run on resolved
                int32_t l_status;
                host_info_t l_host_info;
                std::string l_error;

                if(m_t_conf->m_resolver == NULL)
                {
                        NDBG_PRINT("Error resolver == NULL\n");
                        return STATUS_ERROR;
                }
                l_status = m_t_conf->m_resolver->cached_resolve(l_subr->get_host(),l_subr->get_port(), l_host_info, l_error);
                if(l_status != STATUS_OK)
                {
                        ++m_stat.m_num_errors;
                        l_subr->bump_num_requested();
                        l_subr->bump_num_completed();
                        subr::error_cb_t l_error_cb = l_subr->get_error_cb();
                        if(l_error_cb)
                        {
                                nconn_tcp l_nconn;
                                l_error_cb(*(m_t_conf->m_hlx), *l_subr, l_nconn);
                        }
                        m_subr_queue.pop();
                        continue;
                }
                ++(m_stat.m_num_resolved);
                nconn *l_nconn = NULL;
                l_nconn = get_proxy_conn(l_host_info,
                                         l_subr->get_label(),
                                         l_subr->get_scheme(),
                                         l_subr->get_save(),
                                         l_subr->get_connect_only());
                if(!l_nconn)
                {
                        // Push to back
                        m_subr_queue.pop();
                        m_subr_queue.push(l_subr);
                        continue;
                }

                hconn *l_hconn = static_cast<hconn *>(l_nconn->get_data());
                if(l_hconn)
                {
                        //l_hconn->m_resp.clear();
                        //l_hconn->m_rqst.clear();
                }
                else
                {
                        l_hconn = get_hconn(NULL, DATA_TYPE_CLIENT, l_subr->get_save());
                        if(!l_hconn)
                        {
                                NDBG_PRINT("Error performing get_hconn\n");
                                return STATUS_ERROR;
                        }
                }

                l_nconn->set_data(l_hconn);
                l_nconn->set_read_cb(http_parse);

                l_hconn->m_nconn = l_nconn;
                l_hconn->m_subr = l_subr;
                l_nconn->set_label(l_subr->get_label());
                l_status = start_subr(*l_subr, *l_hconn, *l_nconn);
                if(l_status != STATUS_OK)
                {
                        //NDBG_PRINT("Error performing request\n");
                        m_subr_queue.pop();
                }
                else
                {
                        l_subr->bump_num_requested();
                        //NDBG_PRINT("l_subr->is_pending_done(): %d\n", l_subr->is_pending_done());
                        if(l_subr->get_is_pending_done())
                        {
                                //NDBG_PRINT("POP'ing: host: %s\n", l_subr->m_host.c_str());
                                m_subr_queue.pop();
                        }
                }
        }
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void *t_hlx::t_run(void *a_nothing)
{
        int32_t l_status;
        l_status = init();
        if(l_status != STATUS_OK)
        {
                NDBG_PRINT("Error performing init.\n");
                return NULL;
        }
        m_stopped = false;

        // Set start time
        m_start_time_s = get_time_s();

        // TODO Test -remove
        //uint64_t l_last_time_ms = get_time_ms();
        //uint64_t l_num_run = 0;

        // -------------------------------------------------
        // Run server
        // -------------------------------------------------
        while(!m_stopped)
        {
                //NDBG_PRINT("Running.\n");
                // -----------------------------------------
                // Subrequests
                // -----------------------------------------
                l_status = try_deq_subr();
                if(l_status != STATUS_OK)
                {
                        //NDBG_PRINT("Error performing try_deq_subr.\n");
                        //return NULL;
                }
                l_status = m_evr_loop->run();
        }
        //NDBG_PRINT("Stopped...\n");
        m_stopped = true;
        return NULL;
}

#if 0
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::append_summary(nconn *a_nconn, resp *a_resp)
{
        uint16_t l_status;
        if(!a_resp)
        {
                l_status = 900;
        }
        else
        {
                l_status = a_resp->get_status();
        }
        //NDBG_PRINT("%sTID[%lu]%s: status: %u\n", ANSI_COLOR_BG_BLUE, pthread_self(), ANSI_COLOR_OFF, l_status);
        if(l_status == 900)
        {
                ++m_summary_info.m_error_addr;
        }
        else if((l_status == 0) ||
                (l_status == 901) ||
                (l_status == 902))
        {
#if 0
                char *l_buf = NULL;
                uint32_t l_len;
                a_resp->get_body(&l_buf, l_len);
                std::string l_body;
                l_body.assign(l_buf, l_len);
                // Missing ca
                if(l_body.find("unable to get local issuer certificate") != std::string::npos)
                {
                        ++m_summary_info.m_tls_error_other;
                }
                // expired
                if(l_body.find("certificate has expired") != std::string::npos)
                {
                        ++m_summary_info.m_tls_error_expired;
                }
                // expired
                if(l_body.find("self signed certificate") != std::string::npos)
                {
                        ++m_summary_info.m_tls_error_self_signed;
                }
                ++m_summary_info.m_error_conn;
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
#endif
        }
        else if(l_status == 200)
        {
                ++m_summary_info.m_success;
        }
        else
        {
                ++m_summary_info.m_error_unknown;
        }

        if((l_status == 200) && a_nconn && a_nconn->get_scheme() == SCHEME_TLS)
        {
#if 0
                void *l_cipher;
                a_nconn->get_opt(nconn_tls::OPT_TLS_INFO_CIPHER_STR, &l_cipher, NULL);
                a_resp->m_tls_info_cipher_str = (const char *)l_cipher;

                void *l_protocol;
                a_nconn->get_opt(nconn_tls::OPT_TLS_INFO_PROTOCOL_STR, &l_protocol, NULL);
                a_resp->m_tls_info_protocol_str = (const char *)l_protocol;

                //NDBG_PRINT("(const char *)l_cipher:   %s\n", (const char *)l_cipher);
                //NDBG_PRINT("(const char *)l_protocol: %s\n", (const char *)l_protocol);

                // TODO Flag for summary???
                // Add to summary...
                if(l_cipher)
                {
                        std::string l_cipher_str = (char *)l_cipher;
                        ++m_summary_info.m_tls_ciphers[l_cipher_str];
                }
                if(l_protocol)
                {
                        std::string l_protocol_str = (char *)l_protocol;
                        ++m_summary_info.m_tls_protocols[l_protocol_str];
                }
#endif
        }

        return STATUS_OK;
}
#endif

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::cleanup_hconn(hconn &a_hconn)
{
        //NDBG_PRINT("%sCLEANUP%s: a_hconn: %p -label: %s\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF, &a_hconn, a_hconn.m_nconn->get_label().c_str());
        // Cancel last timer
        if(a_hconn.m_timer_obj)
        {
                m_evr_loop->cancel_timer(a_hconn.m_timer_obj);
                a_hconn.m_timer_obj = NULL;
        }

        //NDBG_PRINT("%sADDING_BACK%s: %u a_nconn: %p type: %d\n",
        //           ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF,
        //           (uint32_t)a_nconn.get_idx(), &a_nconn, a_type);
        //NDBG_PRINT_BT();
        // Add back to free list
        if(a_hconn.m_type == DATA_TYPE_SERVER)
        {
                //NDBG_PRINT("m_nconn_pool size: %d\n", (int)m_nconn_pool.get_nconn_obj_pool().used_size());
                //NDBG_PRINT("m_idle size:       %u\n", (int)m_nconn_pool.num_idle());
                if(STATUS_OK != m_nconn_pool.release(a_hconn.m_nconn))
                {
                        return STATUS_ERROR;
                }

                if(a_hconn.m_hmsg)
                {
                        m_rqst_pool.release(static_cast<rqst *>(a_hconn.m_hmsg));
                }
                //NDBG_PRINT("m_nconn_pool size: %d\n", (int)m_nconn_pool.get_nconn_obj_pool().used_size());
                //NDBG_PRINT("m_idle size:       %u\n", (int)m_nconn_pool.num_idle());
        }
        else if(a_hconn.m_type == DATA_TYPE_CLIENT)
        {
                //NDBG_PRINT("m_nconn_proxy_pool size: %d\n", (int)m_nconn_proxy_pool.get_nconn_obj_pool().used_size());
                //NDBG_PRINT("m_idle size:       %u\n", (int)m_nconn_proxy_pool.num_idle());
                if(STATUS_OK != m_nconn_proxy_pool.release(a_hconn.m_nconn))
                {
                        return STATUS_ERROR;
                }
                if(a_hconn.m_hmsg)
                {
                        m_resp_pool.release(static_cast<resp *>(a_hconn.m_hmsg));
                }
                //NDBG_PRINT("m_nconn_proxy_pool size: %d\n", (int)m_nconn_proxy_pool.get_nconn_obj_pool().used_size());
                //NDBG_PRINT("m_idle size:       %u\n", (int)m_nconn_proxy_pool.num_idle());
        }
        a_hconn.m_nconn = NULL;

        if(a_hconn.m_in_q)
        {
                m_nbq_pool.release(a_hconn.m_in_q);
        }
        if(a_hconn.m_out_q)
        {
                m_nbq_pool.release(a_hconn.m_out_q);
        }

        m_hconn_pool.release(&a_hconn);

        --m_stat.m_cur_conn_count;
        ++m_stat.m_num_conn_completed;

        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::handle_req(hconn &a_hconn, url_router *a_url_router)
{
        rqst *l_rqst = static_cast<rqst *>(a_hconn.m_hmsg);
        // TODO Null check...
        if(!a_url_router)
        {
                return STATUS_ERROR;
        }
        if(!get_from_pool_if_null(a_hconn.m_out_q, m_nbq_pool))
        {
                a_hconn.m_out_q->reset_write();
        }
        url_pmap_t l_pmap;
        //NDBG_PRINT("a_req.get_path: %s\n", l_rqst->get_path().c_str());
        //NDBG_PRINT("a_url_router:   %p\n", a_url_router);
        //NDBG_PRINT("a_req.m_method: %d\n", l_rqst->m_method);
        rqst_h *l_rqst_h = (rqst_h *)a_url_router->find_route(l_rqst->get_path(),l_pmap);
        //NDBG_PRINT("l_rqst_h:       %p\n", l_rqst_h);
        h_resp_t l_hdlr_status = H_RESP_NONE;
        if(l_rqst_h)
        {
                // Method switch
                switch(l_rqst->m_method)
                {
                case HTTP_GET:
                {
                        l_hdlr_status = l_rqst_h->do_get(*(m_t_conf->m_hlx), a_hconn, *l_rqst, l_pmap);
                        break;
                }
                case HTTP_POST:
                {
                        l_hdlr_status = l_rqst_h->do_post(*(m_t_conf->m_hlx), a_hconn, *l_rqst, l_pmap);
                        break;
                }
                case HTTP_PUT:
                {
                        l_hdlr_status = l_rqst_h->do_put(*(m_t_conf->m_hlx), a_hconn, *l_rqst, l_pmap);
                        break;
                }
                case HTTP_DELETE:
                {
                        l_hdlr_status = l_rqst_h->do_delete(*(m_t_conf->m_hlx), a_hconn, *l_rqst, l_pmap);
                        break;
                }
                default:
                {
                        l_hdlr_status = l_rqst_h->do_default(*(m_t_conf->m_hlx), a_hconn, *l_rqst, l_pmap);
                        break;
                }
                }
        }
        else
        {
                // Default response
                l_hdlr_status = m_default_rqst_h.do_get(*(m_t_conf->m_hlx), a_hconn, *l_rqst, l_pmap);
        }

        switch(l_hdlr_status)
        {
        case H_RESP_DONE:
        {
                break;
        }
        case H_RESP_DEFERRED:
        {
                break;
        }
        case H_RESP_ERROR:
        {
                break;
        }
        default:
        {
                break;
        }
        }
        // TODO Handler errors?
        if(l_hdlr_status == H_RESP_ERROR)
        {
                return STATUS_ERROR;
        }

        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_hlx::config_conn(nconn &a_nconn,
                           url_router *a_url_router,
                           hconn_type_t a_type,
                           bool a_save,
                           bool a_connect_only)
{
        a_nconn.set_num_reqs_per_conn(m_t_conf->m_num_reqs_per_conn);
        a_nconn.set_collect_stats(m_t_conf->m_collect_stats);
        a_nconn.set_connect_only(a_connect_only);

        // -------------------------------------------
        // Set options
        // -------------------------------------------
        // Set generic options
        T_HTTP_PROXY_SET_NCONN_OPT((a_nconn), nconn_tcp::OPT_TCP_RECV_BUF_SIZE, NULL, m_t_conf->m_sock_opt_recv_buf_size);
        T_HTTP_PROXY_SET_NCONN_OPT((a_nconn), nconn_tcp::OPT_TCP_SEND_BUF_SIZE, NULL, m_t_conf->m_sock_opt_send_buf_size);
        T_HTTP_PROXY_SET_NCONN_OPT((a_nconn), nconn_tcp::OPT_TCP_NO_DELAY, NULL, m_t_conf->m_sock_opt_no_delay);

        // Set ssl options
        if(a_nconn.get_scheme() == SCHEME_TLS)
        {
                if(a_type == DATA_TYPE_SERVER)
                {
                        T_HTTP_PROXY_SET_NCONN_OPT(a_nconn,
                                               nconn_tls::OPT_TLS_CIPHER_STR,
                                               m_t_conf->m_tls_server_ctx_cipher_list.c_str(),
                                               m_t_conf->m_tls_server_ctx_cipher_list.length());
                        T_HTTP_PROXY_SET_NCONN_OPT(a_nconn,
                                               nconn_tls::OPT_TLS_CTX,
                                               m_t_conf->m_tls_server_ctx,
                                               sizeof(m_t_conf->m_tls_server_ctx));
                        if(!m_t_conf->m_tls_server_ctx_crt.empty())
                        {
                                T_HTTP_PROXY_SET_NCONN_OPT(a_nconn,
                                                       nconn_tls::OPT_TLS_TLS_CRT,
                                                       m_t_conf->m_tls_server_ctx_crt.c_str(),
                                                       m_t_conf->m_tls_server_ctx_crt.length());
                        }
                        if(!m_t_conf->m_tls_server_ctx_key.empty())
                        {
                                T_HTTP_PROXY_SET_NCONN_OPT(a_nconn,
                                                       nconn_tls::OPT_TLS_TLS_KEY,
                                                       m_t_conf->m_tls_server_ctx_key.c_str(),
                                                       m_t_conf->m_tls_server_ctx_key.length());
                        }
                        //T_HTTP_PROXY_SET_NCONN_OPT(a_nconn,
                        //                           nconn_tls::OPT_TLS_OPTIONS,
                        //                           &(m_t_conf->m_tls_server_ctx_options),
                        //                           sizeof(m_t_conf->m_tls_server_ctx_options));
                }
                else
                {
                        T_HTTP_PROXY_SET_NCONN_OPT(a_nconn,
                                               nconn_tls::OPT_TLS_CIPHER_STR,
                                               m_t_conf->m_tls_client_ctx_cipher_list.c_str(),
                                               m_t_conf->m_tls_client_ctx_cipher_list.length());
                        T_HTTP_PROXY_SET_NCONN_OPT(a_nconn,
                                               nconn_tls::OPT_TLS_CTX,
                                               m_t_conf->m_tls_client_ctx,
                                               sizeof(m_t_conf->m_tls_client_ctx));
                        T_HTTP_PROXY_SET_NCONN_OPT(a_nconn,
                                               nconn_tls::OPT_TLS_VERIFY,
                                               &(m_t_conf->m_tls_client_verify),
                                               sizeof(m_t_conf->m_tls_client_verify));
                        //T_HTTP_PROXY_SET_NCONN_OPT(a_nconn,
                        //                           nconn_tls::OPT_TLS_OPTIONS,
                        //                           &(m_t_conf->m_tls_client_ctx_options),
                        //                           sizeof(m_t_conf->m_tls_client_ctx_options));
                }
        }
        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
hconn * t_hlx::get_hconn(url_router *a_url_router,
                         hconn_type_t a_type,
                         bool a_save)
{
        hconn *l_hconn = m_hconn_pool.get_free();
        if(l_hconn)
        {
                //NDBG_PRINT("REUSED!!!\n");
                //l_hconn->m_resp.clear();
                //l_hconn->m_rqst.clear();
        }
        else
        {
                l_hconn = new hconn();
                m_hconn_pool.add(l_hconn);
        }
        //NDBG_PRINT("Adding http_data: %p.\n", l_hconn);
        l_hconn->m_t_hlx = this;
        l_hconn->m_url_router = a_url_router;
        l_hconn->m_timer_obj = NULL;
        l_hconn->m_save = a_save;
        l_hconn->m_type = a_type;
        l_hconn->m_supports_keep_alives = false;
        l_hconn->m_status_code = 0;
        l_hconn->m_http_parser_settings.on_status = hp_on_status;
        l_hconn->m_http_parser_settings.on_message_complete = hp_on_message_complete;
        if(l_hconn->m_save)
        {
                l_hconn->m_http_parser_settings.on_message_begin = hp_on_message_begin;
                l_hconn->m_http_parser_settings.on_url = hp_on_url;
                l_hconn->m_http_parser_settings.on_header_field = hp_on_header_field;
                l_hconn->m_http_parser_settings.on_header_value = hp_on_header_value;
                l_hconn->m_http_parser_settings.on_headers_complete = hp_on_headers_complete;
                l_hconn->m_http_parser_settings.on_body = hp_on_body;
        }
        l_hconn->m_http_parser.data = l_hconn;
        if(a_type == DATA_TYPE_SERVER)
        {
                http_parser_init(&(l_hconn->m_http_parser), HTTP_REQUEST);
        }
        else
        {
                http_parser_init(&(l_hconn->m_http_parser), HTTP_RESPONSE);
        }
        return l_hconn;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void t_hlx::add_stat_to_agg(const req_stat_t &a_req_stat, uint16_t a_status_code)
{
        update_stat(m_stat.m_stat_us_connect, a_req_stat.m_tt_connect_us);
        update_stat(m_stat.m_stat_us_first_response, a_req_stat.m_tt_first_read_us);
        update_stat(m_stat.m_stat_us_end_to_end, a_req_stat.m_tt_completion_us);

        // Totals
        ++m_stat.m_total_reqs;
        m_stat.m_total_bytes += a_req_stat.m_total_bytes;

        // Status code
        //NDBG_PRINT("%sSTATUS_CODE%s: %d\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF, a_req_stat.m_status_code);
        ++m_stat.m_status_code_count_map[a_status_code];
}

} //namespace ns_hlx {