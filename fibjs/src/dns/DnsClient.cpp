/*
 * DnsClient.h
 *
 *  Created on: Aug 16, 2017
 *      Author: Rube
 */

#include "DnsClient.h"
#include "List.h"
#include "Map.h"
#include "SimpleObject.h"
#include <cares/ares.h>

#if defined(__ANDROID__) || defined(__MINGW32__) || defined(__OpenBSD__) || defined(_MSC_VER)

#include <cares/include/nameser.h>
#else
#include <arpa/nameser.h>
#endif

namespace fibjs {
inline const char* ToDNSErrorCodeString(int status)
{
    switch (status) {
#define V(code)       \
    case ARES_##code: \
        return #code;
        V(EADDRGETNETWORKPARAMS)
        V(EBADFAMILY)
        V(EBADFLAGS)
        V(EBADHINTS)
        V(EBADNAME)
        V(EBADQUERY)
        V(EBADRESP)
        V(EBADSTR)
        V(ECANCELLED)
        V(ECONNREFUSED)
        V(EDESTRUCTION)
        V(EFILE)
        V(EFORMERR)
        V(ELOADIPHLPAPI)
        V(ENODATA)
        V(ENOMEM)
        V(ENONAME)
        V(ENOTFOUND)
        V(ENOTIMP)
        V(ENOTINITIALIZED)
        V(EOF)
        V(EREFUSED)
        V(ESERVFAIL)
        V(ETIMEOUT)
#undef V
    }

    return "UNKNOWN_ARES_ERROR";
}

class AresChannel {
public:
    AresChannel()
        : m_channel(nullptr)
    {
    }
    exlib::Semaphore m_sem;
    ares_channel m_channel;
};

static AresChannel s_aresChannel;
class asyncRadosCallback : public exlib::Task_base {
public:
    asyncRadosCallback(RadosStream* pThis, AsyncEvent* ac, exlib::Locker& locker)
        : m_comp(NULL)
        , m_pThis(pThis)
        , m_ac(ac)
        , m_locker(locker)
    {
    }
    virtual ~asyncRadosCallback()
    {
        if (m_comp) {
            _rados_aio_release(m_comp);
            m_comp = NULL;
        }
    }

public:
    virtual void suspend()
    {
    }

    virtual void suspend(exlib::spinlock& lock)
    {
        lock.unlock();
    }

    virtual void resume()
    {
    }

public:
    result_t call()
    {
        if (m_locker.lock(this)) {
            result_t hr = process();
            if (hr != CALL_E_PENDDING) {
                m_locker.unlock(this);
                delete this;

                return hr;
            }
        }

        return CALL_E_PENDDING;
    }

    virtual int32_t process()
    {
        return 0;
    }

    virtual void proc()
    {
        ready(process());
    }

    result_t before()
    {
        result_t hr;

        if (!m_comp) {
            hr = _rados_aio_create_completion((void*)this, complete_callback, NULL, &m_comp);
            if (hr < 0)
                return CHECK_ERROR(hr);
        }

        return 0;
    }

    void ready(int32_t v)
    {
        m_locker.unlock(this);
        m_ac->apost(v);
        delete this;
    }
    void onready()
    {
        proc();
    }

public:
    static void complete_callback(rados_completion_t comp, void* arg)
    {
        ((asyncRadosCallback*)arg)->onready();
    }

public:
    rados_completion_t m_comp;
    obj_ptr<RadosStream> m_pThis;
    AsyncEvent* m_ac;
    exlib::Locker& m_locker;
};

class asyncDNSQuery : public AsyncState {
public:
    asyncDNSQuery(exlib::string host, obj_ptr<List_base>& retVal, int dnsclass, int type, ares_callback callback, AsyncEvent* ac)
        : AsyncState(ac)
        , m_retVal((obj_ptr<object_base>&)retVal)
        , m_type(type)
        , m_host(host)
        , m_dnsclass(dnsclass)
        , m_callback(callback)
    {
        set(query);
    }

    asyncDNSQuery(exlib::string host, obj_ptr<object_base>& retVal, int dnsclass, int type, ares_callback callback, AsyncEvent* ac)
        : AsyncState(ac)
        , m_retVal(retVal)
        , m_type(type)
        , m_host(host)
        , m_dnsclass(dnsclass)
        , m_callback(callback)
    {
        set(query);
    }

    static int32_t query(AsyncState* pState, int32_t n)
    {
        asyncDNSQuery* pThis = (asyncDNSQuery*)pState;

        ares_query(s_aresChannel.m_channel, pThis->m_host.c_str(), pThis->m_dnsclass, pThis->m_type, pThis->m_callback, pThis);
        s_aresChannel.m_sem.post();

        return 0;
    }

    static int32_t error(AsyncState* pState, int32_t n)
    {
        asyncDNSQuery* pThis = (asyncDNSQuery*)pState;

        if (pThis->errorno != 0) {
            pThis->done();
            return CHECK_ERROR(Runtime::setError(ToDNSErrorCodeString(pThis->errorno)));
        }

        pThis->done();
        return 0;
    }

    obj_ptr<object_base>& m_retVal;
    int errorno = 0;

private:
    int m_type;
    exlib::string m_host;
    int m_dnsclass;
    ares_callback m_callback;
};

class _acAres : public exlib::OSThread {
public:
    _acAres()
    {
        int32_t s, res;
        s = ares_library_init(ARES_LIB_INIT_ALL);
        if (s != ARES_SUCCESS) {
            printf("ares_library_init failed: %d\n", s);
            exit(-1);
        }
        res = ares_init(&s_aresChannel.m_channel);
        if (res != ARES_SUCCESS) {
            printf("ares_init failed: %d\n", s);
            exit(-1);
        }
    }

    virtual void Run()
    {
        int32_t nfds;
        timeval tv, *tvp;

        Runtime rt(NULL);
        while (1) {
            s_aresChannel.m_sem.wait();
            while (s_aresChannel.m_sem.trywait())
                ;
            FD_ZERO(&m_readers);
            FD_ZERO(&m_writers);
            nfds = ares_fds(s_aresChannel.m_channel, &m_readers, &m_writers);
            if (nfds == 0)
                continue;
            tvp = ares_timeout(s_aresChannel.m_channel, NULL, &tv);
            select(nfds, &m_readers, &m_writers, NULL, tvp);
            ares_process(s_aresChannel.m_channel, &m_readers, &m_writers);
        }
    }

public:
    fd_set m_readers;
    fd_set m_writers;
};

void init_ares()
{
    static _acAres s_acAres;

    s_acAres.start();
}

class asyncMxQuery : public asyncDNSQuery {
public:
    class ResolveMxResult : public SimpleObject {
    public:
        ResolveMxResult(ares_mx_reply* mx_reply)
        {
            add("exchange", mx_reply->host);
            add("priority", mx_reply->priority);
        }
    };

    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        struct ares_mx_reply* mx_reply = nullptr;
        obj_ptr<List> mx_list;
        asyncDNSQuery* pThis = (asyncDNSQuery*)arg;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_mx_reply(abuf, alen, &mx_reply);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        mx_list = new List();
        ares_mx_reply* current = mx_reply;
        for (uint32_t i = 0; current != nullptr; ++i, current = current->next) {
            mx_list->append(new ResolveMxResult(current));
        }

        ares_free_data(mx_reply);
        pThis->m_retVal = mx_list;
        pThis->done();
    }

    asyncMxQuery(exlib::string hostName, obj_ptr<List_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(hostName, retVal, ns_c_in, ns_t_mx, callback, ac){};
};

class asyncSrvQuery : public asyncDNSQuery {
public:
    class ResolveSrvResult : public SimpleObject {
    public:
        ResolveSrvResult(ares_srv_reply* srv_reply)
        {
            add("name", srv_reply->host);
            add("port", srv_reply->port);
            add("priority", srv_reply->priority);
            add("weight", srv_reply->weight);
        }
    };

    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        struct ares_srv_reply* srv_start;
        asyncDNSQuery* pThis = (asyncDNSQuery*)arg;
        obj_ptr<List> srv_list;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_srv_reply(abuf, alen, &srv_start);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        srv_list = new List();
        ares_srv_reply* current = srv_start;
        for (uint32_t i = 0; current != nullptr; ++i, current = current->next) {
            srv_list->append(new ResolveSrvResult(current));
        }

        ares_free_data(srv_start);
        pThis->m_retVal = srv_list;
        pThis->done();
    }

    asyncSrvQuery(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(host, retVal, ns_c_in, ns_t_srv, callback, ac){};
};

class asyncTxtQuery : public asyncDNSQuery {
public:
    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        struct ares_txt_ext* txt_out;
        asyncDNSQuery* pThis = (asyncDNSQuery*)arg;
        obj_ptr<List> txt_list;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_txt_reply_ext(abuf, alen, &txt_out);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        struct ares_txt_ext* current = txt_out;
        int32_t len;
        obj_ptr<List> txt_result = new List();
        txt_list = new List();

        for (uint32_t i = 0; current != nullptr; current = current->next) {

            if (current->record_start) {
                txt_result->get_length(len);
                if (len != 0) {
                    txt_list->append(txt_result);
                }

                txt_result = new List();
                i = 0;
            }

            txt_result->append((char*)current->txt);
        }

        txt_result->get_length(len);
        if (len != 0) {
            txt_list->append(txt_result);
        }

        ares_free_data(txt_out);
        pThis->m_retVal = txt_list;
        pThis->done();
    }

    asyncTxtQuery(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(host, retVal, ns_c_in, ns_t_txt, callback, ac){};
};

class asyncNsQuery : public asyncDNSQuery {
public:
    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        asyncDNSQuery* pThis = (asyncDNSQuery*)arg;
        obj_ptr<List> ns_list;
        hostent* host;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_ns_reply(abuf, alen, &host);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        ns_list = new List();
        for (uint32_t i = 0; host->h_aliases[i] != nullptr; ++i) {
            ns_list->append(host->h_aliases[i]);
        }

        ares_free_hostent(host);
        pThis->m_retVal = ns_list;
        pThis->done();
    }

    asyncNsQuery(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(host, retVal, ns_c_in, ns_t_ns, callback, ac){};
};

class asyncSoaQuery : public asyncDNSQuery {
public:
    class ResolveSoaResult : public SimpleObject {
    public:
        ResolveSoaResult(ares_soa_reply* soa_out)
        {
            add("nsname", soa_out->nsname);
            add("hostmaster", soa_out->hostmaster);
            add("serial", (int)soa_out->serial);
            add("refresh", (int)soa_out->refresh);
            add("retry", (int)soa_out->retry);
            add("expire", (int)soa_out->expire);
            add("minttl", (int)soa_out->minttl);
        }
    };

    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        asyncDNSQuery* pThis = (asyncDNSQuery*)arg;
        ares_soa_reply* soa_out;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_soa_reply(abuf, alen, &soa_out);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        pThis->m_retVal = new ResolveSoaResult(soa_out);
        ares_free_data(soa_out);
        pThis->done();
    }

    asyncSoaQuery(exlib::string host, obj_ptr<object_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(host, retVal, ns_c_in, ns_t_soa, callback, ac){};
};

class asyncPtrQuery : public asyncDNSQuery {
public:
    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        asyncDNSQuery* pThis = (asyncDNSQuery*)arg;
        hostent* host;
        obj_ptr<List> ptr_list;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_ptr_reply(abuf, alen, NULL, 0, AF_INET, &host);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        ptr_list = new List();
        for (uint32_t i = 0; host->h_aliases[i] != NULL; i++) {
            ptr_list->append(host->h_aliases[i]);
        }

        ares_free_hostent(host);
        pThis->m_retVal = ptr_list;
        pThis->done();
    }

    asyncPtrQuery(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(host, retVal, ns_c_in, ns_t_ptr, callback, ac){};
};

class asyncNaptrQuery : public asyncDNSQuery {
public:
    class ResolveNaptrResult : public SimpleObject {
    public:
        ResolveNaptrResult(ares_naptr_reply* naptr_reply)
        {
            add("flags", (char*)naptr_reply->flags);
            add("service", (char*)naptr_reply->service);
            add("regexp", (char*)naptr_reply->regexp);
            add("replacement", naptr_reply->replacement);
            add("order", naptr_reply->order);
            add("preference", naptr_reply->preference);
        }
    };

    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        asyncDNSQuery* pThis = (asyncDNSQuery*)arg;
        ares_naptr_reply* naptr_start;
        obj_ptr<List> naptr_list;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_naptr_reply(abuf, alen, &naptr_start);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        naptr_list = new List();
        ares_naptr_reply* current = naptr_start;
        for (uint32_t i = 0; current != nullptr; ++i, current = current->next) {
            naptr_list->append(new ResolveNaptrResult(current));
        }

        ares_free_data(naptr_start);
        pThis->m_retVal = naptr_list;
        pThis->done();
    }

    asyncNaptrQuery(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(host, retVal, ns_c_in, ns_t_naptr, callback, ac){};
};

class asyncCnameQuery : public asyncDNSQuery {
public:
    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        asyncDNSQuery* pThis = (asyncDNSQuery*)arg;
        hostent* host;
        obj_ptr<List> cname_list;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_a_reply(abuf, alen, &host, nullptr, nullptr);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        cname_list = new List();
        cname_list->append(host->h_name);
        ares_free_hostent(host);
        pThis->m_retVal = cname_list;
        pThis->done();
    }

    asyncCnameQuery(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(host, retVal, ns_c_in, ns_t_cname, callback, ac){};
};

class asyncAQuery : public asyncDNSQuery {
public:
    class ResolveAResult : public SimpleObject {
    public:
        ResolveAResult(int ttl, char* ip)
        {
            add("address", ip);
            add("ttl", ttl);
        }
    };

    static int inet_ntop4(const unsigned char* src, char* dst, size_t size)
    {
        static const char fmt[] = "%u.%u.%u.%u";
        char tmp[16];
        int l;

        l = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
        if (l <= 0 || (size_t)l >= size) {
            return 1;
        }
        strncpy(dst, tmp, size);
        dst[size - 1] = '\0';
        return 0;
    }

    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        asyncAQuery* pThis = (asyncAQuery*)arg;
        hostent* host;
        ares_addrttl addrttls[256];
        int naddrttls = sizeof(addrttls);
        obj_ptr<List> a_list;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_a_reply(abuf, alen, &host, (ares_addrttl*)addrttls, &naddrttls);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        a_list = new List();
        for (uint32_t i = 0; host->h_addr_list[i] != nullptr; ++i) {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop4((const unsigned char*)host->h_addr_list[i], ip, sizeof(ip));

            if (pThis->m_ttl) {
                a_list->append(new ResolveAResult(addrttls[i].ttl, ip));
            } else {
                a_list->append(ip);
            }
        }

        ares_free_hostent(host);
        pThis->m_retVal = a_list;
        pThis->done();
    }

    asyncAQuery(exlib::string host, bool ttl, obj_ptr<List_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(host, retVal, ns_c_in, ns_t_a, callback, ac)
        , m_ttl(ttl){};

public:
    bool m_ttl = false;
};

class asyncAAAAQuery : public asyncDNSQuery {
public:
    class ResolveAAAAResult : public SimpleObject {
    public:
        ResolveAAAAResult(int ttl, char* ip)
        {
            add("address", ip);
            add("ttl", ttl);
        }
    };

    static int inet_ntop6(const unsigned char* src, char* dst, size_t size)
    {

        char tmp[46], *tp;
        struct {
            int base, len;
        } best, cur;
        unsigned int words[sizeof(struct in6_addr) / sizeof(uint16_t)];
        int i;

        memset(words, '\0', sizeof words);
        for (i = 0; i < (int)sizeof(struct in6_addr); i++)
            words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
        best.base = -1;
        best.len = 0;
        cur.base = -1;
        cur.len = 0;
        for (i = 0; i < (int)(sizeof(words) / sizeof((words)[0])); i++) {
            if (words[i] == 0) {
                if (cur.base == -1)
                    cur.base = i, cur.len = 1;
                else
                    cur.len++;
            } else {
                if (cur.base != -1) {
                    if (best.base == -1 || cur.len > best.len)
                        best = cur;
                    cur.base = -1;
                }
            }
        }
        if (cur.base != -1) {
            if (best.base == -1 || cur.len > best.len)
                best = cur;
        }
        if (best.base != -1 && best.len < 2)
            best.base = -1;

        tp = tmp;
        for (i = 0; i < (int)(sizeof(words) / sizeof((words)[0])); i++) {
            if (best.base != -1 && i >= best.base && i < (best.base + best.len)) {
                if (i == best.base)
                    *tp++ = ':';
                continue;
            }

            if (i != 0)
                *tp++ = ':';

            if (i == 6 && best.base == 0 && (best.len == 6 || (best.len == 7 && words[7] != 0x0001) || (best.len == 5 && words[5] == 0xffff))) {
                int err = asyncAQuery::inet_ntop4(src + 12, tp, sizeof tmp - (tp - tmp));
                if (err)
                    return err;
                tp += strlen(tp);
                break;
            }
            tp += sprintf(tp, "%x", words[i]);
        }

        if (best.base != -1 && (best.base + best.len) == (sizeof(words) / sizeof((words)[0])))
            *tp++ = ':';
        *tp++ = '\0';

        if ((size_t)(tp - tmp) > size) {
            return 1;
        }
        strcpy(dst, tmp);
        return 0;
    }

    static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
    {
        asyncAQuery* pThis = (asyncAQuery*)arg;
        hostent* host;
        ares_addr6ttl addrttls[256];
        int naddrttls = sizeof(addrttls);
        obj_ptr<List> aaaa_list;

        if (status != ARES_SUCCESS) {
            pThis->errorno = status;
            pThis->set(error);
            return;
        }

        int rs_status = ares_parse_aaaa_reply(abuf, alen, &host, (ares_addr6ttl*)addrttls, &naddrttls);
        if (rs_status != ARES_SUCCESS) {
            pThis->errorno = rs_status;
            pThis->set(error);
            return;
        }

        aaaa_list = new List();
        for (uint32_t i = 0; host->h_addr_list[i] != nullptr; ++i) {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop6((const unsigned char*)host->h_addr_list[i], ip, sizeof(ip));

            if (pThis->m_ttl) {
                aaaa_list->append(new ResolveAAAAResult(addrttls[i].ttl, ip));
            } else {
                aaaa_list->append(ip);
            }
        }

        ares_free_hostent(host);
        pThis->m_retVal = aaaa_list;
        pThis->done();
    }

    asyncAAAAQuery(exlib::string host, bool ttl, obj_ptr<List_base>& retVal, AsyncEvent* ac)
        : asyncDNSQuery(host, retVal, ns_c_in, ns_t_aaaa, callback, ac)
        , m_ttl(ttl){};

public:
    bool m_ttl = false;
};

result_t DnsClient_base::_new(obj_ptr<DnsClient_base>& retVal, v8::Local<v8::Object> This)
{
    retVal = new DnsClient();
    return 0;
}

result_t DnsClient::resolve(exlib::string host, exlib::string type, Variant& retVal, AsyncEvent* ac)
{
    result_t hr;
    Isolate* isolate = Isolate::current();

    v8::Local<v8::Object> oRet = v8::Object::New(isolate->m_isolate);
    v8::Local<v8::Array> aRet = v8::Array::New(isolate->m_isolate);

    if (type == "MX") {
        hr = resolveMx(host, aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "TXT") {
        hr = resolveTxt(host, aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "SRV") {
        hr = resolveSrv(host, aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "A") {
        hr = resolve4(host, v8::Object::New(isolate->m_isolate), aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "AAAA") {
        hr = resolve6(host, v8::Object::New(isolate->m_isolate), aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "CNAME") {
        hr = resolveCname(host, aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "NAPTR") {
        hr = resolveNaptr(host, aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "PTR") {
        hr = resolvePtr(host, aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "NS") {
        hr = resolveNs(host, aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "SOA") {
        hr = resolveSoa(host, oRet, ac);
        retVal = oRet;
        return hr;
    }

    return CHECK_ERROR(CALL_E_INVALIDARG);
}

// result_t DnsClient::resolve4(exlib::string host, v8::Local<v8::Object> options, v8::Local<v8::Array>& retVal, AsyncEvent* ac)
result_t DnsClient::resolve4(exlib::string host, Map_base* options, obj_ptr<List_base>& retVal,
    AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    Variant v;
    options->get("ttl", v);

    return (new asyncAQuery(host, v.boolVal(), retVal, ac))->post(0);
}

result_t DnsClient::resolve4(exlib::string host, obj_ptr<List_base>& retVal,
    AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncAQuery(host, false, retVal, ac))->post(0);
}

result_t DnsClient::resolve6(exlib::string host, Map_base* options, obj_ptr<List_base>& retVal,
    AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    Variant v;
    options->get("ttl", v);

    return (new asyncAAAAQuery(host, v.boolVal(), retVal, ac))->post(0);
}

result_t DnsClient::resolve6(exlib::string host, obj_ptr<List_base>& retVal,
    AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncAAAAQuery(host, false, retVal, ac))->post(0);
}

result_t DnsClient::resolveCname(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncCnameQuery(host, retVal, ac))->post(0);
}

result_t DnsClient::resolveNaptr(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncNaptrQuery(host, retVal, ac))->post(0);
}

result_t DnsClient::resolveNs(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncNsQuery(host, retVal, ac))->post(0);
}

result_t DnsClient::resolvePtr(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncPtrQuery(host, retVal, ac))->post(0);
}

result_t DnsClient::resolveSoa(exlib::string host, obj_ptr<object_base>& retVal, AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncSoaQuery(host, retVal, ac))->post(0);
}

result_t DnsClient::resolveTxt(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncTxtQuery(host, retVal, ac))->post(0);
}

result_t DnsClient::resolveSrv(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
{

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncSrvQuery(host, retVal, ac))->post(0);
}

result_t DnsClient::resolveMx(exlib::string host, obj_ptr<List_base>& retVal, AsyncEvent* ac)
{
    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    return (new asyncMxQuery(host, retVal, ac))->post(0);
}
}