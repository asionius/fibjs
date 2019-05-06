/*
 * DnsClient.h
 *
 *  Created on: Aug 16, 2017
 *      Author: Rube
 */

#include "DnsClient.h"
#include <cares/ares.h>

#if defined(__ANDROID__) || defined(__MINGW32__) || defined(__OpenBSD__) || defined(_MSC_VER)

#include <cares/include/nameser.h>
#else
#include <arpa/nameser.h>
#endif

namespace fibjs {

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

class asyncDNSQuery : public exlib::Task_base {
public:
    asyncDNSQuery(AsyncEvent* ac, exlib::Locker& locker)
        : m_ac(ac)
        , m_locker(locker)
    {
    }
    virtual ~asyncDNSQuery()
    {
    }

public:
    virtual void resume()
    {
        process2();
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

    virtual int32_t process2()
    {
        return 0;
    }

    virtual void proc()
    {
        ready(process());
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
    AsyncEvent* m_ac;
    exlib::Locker& m_locker;
};

static exlib::string AddressToString(const void* vaddr, int len)
{
    const uint8_t* addr = (const uint8_t*)vaddr;
    exlib::string s;
    if (len == 4) {
        char buffer[4 * 4 + 3 + 1] = { 0 };
        sprintf(buffer, "%u.%u.%u.%u",
            (unsigned char)addr[0],
            (unsigned char)addr[1],
            (unsigned char)addr[2],
            (unsigned char)addr[3]);
        s += buffer;
    } else if (len == 16) {
        for (int ii = 0; ii < 16; ii += 2) {
            if (ii > 0)
                s += ':';
            char buffer[4 + 1];
            sprintf(buffer, "%02x%02x", (unsigned char)addr[ii], (unsigned char)addr[ii + 1]);
            s += buffer;
        }
    } else {
        exlib::string s1;
        for (int ii = 0; ii < len; ii++) {
            char buffer[2 + 1] = { 0 };
            sprintf(buffer, "%02x", addr[ii]);
            s1 += buffer;
        }
        s = s + "!" + s1 + "!";
    }
    return s;
}

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
        timeval tv, *tvp, tv1;

        tv1.tv_sec = 0;
        tv1.tv_usec = 100000;

        Runtime rt(NULL);
        while (1) {
            s_aresChannel.m_sem.wait();
            while (1) {
                FD_ZERO(&m_readers);
                FD_ZERO(&m_writers);
                nfds = ares_fds(s_aresChannel.m_channel, &m_readers, &m_writers);
                if (nfds == 0)
                    break;
                tvp = ares_timeout(s_aresChannel.m_channel, &tv1, &tv);
                select(nfds, &m_readers, &m_writers, NULL, tvp);
                ares_process(s_aresChannel.m_channel, &m_readers, &m_writers);
            }
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

result_t DnsClient_base::_new(obj_ptr<DnsClient_base>& retVal, v8::Local<v8::Object> This)
{
    retVal = new DnsClient();
    return 0;
}

result_t DnsClient::resolve(exlib::string host, exlib::string type, Variant& retVal, AsyncEvent* ac)
{
    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    result_t hr;

    obj_ptr<NObject> oRet = new NObject();
    obj_ptr<NArray> aRet = new NArray();

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
        hr = resolve4(host, false, aRet, ac);
        retVal = aRet;
        return hr;
    } else if (type == "AAAA") {
        hr = resolve6(host, false, aRet, ac);
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

result_t DnsClient::resolve4(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return resolve4(host, false, retVal, ac);
}

result_t DnsClient::resolve4(exlib::string host, v8::Local<v8::Object> options, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    bool v;
    if (ac->isSync()) {
        result_t hr;
        Isolate* isolate = Isolate::current();

        hr = GetConfigValue(isolate->m_isolate, options, "ttl", v);
        if (hr == CALL_E_PARAMNOTOPTIONAL)
            v = false;
        else if (hr < 0)
            return CHECK_ERROR(hr);

        ac->m_ctx.resize(1);
        ac->m_ctx[0] = v;
        return CHECK_ERROR(CALL_E_NOSYNC);
    }

    v = ac->m_ctx[0].boolVal();
    return resolve4(host, v, retVal, ac);
}

result_t DnsClient::resolve6(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return resolve6(host, false, retVal, ac);
}

result_t DnsClient::resolve6(exlib::string host, v8::Local<v8::Object> options, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    bool v;
    if (ac->isSync()) {
        result_t hr;
        Isolate* isolate = Isolate::current();

        hr = GetConfigValue(isolate->m_isolate, options, "ttl", v);
        if (hr == CALL_E_PARAMNOTOPTIONAL)
            v = false;
        else if (hr < 0)
            return CHECK_ERROR(hr);

        ac->m_ctx.resize(1);
        ac->m_ctx[0] = v;
        return CHECK_ERROR(CALL_E_NOSYNC);
    }

    v = ac->m_ctx[0].boolVal();

    return resolve6(host, v, retVal, ac);
}

result_t DnsClient::resolve4(exlib::string host, bool ttl, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    class asyncResolve4 : public asyncDNSQuery {
    public:
        asyncResolve4(exlib::string host, bool ttl, obj_ptr<NArray>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_ttl(ttl)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_a, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_a, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolve4* pThis = (asyncResolve4*)arg;
            struct hostent* host;
            struct ares_addrttl addrttls[256];
            int naddrttls = sizeof(addrttls);

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_a_reply(abuf, alen, &host, (ares_addrttl*)addrttls, &naddrttls);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }
            for (uint32_t i = 0; host->h_addr_list[i] != nullptr; ++i) {
                exlib::string ip;
                ip = AddressToString(host->h_addr_list[i], host->h_length);

                if (pThis->m_ttl) {
                    pThis->m_retVal->append(new ResolveResult(addrttls[i].ttl, ip));
                } else {
                    pThis->m_retVal->append(ip);
                }
            }
            ares_free_hostent(host);
            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_ttl;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NArray> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();
    return (new asyncResolve4(host, ttl, retVal, ac, m_lockRead))->call();
}

result_t DnsClient::resolve6(exlib::string host, bool ttl, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    class asyncResolve6 : public asyncDNSQuery {
    public:
        asyncResolve6(exlib::string host, bool ttl, obj_ptr<NArray>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_ttl(ttl)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_aaaa, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_aaaa, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolve6* pThis = (asyncResolve6*)arg;
            struct hostent* host;
            struct ares_addr6ttl addrttls[256];
            int naddrttls = sizeof(addrttls);

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_aaaa_reply(abuf, alen, &host, (ares_addr6ttl*)addrttls, &naddrttls);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }
            for (uint32_t i = 0; host->h_addr_list[i] != nullptr; ++i) {
                exlib::string ip;
                ip = AddressToString(host->h_addr_list[i], host->h_length);

                if (pThis->m_ttl) {
                    pThis->m_retVal->append(new ResolveResult(addrttls[i].ttl, ip));
                } else {
                    pThis->m_retVal->append(ip);
                }
            }
            ares_free_hostent(host);
            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_ttl;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NArray> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();
    return (new asyncResolve6(host, ttl, retVal, ac, m_lockRead))->call();
}

result_t DnsClient::resolveCname(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    class asyncResolveCname : public asyncDNSQuery {
    public:
        asyncResolveCname(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_cname, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_cname, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolveCname* pThis = (asyncResolveCname*)arg;
            struct hostent* host;
            struct ares_addrttl addrttls[256];
            int naddrttls = sizeof(addrttls);

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_a_reply(abuf, alen, &host, (ares_addrttl*)addrttls, &naddrttls);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            pThis->m_retVal->append(host->h_name);
            ares_free_hostent(host);
            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NArray> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();
    return (new asyncResolveCname(host, retVal, ac, m_lockRead))->call();
}

result_t DnsClient::resolveNaptr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    class asyncResolveNaptr : public asyncDNSQuery {
    public:
        class ResolveNaptrResult : public NObject {
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

    public:
        asyncResolveNaptr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_naptr, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_naptr, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolveNaptr* pThis = (asyncResolveNaptr*)arg;
            struct ares_naptr_reply* naptr_start;

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_naptr_reply(abuf, alen, &naptr_start);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            for (struct ares_naptr_reply* current = naptr_start; current != nullptr; current = current->next) {
                pThis->m_retVal->append(new ResolveNaptrResult(current));
            }
            ares_free_data(naptr_start);

            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NArray> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();
    return (new asyncResolveNaptr(host, retVal, ac, m_lockRead))->call();
}

result_t DnsClient::resolveNs(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    class asyncResolveNs : public asyncDNSQuery {
    public:
        asyncResolveNs(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_ns, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_ns, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolveNs* pThis = (asyncResolveNs*)arg;
            struct hostent* host;

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_ns_reply(abuf, alen, &host);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            for (uint32_t i = 0; host->h_aliases[i] != nullptr; ++i) {
                pThis->m_retVal->append(host->h_aliases[i]);
            }
            ares_free_hostent(host);
            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NArray> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();
    return (new asyncResolveNs(host, retVal, ac, m_lockRead))->call();
}

result_t DnsClient::resolvePtr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    class asyncResolvePtr : public asyncDNSQuery {
    public:
        asyncResolvePtr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_ptr, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_ptr, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolvePtr* pThis = (asyncResolvePtr*)arg;
            struct hostent* host;

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_ptr_reply(abuf, alen, NULL, 0, AF_INET, &host);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            for (uint32_t i = 0; host->h_aliases[i] != nullptr; ++i) {
                pThis->m_retVal->append(host->h_aliases[i]);
            }
            ares_free_hostent(host);
            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NArray> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();
    return (new asyncResolvePtr(host, retVal, ac, m_lockRead))->call();
}

result_t DnsClient::resolveSoa(exlib::string host, obj_ptr<NObject>& retVal, AsyncEvent* ac)
{
    class asyncResolveSoa : public asyncDNSQuery {
    public:
        asyncResolveSoa(exlib::string host, obj_ptr<NObject>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_soa, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_soa, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolveSoa* pThis = (asyncResolveSoa*)arg;
            struct ares_soa_reply* soa_out;

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_soa_reply(abuf, alen, &soa_out);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            pThis->m_retVal->add("nsname", soa_out->nsname);
            pThis->m_retVal->add("hostmaster", soa_out->hostmaster);
            pThis->m_retVal->add("serial", (int)soa_out->serial);
            pThis->m_retVal->add("refresh", (int)soa_out->refresh);
            pThis->m_retVal->add("retry", (int)soa_out->retry);
            pThis->m_retVal->add("expire", (int)soa_out->expire);
            pThis->m_retVal->add("minttl", (int)soa_out->minttl);

            ares_free_data(soa_out);

            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NObject> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NObject();
    return (new asyncResolveSoa(host, retVal, ac, m_lockRead))->call();
}

result_t DnsClient::resolveTxt(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    class asyncResolveTxt : public asyncDNSQuery {
    public:
        asyncResolveTxt(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_txt, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_txt, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolveTxt* pThis = (asyncResolveTxt*)arg;
            struct ares_txt_ext* txt_out;

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_txt_reply_ext(abuf, alen, &txt_out);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int32_t len;
            obj_ptr<NArray> txt_result = new NArray();
            for (struct ares_txt_ext* current = txt_out; current != nullptr; current = current->next) {
                if (current->record_start) {
                    txt_result->get_length(len);
                    if (len > 0) {
                        pThis->m_retVal->append(txt_result);
                    }

                    txt_result = new NArray();
                }

                txt_result->append((char*)current->txt);
            }

            txt_result->get_length(len);
            if (len > 0) {
                pThis->m_retVal->append(txt_result);
            }
            ares_free_data(txt_out);
            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NArray> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();
    return (new asyncResolveTxt(host, retVal, ac, m_lockRead))->call();
}

result_t DnsClient::resolveSrv(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    class asyncResolveSrv : public asyncDNSQuery {
    public:
        class ResolveSrvResult : public NObject {
        public:
            ResolveSrvResult(ares_srv_reply* srv_reply)
            {
                add("name", srv_reply->host);
                add("port", srv_reply->port);
                add("priority", srv_reply->priority);
                add("weight", srv_reply->weight);
            }
        };

    public:
        asyncResolveSrv(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_srv, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_srv, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolveSrv* pThis = (asyncResolveSrv*)arg;
            struct ares_srv_reply* srv_start;

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_srv_reply(abuf, alen, &srv_start);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            for (struct ares_srv_reply* current = srv_start; current != nullptr; current = current->next) {
                pThis->m_retVal->append(new ResolveSrvResult(current));
            }
            ares_free_data(srv_start);

            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NArray> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();
    return (new asyncResolveSrv(host, retVal, ac, m_lockRead))->call();
}

result_t DnsClient::resolveMx(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    class asyncResolveMx : public asyncDNSQuery {
    public:
        class ResolveMxResult : public NObject {
        public:
            ResolveMxResult(ares_mx_reply* mx_reply)
            {
                add("exchange", mx_reply->host);
                add("priority", mx_reply->priority);
            }
        };

    public:
        asyncResolveMx(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac, exlib::Locker& locker)
            : asyncDNSQuery(ac, locker)
            , m_errorno(0)
            , m_cbAsync(true)
            , m_cbSync(true)
            , m_host(host)
            , m_retVal(retVal)
        {
        }

        virtual result_t process()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_mx, callback, this);
            if (!m_cbAsync) {
                if (m_errorno != 0)
                    return CHECK_ERROR(Runtime::setError(ares_strerror(m_errorno)));
                return 0;
            }

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CHECK_ERROR(CALL_E_PENDDING);
        }

        virtual result_t process2()
        {
            ares_query(s_aresChannel.m_channel, m_host.c_str(), ns_c_in, ns_t_mx, callback, this);
            if (!m_cbAsync)
                onready();

            m_cbSync = false;
            s_aresChannel.m_sem.post();
            return CALL_E_PENDDING;
        }

        virtual void proc()
        {
            if (m_errorno != 0)
                ready(Runtime::setError(ares_strerror(m_errorno)));
            else {
                ready(0);
            }
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            asyncResolveMx* pThis = (asyncResolveMx*)arg;
            struct ares_mx_reply* mx_reply = nullptr;

            pThis->m_cbAsync = false;
            if (status != ARES_SUCCESS) {
                pThis->m_errorno = status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            int rs_status = ares_parse_mx_reply(abuf, alen, &mx_reply);
            if (rs_status != ARES_SUCCESS) {
                pThis->m_errorno = rs_status;
                if (pThis->m_cbSync)
                    return;
                pThis->onready();
                return;
            }

            for (struct ares_mx_reply* current = mx_reply; current != nullptr; current = current->next) {
                pThis->m_retVal->append(new ResolveMxResult(current));
            }
            ares_free_data(mx_reply);

            if (pThis->m_cbSync)
                return;
            pThis->onready();
        }

    public:
        int32_t m_errorno;
        bool m_cbAsync;
        bool m_cbSync;
        exlib::string m_host;
        obj_ptr<NArray> m_retVal;
    };

    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();
    return (new asyncResolveMx(host, retVal, ac, m_lockRead))->call();
}
result_t DnsClient::resolveAny(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    result_t hr;
    if (ac->isSync())
        return CHECK_ERROR(CALL_E_NOSYNC);

    retVal = new NArray();

    obj_ptr<NArray> retVal4 = new NArray();
    hr = cc_resolve4(host, retVal4);
    if (hr < 0)
        return hr;
    return 0;
}
}