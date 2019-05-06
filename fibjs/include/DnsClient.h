/*
 * DnsClient.h
 *
 *  Created on: Aug 16, 2017
 *      Author: Rube
 */

#ifndef DNSCLIENT_H_
#define DNSCLIENT_H_

#include "ifs/DnsClient.h"

namespace fibjs {

class DnsClient : public DnsClient_base {
    FIBER_FREE();

public:
    class ResolveResult : public NObject {
    public:
        ResolveResult(int ttl, exlib::string ip)
        {
            add("address", ip);
            add("ttl", ttl);
        }
    };

public:
    virtual result_t resolve(exlib::string host, exlib::string type, Variant& retVal, AsyncEvent* ac);
    virtual result_t resolve4(exlib::string host, v8::Local<v8::Object> options, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolve4(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolve6(exlib::string host, v8::Local<v8::Object> options, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolve6(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolveAny(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolveMx(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolveTxt(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolveSrv(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolveSoa(exlib::string host, obj_ptr<NObject>& retVal, AsyncEvent* ac);
    virtual result_t resolveNs(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolveCname(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolveNaptr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    virtual result_t resolvePtr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);

private:
    result_t resolve4(exlib::string host, bool ttl, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    result_t resolve6(exlib::string host, bool ttl, obj_ptr<NArray>& retVal, AsyncEvent* ac);

private:
    exlib::Locker m_lockRead;
};
}

#endif //DNSCLIENT_H_
