/*
 * dns.cpp
 *
 *  Created on: Aug 15, 2017
 *      Author: Rube
 */

#include "ifs/dns.h"
#include "DnsClient.h"

namespace fibjs {
DECLARE_MODULE(dns);

static DnsClient* get_DnsClient(Isolate* isolate = NULL)
{
    if (isolate == NULL)
        isolate = Isolate::current();

    if (!isolate->m_dnsclient)
        isolate->m_dnsclient = new DnsClient();
    return (DnsClient*)(obj_base*)isolate->m_dnsclient;
}

result_t dns_base::resolve(exlib::string host, exlib::string type, Variant& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolve(host, type, retVal, ac);
}

result_t dns_base::resolve4(exlib::string host, v8::Local<v8::Object> options, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolve4(host, options, retVal, ac);
}

result_t dns_base::resolve6(exlib::string host, v8::Local<v8::Object> options, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolve6(host, options, retVal, ac);
}

result_t dns_base::resolveSrv(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolveSrv(host, retVal, ac);
}

result_t dns_base::resolveMx(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolveMx(host, retVal, ac);
}

result_t dns_base::resolveTxt(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolveTxt(host, retVal, ac);
}

result_t dns_base::resolveSoa(exlib::string host, obj_ptr<NObject>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolveSoa(host, retVal, ac);
}

result_t dns_base::resolvePtr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolvePtr(host, retVal, ac);
}

result_t dns_base::resolveNs(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolveNs(host, retVal, ac);
}

result_t dns_base::resolveNaptr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolveNaptr(host, retVal, ac);
}

result_t dns_base::resolveCname(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolveCname(host, retVal, ac);
}
result_t dns_base::resolveAny(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac)
{
    return get_DnsClient(ac->isolate())->resolveAny(host, retVal, ac);
}
}