/***************************************************************************
 *                                                                         *
 *   This file was automatically generated using idlc.js                   *
 *   PLEASE DO NOT EDIT!!!!                                                *
 *                                                                         *
 ***************************************************************************/

#ifndef _dns_base_H_
#define _dns_base_H_

/**
 @author Leo Hoo <lion@9465.net>
 */

#include "../object.h"

namespace fibjs {

class DnsClient_base;

class dns_base : public object_base {
    DECLARE_CLASS(dns_base);

public:
    // dns_base
    static result_t resolve(exlib::string host, exlib::string type, Variant& retVal, AsyncEvent* ac);
    static result_t resolve4(exlib::string host, v8::Local<v8::Object> options, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    static result_t resolve6(exlib::string host, v8::Local<v8::Object> options, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    static result_t resolveAny(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    static result_t resolveMx(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    static result_t resolveTxt(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    static result_t resolveSrv(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    static result_t resolveSoa(exlib::string host, obj_ptr<NObject>& retVal, AsyncEvent* ac);
    static result_t resolveNs(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    static result_t resolveCname(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    static result_t resolveNaptr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);
    static result_t resolvePtr(exlib::string host, obj_ptr<NArray>& retVal, AsyncEvent* ac);

public:
    static void s__new(const v8::FunctionCallbackInfo<v8::Value>& args)
    {
        CONSTRUCT_INIT();

        Isolate* isolate = Isolate::current();

        isolate->m_isolate->ThrowException(
            isolate->NewString("not a constructor"));
    }

public:
    static void s_resolve(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolve4(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolve6(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolveAny(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolveMx(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolveTxt(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolveSrv(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolveSoa(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolveNs(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolveCname(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolveNaptr(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_resolvePtr(const v8::FunctionCallbackInfo<v8::Value>& args);

public:
    ASYNC_STATICVALUE3(dns_base, resolve, exlib::string, exlib::string, Variant);
    ASYNC_STATICVALUE3(dns_base, resolve4, exlib::string, v8::Local<v8::Object>, obj_ptr<NArray>);
    ASYNC_STATICVALUE3(dns_base, resolve6, exlib::string, v8::Local<v8::Object>, obj_ptr<NArray>);
    ASYNC_STATICVALUE2(dns_base, resolveAny, exlib::string, obj_ptr<NArray>);
    ASYNC_STATICVALUE2(dns_base, resolveMx, exlib::string, obj_ptr<NArray>);
    ASYNC_STATICVALUE2(dns_base, resolveTxt, exlib::string, obj_ptr<NArray>);
    ASYNC_STATICVALUE2(dns_base, resolveSrv, exlib::string, obj_ptr<NArray>);
    ASYNC_STATICVALUE2(dns_base, resolveSoa, exlib::string, obj_ptr<NObject>);
    ASYNC_STATICVALUE2(dns_base, resolveNs, exlib::string, obj_ptr<NArray>);
    ASYNC_STATICVALUE2(dns_base, resolveCname, exlib::string, obj_ptr<NArray>);
    ASYNC_STATICVALUE2(dns_base, resolveNaptr, exlib::string, obj_ptr<NArray>);
    ASYNC_STATICVALUE2(dns_base, resolvePtr, exlib::string, obj_ptr<NArray>);
};
}

#include "ifs/DnsClient.h"

namespace fibjs {
inline ClassInfo& dns_base::class_info()
{
    static ClassData::ClassMethod s_method[] = {
        { "resolve", s_resolve, true },
        { "resolveSync", s_resolve, true },
        { "resolve4", s_resolve4, true },
        { "resolve4Sync", s_resolve4, true },
        { "resolve6", s_resolve6, true },
        { "resolve6Sync", s_resolve6, true },
        { "resolveAny", s_resolveAny, true },
        { "resolveAnySync", s_resolveAny, true },
        { "resolveMx", s_resolveMx, true },
        { "resolveMxSync", s_resolveMx, true },
        { "resolveTxt", s_resolveTxt, true },
        { "resolveTxtSync", s_resolveTxt, true },
        { "resolveSrv", s_resolveSrv, true },
        { "resolveSrvSync", s_resolveSrv, true },
        { "resolveSoa", s_resolveSoa, true },
        { "resolveSoaSync", s_resolveSoa, true },
        { "resolveNs", s_resolveNs, true },
        { "resolveNsSync", s_resolveNs, true },
        { "resolveCname", s_resolveCname, true },
        { "resolveCnameSync", s_resolveCname, true },
        { "resolveNaptr", s_resolveNaptr, true },
        { "resolveNaptrSync", s_resolveNaptr, true },
        { "resolvePtr", s_resolvePtr, true },
        { "resolvePtrSync", s_resolvePtr, true }
    };

    static ClassData::ClassObject s_object[] = {
        { "Resolver", DnsClient_base::class_info }
    };

    static ClassData s_cd = {
        "dns", true, s__new, NULL,
        ARRAYSIZE(s_method), s_method, ARRAYSIZE(s_object), s_object, 0, NULL, 0, NULL, NULL, NULL,
        &object_base::class_info()
    };

    static ClassInfo s_ci(s_cd);
    return s_ci;
}

inline void dns_base::s_resolve(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    Variant vr;

    METHOD_NAME("dns.resolve");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(2, 1);

    ARG(exlib::string, 0);
    OPT_ARG(exlib::string, 1, "A");

    if (!cb.IsEmpty()) {
        acb_resolve(v0, v1, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolve(v0, v1, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolve4(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolve4");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(2, 1);

    ARG(exlib::string, 0);
    OPT_ARG(v8::Local<v8::Object>, 1, v8::Object::New(isolate));

    if (!cb.IsEmpty()) {
        acb_resolve4(v0, v1, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolve4(v0, v1, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolve6(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolve6");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(2, 1);

    ARG(exlib::string, 0);
    OPT_ARG(v8::Local<v8::Object>, 1, v8::Object::New(isolate));

    if (!cb.IsEmpty()) {
        acb_resolve6(v0, v1, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolve6(v0, v1, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolveAny(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolveAny");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    if (!cb.IsEmpty()) {
        acb_resolveAny(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolveAny(v0, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolveMx(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolveMx");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    if (!cb.IsEmpty()) {
        acb_resolveMx(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolveMx(v0, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolveTxt(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolveTxt");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    if (!cb.IsEmpty()) {
        acb_resolveTxt(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolveTxt(v0, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolveSrv(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolveSrv");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    if (!cb.IsEmpty()) {
        acb_resolveSrv(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolveSrv(v0, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolveSoa(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NObject> vr;

    METHOD_NAME("dns.resolveSoa");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    if (!cb.IsEmpty()) {
        acb_resolveSoa(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolveSoa(v0, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolveNs(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolveNs");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    if (!cb.IsEmpty()) {
        acb_resolveNs(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolveNs(v0, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolveCname(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolveCname");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    if (!cb.IsEmpty()) {
        acb_resolveCname(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolveCname(v0, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolveNaptr(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolveNaptr");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    if (!cb.IsEmpty()) {
        acb_resolveNaptr(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolveNaptr(v0, vr);

    METHOD_RETURN();
}

inline void dns_base::s_resolvePtr(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<NArray> vr;

    METHOD_NAME("dns.resolvePtr");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    if (!cb.IsEmpty()) {
        acb_resolvePtr(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_resolvePtr(v0, vr);

    METHOD_RETURN();
}
}

#endif
