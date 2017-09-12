/***************************************************************************
 *                                                                         *
 *   This file was automatically generated using idlc.js                   *
 *   PLEASE DO NOT EDIT!!!!                                                *
 *                                                                         *
 ***************************************************************************/

#ifndef _HsRegExp_base_H_
#define _HsRegExp_base_H_

/**
 @author Leo Hoo <lion@9465.net>
 */

#include "../object.h"

namespace fibjs {

class HsRegExp_base : public object_base {
    DECLARE_CLASS(HsRegExp_base);

public:
    // HsRegExp_base
    virtual result_t scan(exlib::string text, v8::Local<v8::Value>& retVal) = 0;

public:
    static void s__new(const v8::FunctionCallbackInfo<v8::Value>& args)
    {
        CONSTRUCT_INIT();

        Isolate* isolate = Isolate::current();

        isolate->m_isolate->ThrowException(
            isolate->NewString("not a constructor"));
    }

public:
    static void s_scan(const v8::FunctionCallbackInfo<v8::Value>& args);
};
}

namespace fibjs {
inline ClassInfo& HsRegExp_base::class_info()
{
    static ClassData::ClassMethod s_method[] = {
        { "scan", s_scan, false }
    };

    static ClassData s_cd = {
        "HsRegExp", false, s__new, NULL,
        ARRAYSIZE(s_method), s_method, 0, NULL, 0, NULL, NULL, NULL,
        &object_base::class_info()
    };

    static ClassInfo s_ci(s_cd);
    return s_ci;
}

inline void HsRegExp_base::s_scan(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    v8::Local<v8::Value> vr;

    METHOD_INSTANCE(HsRegExp_base);
    METHOD_ENTER();

    METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    hr = pInst->scan(v0, vr);

    METHOD_RETURN();
}
}

#endif
