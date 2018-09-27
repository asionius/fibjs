/***************************************************************************
 *                                                                         *
 *   This file was automatically generated using idlc.js                   *
 *   PLEASE DO NOT EDIT!!!!                                                *
 *                                                                         *
 ***************************************************************************/

#ifndef _rados_base_H_
#define _rados_base_H_

/**
 @author Leo Hoo <lion@9465.net>
 */

#include "../object.h"

namespace fibjs {

class RadosCluster_base;

class rados_base : public object_base {
    DECLARE_CLASS(rados_base);

public:
    // rados_base
    static result_t create(exlib::string clusterName, exlib::string userName, exlib::string confPath, obj_ptr<RadosCluster_base>& retVal, AsyncEvent* ac);

public:
    static void s__new(const v8::FunctionCallbackInfo<v8::Value>& args)
    {
        CONSTRUCT_INIT();

        Isolate* isolate = Isolate::current();

        isolate->m_isolate->ThrowException(
            isolate->NewString("not a constructor"));
    }

public:
    static void s_create(const v8::FunctionCallbackInfo<v8::Value>& args);

public:
    ASYNC_STATICVALUE4(rados_base, create, exlib::string, exlib::string, exlib::string, obj_ptr<RadosCluster_base>);
};
}

#include "RadosCluster.h"

namespace fibjs {
inline ClassInfo& rados_base::class_info()
{
    static ClassData::ClassMethod s_method[] = {
        { "create", s_create, true },
        { "createSync", s_create, true }
    };

    static ClassData s_cd = {
        "rados", true, s__new, NULL,
        ARRAYSIZE(s_method), s_method, 0, NULL, 0, NULL, 0, NULL, NULL, NULL,
        &object_base::class_info()
    };

    static ClassInfo s_ci(s_cd);
    return s_ci;
}

inline void rados_base::s_create(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<RadosCluster_base> vr;

    METHOD_NAME("rados.create");
    METHOD_ENTER();

    ASYNC_METHOD_OVER(3, 3);

    ARG(exlib::string, 0);
    ARG(exlib::string, 1);
    ARG(exlib::string, 2);

    if (!cb.IsEmpty()) {
        acb_create(v0, v1, v2, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = ac_create(v0, v1, v2, vr);

    METHOD_RETURN();
}
}

#endif
