/***************************************************************************
 *                                                                         *
 *   This file was automatically generated using idlc.js                   *
 *   PLEASE DO NOT EDIT!!!!                                                *
 *                                                                         *
 ***************************************************************************/

#ifndef _RbdImage_base_H_
#define _RbdImage_base_H_

/**
 @author Leo Hoo <lion@9465.net>
 */

#include "../object.h"
#include "SeekableStream.h"

namespace fibjs {

class SeekableStream_base;

class RbdImage_base : public SeekableStream_base {
    DECLARE_CLASS(RbdImage_base);

public:
    // RbdImage_base
    virtual result_t get_size(int64_t& retVal) = 0;
    virtual result_t get_stripe_unit(int64_t& retVal) = 0;
    virtual result_t get_stripe_count(int64_t& retVal) = 0;
    virtual result_t get_features(int64_t& retVal) = 0;
    virtual result_t get_create_timestamp(date_t& retVal) = 0;
    virtual result_t get_block_name_prefix(exlib::string& retVal) = 0;
    virtual result_t resize(int64_t bytes, AsyncEvent* ac) = 0;
    virtual result_t flush(AsyncEvent* ac) = 0;

public:
    static void s__new(const v8::FunctionCallbackInfo<v8::Value>& args)
    {
        CONSTRUCT_INIT();

        Isolate* isolate = Isolate::current();

        isolate->m_isolate->ThrowException(
            isolate->NewFromUtf8("not a constructor"));
    }

public:
    static void s_get_size(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args);
    static void s_get_stripe_unit(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args);
    static void s_get_stripe_count(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args);
    static void s_get_features(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args);
    static void s_get_create_timestamp(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args);
    static void s_get_block_name_prefix(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args);
    static void s_resize(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_flush(const v8::FunctionCallbackInfo<v8::Value>& args);

public:
    ASYNC_MEMBER1(RbdImage_base, resize, int64_t);
    ASYNC_MEMBER0(RbdImage_base, flush);
};
}

namespace fibjs {
inline ClassInfo& RbdImage_base::class_info()
{
    static ClassData::ClassMethod s_method[] = {
        { "resize", s_resize, false },
        { "flush", s_flush, false }
    };

    static ClassData::ClassProperty s_property[] = {
        { "size", s_get_size, block_set, false },
        { "stripe_unit", s_get_stripe_unit, block_set, false },
        { "stripe_count", s_get_stripe_count, block_set, false },
        { "features", s_get_features, block_set, false },
        { "create_timestamp", s_get_create_timestamp, block_set, false },
        { "block_name_prefix", s_get_block_name_prefix, block_set, false }
    };

    static ClassData s_cd = {
        "RbdImage", false, s__new, NULL,
        ARRAYSIZE(s_method), s_method, 0, NULL, ARRAYSIZE(s_property), s_property, NULL, NULL,
        &SeekableStream_base::class_info()
    };

    static ClassInfo s_ci(s_cd);
    return s_ci;
}

inline void RbdImage_base::s_get_size(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args)
{
    int64_t vr;

    METHOD_INSTANCE(RbdImage_base);
    PROPERTY_ENTER();

    hr = pInst->get_size(vr);

    METHOD_RETURN();
}

inline void RbdImage_base::s_get_stripe_unit(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args)
{
    int64_t vr;

    METHOD_INSTANCE(RbdImage_base);
    PROPERTY_ENTER();

    hr = pInst->get_stripe_unit(vr);

    METHOD_RETURN();
}

inline void RbdImage_base::s_get_stripe_count(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args)
{
    int64_t vr;

    METHOD_INSTANCE(RbdImage_base);
    PROPERTY_ENTER();

    hr = pInst->get_stripe_count(vr);

    METHOD_RETURN();
}

inline void RbdImage_base::s_get_features(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args)
{
    int64_t vr;

    METHOD_INSTANCE(RbdImage_base);
    PROPERTY_ENTER();

    hr = pInst->get_features(vr);

    METHOD_RETURN();
}

inline void RbdImage_base::s_get_create_timestamp(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args)
{
    date_t vr;

    METHOD_INSTANCE(RbdImage_base);
    PROPERTY_ENTER();

    hr = pInst->get_create_timestamp(vr);

    METHOD_RETURN();
}

inline void RbdImage_base::s_get_block_name_prefix(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& args)
{
    exlib::string vr;

    METHOD_INSTANCE(RbdImage_base);
    PROPERTY_ENTER();

    hr = pInst->get_block_name_prefix(vr);

    METHOD_RETURN();
}

inline void RbdImage_base::s_resize(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    METHOD_INSTANCE(RbdImage_base);
    METHOD_ENTER();

    ASYNC_METHOD_OVER(1, 1);

    ARG(int64_t, 0);

    if (!cb.IsEmpty()) {
        pInst->acb_resize(v0, cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = pInst->ac_resize(v0);

    METHOD_VOID();
}

inline void RbdImage_base::s_flush(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    METHOD_INSTANCE(RbdImage_base);
    METHOD_ENTER();

    ASYNC_METHOD_OVER(0, 0);

    if (!cb.IsEmpty()) {
        pInst->acb_flush(cb);
        hr = CALL_RETURN_NULL;
    } else
        hr = pInst->ac_flush();

    METHOD_VOID();
}
}

#endif
