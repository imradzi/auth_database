#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#ifdef _WIN32
#include "winsock2.h"
#endif

#ifdef __clang__
#if __has_warning("-Wdeprecated-enum-enum-conversion")
#pragma clang diagnostic ignored "-Wdeprecated-enum-enum-conversion"  // warning: bitwise operation between different enumeration types ("XXXFlags_" and "XXXFlagsPrivate_") is deprecated
#endif
#endif

#ifdef __WX__
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif
#include "wx/tokenzr.h"
#endif
#ifdef _USEPOSTGRESQL
#undef _USEPOSTGRESQL
#endif

#include "authDB.h"
#include "timefunctions.h"
using namespace std::chrono_literals;

bool AuthorizationDB::IsClientTokenExists(const std::string& email) {
    LOG_INFO("AuthorizationDB::IsClientTokenExists - enter");
    auto stt = GetSession().PrepareStatement("delete from idTokens where dateChecked < ?");
    stt->Bind(1, std::chrono::system_clock::now() - 24h);
    stt->ExecuteUpdate();

    stt = GetSession().PrepareStatement("select * from idTokens where email= ?");
    stt->Bind(1, email);
    auto rs = stt->ExecuteQuery();
    if (rs->NextRow()) {
        return true;
    }
    return false;
}

bool AuthorizationDB::IsValidClientToken(const std::string& token, const std::string& email) {
    if (IsClientTokenExists(email)) return true;

    if (CheckClientToken(token, email)) {
        auto stt = GetSession().PrepareStatement("replace into idTokens(email, dateChecked) values(@email, @date)");
        stt->Bind("@email", email);
        stt->Bind("@date", std::chrono::system_clock::now());
        stt->ExecuteUpdate();
        LOG_INFO("AuthorizationDB::IsValidClientToken - update the cache");
        return true;
    }
    LOG_INFO("CheckClientToken - return FALSE (email={})", email);
    return false;
}

//  - result from validate token
// {
// 'name': 'Mohd Radzi Ibrahim',
// 'iss': 'https://securetoken.google.com/his-id',
// 'aud': 'his-id',
// 'auth_time': 1709717261,
// 'user_id': 'T34QpBU7lSeIqly4sEL8lGCvj0T2',
// 'sub': 'T34QpBU7lSeIqly4sEL8lGCvj0T2',
// 'iat': 1709720824,
// 'exp': 1709724424,
// 'email': 'imradzi@gmail.com',
// 'email_verified': True,
// 'firebase': {
//   'identities': {
//     'email': ['imradzi@gmail.com']
//     },
//     'sign_in_provider': 'password'
//     },
//     'uid': 'T34QpBU7lSeIqly4sEL8lGCvj0T2'
//   }
