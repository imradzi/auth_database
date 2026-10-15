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
#include <chrono>
#include <string>

#include "authDB.h"
using namespace std::chrono_literals;

bool AuthorizationDB::CheckClientToken(const std::string& idToken, const std::string& email) {
    LOG_INFO("CheckClientToken - Verifying token for email: {}", email);
    
    // Use shared lazy-initialized Firebase verifier
    if (!EnsureFirebaseVerifier()) {
        return false;
    }
    
    // Call Firebase Admin API to verify the token
    auto [success, verified_email] = sFirebaseVerifier->VerifyIdToken(idToken, email);
    
    if (!success) {
        LOG_ERROR("CheckClientToken - Firebase verification failed: {}", verified_email);
        return false;
    }
    
    // Verify the returned email matches expected email
    bool result = (verified_email == email || email.empty()); // or no check with email
    if (result) {
        LOG_INFO("CheckClientToken - Token verified successfully for email: {}", email);
    } else {
        LOG_ERROR("CheckClientToken - Email mismatch: {} != {}", verified_email, email);
    }
    return result;
}
