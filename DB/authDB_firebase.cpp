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
#pragma clang diagnostic ignored "-Wdeprecated-enum-enum-conversion"
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
#include "logger/logger.h"
#include <algorithm>

/**
 * Initialize Firebase Admin SDK and verify ID token with Firebase
 * 
 * This method:
 * 1. Lazy-loads the FirebaseAdminTokenVerifier from service account JSON
 * 2. Calls Firebase Admin API to verify the ID token
 * 3. Caches positive verification results in SQLite (idTokens table)
 * 4. Returns true if token is valid, false otherwise
 */
bool AuthorizationDB::VerifyFirebaseIdToken(const std::string& idToken, const std::string& email) {
    LOG_INFO("AuthorizationDB::VerifyFirebaseIdToken - Verifying token for email: {}", email);
    
    try {
        // Initialize Firebase verifier on first use (lazy loading)
        if (!firebaseVerifier) {
            auto credFilePath = GetRegistry()->GetKey("app_firebase_admin_credential_json_file");
            
            if (credFilePath.empty()) {
                LOG_ERROR("AuthorizationDB::VerifyFirebaseIdToken - Firebase credential path not configured in registry");
                return false;
            }
            
            try {
                firebaseVerifier = std::make_shared<FirebaseAdminTokenVerifier>(credFilePath);
                LOG_INFO("AuthorizationDB::VerifyFirebaseIdToken - Firebase verifier initialized");
            } catch (const std::exception& e) {
                LOG_ERROR("AuthorizationDB::VerifyFirebaseIdToken - Failed to initialize Firebase verifier: {}", 
                         e.what());
                return false;
            }
        }

        // Call Firebase Admin API to verify the token
        auto [success, result] = firebaseVerifier->VerifyIdToken(idToken, email);
        
        if (!success) {
            LOG_ERROR("AuthorizationDB::VerifyFirebaseIdToken - Firebase verification failed: {}", result);
            return false;
        }

        // Cache the verified token in SQLite
        // Use the idTokens table (already has email and dateChecked columns)
        try {
            auto stt = GetSession().PrepareStatement(
                "replace into idTokens(email, dateChecked) values(@email, @date)");
            stt->Bind("@email", email);
            stt->Bind("@date", std::chrono::system_clock::now());
            stt->ExecuteUpdate();
            
            LOG_INFO("AuthorizationDB::VerifyFirebaseIdToken - Token cached for email: {}", email);
        } catch (const std::exception& e) {
            LOG_WARN("AuthorizationDB::VerifyFirebaseIdToken - Failed to cache token: {}", e.what());
            // Don't fail the verification just because caching failed
            // The user is authenticated, just can't benefit from cache next time
        }

        LOG_INFO("AuthorizationDB::VerifyFirebaseIdToken - Token verification successful, verified email: {}", 
                 result);
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR("AuthorizationDB::VerifyFirebaseIdToken - Exception: {}", e.what());
        return false;
    } catch (...) {
        LOG_ERROR("AuthorizationDB::VerifyFirebaseIdToken - Unknown exception");
        return false;
    }
}
