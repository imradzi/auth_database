// Firebase ID-token verification — keyless mode.
//
// Calls Identity Toolkit `accounts:lookup` with the project's PUBLIC web API
// key. Google validates the token server-side (the same mechanism Firebase
// client SDKs use), so no service-account credential is needed on ppServer
// installs. See docs/keyless-firebase-verification-plan.md.

#include "FirebaseAdminTokenVerifier.h"
#include "FirebasePublicConfig.h"
#include "logger/logger.h"
#include "beast/webclient.h"

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>

namespace {

/** Map Identity Toolkit error codes to friendlier messages. */
std::string FriendlyVerifyError(const std::string& code) {
    if (code == "INVALID_ID_TOKEN") return "Invalid or expired token";
    if (code == "USER_DISABLED") return "User account is disabled";
    if (code == "USER_NOT_FOUND") return "User not found";
    return code;
}

/** Extract error.message from an identitytoolkit error response body. */
std::string ExtractErrorCode(const std::string& response) {
    try {
        auto j = json::parse(response);
        if (j.contains("error") && j["error"].is_object() && j["error"].contains("message")) {
            return j["error"]["message"].get<std::string>();
        }
    } catch (...) {
        // response isn't JSON — fall through to the generic message
    }
    return "";
}

}  // namespace

/**
 * Constructor — keyless mode; no credentials to load.
 */
FirebaseAdminTokenVerifier::FirebaseAdminTokenVerifier() {
    LOG_INFO("FirebaseAdminTokenVerifier::Constructor - keyless mode (accounts:lookup via public web API key)");
}

/**
 * Verify an ID token with the Firebase Identity Toolkit (keyless).
 *
 * POSTs to accounts:lookup with the project's public web API key; Google
 * validates the token server-side and returns the account record.
 */
std::tuple<bool, std::string> FirebaseAdminTokenVerifier::VerifyIdToken(const std::string& idToken, const std::string& expectedEmail) {
    try {
        if (idToken.empty()) {
            LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Empty ID token provided");
            return {false, "Empty ID token"};
        }

        const std::string url = fmt::format(
            "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={}",
            FirebasePublicConfig::webApiKey);

        json requestBody = {
            {"idToken", idToken}
        };

        std::unordered_map<std::string, std::string> headers;
        headers["Content-Type"] = "application/json";

        LOG_INFO("FirebaseAdminTokenVerifier::VerifyIdToken - Calling Firebase accounts:lookup");

        auto [response, statusCode] = WebClient::Post(url, requestBody.dump(), headers);

        if (statusCode != 200) {
            std::string code = ExtractErrorCode(response);
            std::string error = code.empty() ? fmt::format("Firebase API error ({})", statusCode)
                                             : FriendlyVerifyError(code);
            LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Firebase API returned status: {} error: {}", statusCode, error);
            return {false, error};
        }

        // Parse response
        try {
            json responseJson = json::parse(response);

            // accounts:lookup returns {"kind":..., "users":[{...}]} for a valid token
            if (!responseJson.contains("users") || !responseJson["users"].is_array() || responseJson["users"].empty()) {
                LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - No users in response");
                return {false, "User not found in Firebase response"};
            }

            auto user = responseJson["users"][0];
            if (!user.contains("email")) {
                LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - No email in response");
                return {false, "Email not found in Firebase response"};
            }

            std::string verifiedEmail = user["email"].get<std::string>();
            if (!expectedEmail.empty() && verifiedEmail != expectedEmail) {
                LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Email mismatch: {} != {}", verifiedEmail, expectedEmail);
                return {false, fmt::format("expected email {}", verifiedEmail)};
            }

            LOG_INFO("FirebaseAdminTokenVerifier::VerifyIdToken - Token verified for: {}", verifiedEmail);
            return {true, verifiedEmail};

        } catch (const json::exception& e) {
            LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - JSON parse error: {}", e.what());
            return {false, "Invalid Firebase response format"};
        }

    } catch (const std::exception& e) {
        LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Exception: {}", e.what());
        return {false, fmt::format("Exception: {}", e.what())};
    } catch (...) {
        LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Unknown exception");
        return {false, "Unknown error"};
    }
}
