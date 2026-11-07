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
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

namespace {

// Tunables (env overrides keep production/regression runs flexible).
// The cache is positive-only: entries are created after Google accepted the
// token, and the TTL is additionally capped by the JWT's own `exp` claim.
constexpr int kDefaultCacheTtlSeconds = 300;
constexpr size_t kDefaultCacheMaxEntries = 1024;

int CacheTtlSeconds() {
    static const int value = [] {
        const char* env = std::getenv("PPOS_FIREBASE_TOKEN_CACHE_TTL_SEC");
        const int parsed = env ? std::atoi(env) : 0;
        if (parsed < 30 || parsed > 1800) return kDefaultCacheTtlSeconds;
        return parsed;
    }();
    return value;
}

size_t CacheMaxEntries() {
    static const size_t value = [] {
        const char* env = std::getenv("PPOS_FIREBASE_TOKEN_CACHE_MAX");
        const long parsed = env ? std::atol(env) : 0;
        if (parsed < 64 || parsed > 8192) return kDefaultCacheMaxEntries;
        return static_cast<size_t>(parsed);
    }();
    return value;
}

/** Decode standard base64url (JWT alphabet, padding optional). */
std::string Base64UrlDecode(const std::string& input) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(input.size() * 3 / 4);
    int buffer = 0;
    int bits = -8;
    for (char c : input) {
        if (c == '=') break;
        const char* pos = std::strchr(kAlphabet, c);
        if (pos == nullptr) continue;  // tolerate stray whitespace
        buffer = (buffer << 6) + static_cast<int>(pos - kAlphabet);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

/**
 * Read the unverified `exp` claim from a JWT. This is only used to bound the
 * cache TTL — the token itself is still verified by Google before caching.
 * Returns 0 when the claim cannot be decoded.
 */
int64_t JwtExpiryEpochSeconds(const std::string& jwt) {
    const size_t firstDot = jwt.find('.');
    if (firstDot == std::string::npos) return 0;
    const size_t secondDot = jwt.find('.', firstDot + 1);
    if (secondDot == std::string::npos) return 0;
    const std::string payload =
        Base64UrlDecode(jwt.substr(firstDot + 1, secondDot - firstDot - 1));
    if (payload.empty()) return 0;
    const json claims = json::parse(payload, nullptr, false);
    if (claims.is_discarded() || !claims.is_object()) return 0;
    const auto it = claims.find("exp");
    if (it == claims.end() || !it->is_number_integer()) return 0;
    return it->get<int64_t>();
}

/** Cache lifetime for a freshly verified token (never past its own expiry). */
std::chrono::seconds CacheLifetimeFor(const std::string& idToken) {
    int ttl = CacheTtlSeconds();
    const int64_t exp = JwtExpiryEpochSeconds(idToken);
    if (exp > 0) {
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
        const int64_t remaining = exp - now - 30;  // stop serving before expiry
        if (remaining <= 0) return std::chrono::seconds(0);
        ttl = static_cast<int>(std::min<int64_t>(ttl, remaining));
    }
    return std::chrono::seconds(ttl);
}

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

        // Fast path: a token Google already accepted recently can be reused.
        // Positive-only and bounded; expectedEmail is re-checked on every hit.
        {
            std::lock_guard<std::mutex> lock(cacheMutex_);
            const auto it = cache_.find(idToken);
            if (it != cache_.end()) {
                if (std::chrono::steady_clock::now() < it->second.expiresAt) {
                    if (!expectedEmail.empty() && it->second.email != expectedEmail) {
                        LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Email mismatch (cached): {} != {}",
                                  it->second.email, expectedEmail);
                        return {false, fmt::format("expected email {}", it->second.email)};
                    }
                    LOG_DEBUG("FirebaseAdminTokenVerifier::VerifyIdToken - Cache hit for {}",
                              it->second.email);
                    return {true, it->second.email};
                }
                cache_.erase(it);
            }
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

            // Remember the successful verification. Never log the token.
            const auto lifetime = CacheLifetimeFor(idToken);
            if (lifetime.count() > 0) {
                std::lock_guard<std::mutex> lock(cacheMutex_);
                const size_t maxEntries = CacheMaxEntries();
                while (cache_.size() >= maxEntries && !cacheOrder_.empty()) {
                    cache_.erase(cacheOrder_.front());
                    cacheOrder_.pop_front();
                }
                // Bound the FIFO even when entries expire before being reused.
                while (cacheOrder_.size() > maxEntries * 4 && !cacheOrder_.empty()) {
                    cache_.erase(cacheOrder_.front());
                    cacheOrder_.pop_front();
                }
                const auto [it, inserted] = cache_.try_emplace(
                    idToken, CacheEntry{verifiedEmail,
                                        std::chrono::steady_clock::now() + lifetime});
                if (!inserted) {
                    it->second = CacheEntry{verifiedEmail,
                                            std::chrono::steady_clock::now() + lifetime};
                } else {
                    cacheOrder_.push_back(idToken);
                }
            }

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

size_t FirebaseAdminTokenVerifier::CacheSize() const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    return cache_.size();
}

void FirebaseAdminTokenVerifier::ClearCache() {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cache_.clear();
    cacheOrder_.clear();
}
