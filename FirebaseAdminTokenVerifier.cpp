#include "FirebaseAdminTokenVerifier.h"
#include "logger/logger.h"
#include "beast/webclient.h"

#include <fstream>
#include <fmt/format.h>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <cstring>

// Firebase Admin API endpoint for ID token verification
const std::string FirebaseAdminTokenVerifier::FIREBASE_API_ENDPOINT = 
    "https://identitytoolkit.googleapis.com/v1/accounts:lookup";

// JWT algorithm
const std::string FirebaseAdminTokenVerifier::JWT_ALGORITHM = "RS256";

/**
 * Base64url encoding without padding
 * Standard base64 uses +, /, and = chars
 * URL-safe base64 uses -, _, and no padding
 */
std::string FirebaseAdminTokenVerifier::Base64UrlEncode(const std::string& input) {
    static const char* const base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    std::string output;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (size_t n = 0; n < input.length(); n++) {
        char_array_3[i++] = input[n];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) output += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++) char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (int j = 0; j < i + 1; j++) output += base64_chars[char_array_4[j]];
    }

    // Remove padding (=) - URL-safe base64 doesn't use padding
    while (output.back() == '=') {
        output.pop_back();
    }
    
    return output;
}

/**
 * Sign a message using RSA private key (RS256 algorithm)
 */
std::string FirebaseAdminTokenVerifier::SignWithRS256(const std::string& message) {
    try {
        // Load private key from PEM string
        BIO* bio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
        if (!bio) {
            LOG_ERROR("FirebaseAdminTokenVerifier::SignWithRS256 - Failed to create BIO");
            return "";
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey) {
            LOG_ERROR("FirebaseAdminTokenVerifier::SignWithRS256 - Failed to read private key: {}",
                      ERR_error_string(ERR_get_error(), nullptr));
            return "";
        }

        // Create signature context
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            LOG_ERROR("FirebaseAdminTokenVerifier::SignWithRS256 - Failed to create MD context");
            EVP_PKEY_free(pkey);
            return "";
        }

        // Initialize context for SHA256 with RSA
        if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
            LOG_ERROR("FirebaseAdminTokenVerifier::SignWithRS256 - DigestSignInit failed: {}",
                      ERR_error_string(ERR_get_error(), nullptr));
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return "";
        }

        // Update with message
        if (EVP_DigestSignUpdate(mdctx, message.data(), message.size()) <= 0) {
            LOG_ERROR("FirebaseAdminTokenVerifier::SignWithRS256 - DigestSignUpdate failed: {}",
                      ERR_error_string(ERR_get_error(), nullptr));
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return "";
        }

        // Get signature size
        size_t sig_len = 0;
        if (EVP_DigestSignFinal(mdctx, nullptr, &sig_len) <= 0) {
            LOG_ERROR("FirebaseAdminTokenVerifier::SignWithRS256 - DigestSignFinal (size) failed: {}",
                      ERR_error_string(ERR_get_error(), nullptr));
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return "";
        }

        // Create signature
        std::vector<unsigned char> signature(sig_len);
        if (EVP_DigestSignFinal(mdctx, signature.data(), &sig_len) <= 0) {
            LOG_ERROR("FirebaseAdminTokenVerifier::SignWithRS256 - DigestSignFinal failed: {}",
                      ERR_error_string(ERR_get_error(), nullptr));
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return "";
        }

        signature.resize(sig_len);

        // Clean up
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);

        // Convert to string and base64url encode
        std::string sig_str(signature.begin(), signature.end());
        return Base64UrlEncode(sig_str);

    } catch (const std::exception& e) {
        LOG_ERROR("FirebaseAdminTokenVerifier::SignWithRS256 - Exception: {}", e.what());
        return "";
    }
}

/**
 * Load service account credentials from JSON file
 */
bool FirebaseAdminTokenVerifier::LoadServiceAccount(const std::string& credentialJsonPath) {
    try {
        std::ifstream file(credentialJsonPath);
        if (!file.is_open()) {
            LOG_ERROR("FirebaseAdminTokenVerifier::LoadServiceAccount - Cannot open file: {}", 
                      credentialJsonPath);
            return false;
        }

        json credentials;
        file >> credentials;
        file.close();

        // Extract required fields
        if (!credentials.contains("private_key") || !credentials.contains("client_email") ||
            !credentials.contains("project_id")) {
            LOG_ERROR("FirebaseAdminTokenVerifier::LoadServiceAccount - Missing required fields");
            return false;
        }

        privateKey = credentials["private_key"].get<std::string>();
        clientEmail = credentials["client_email"].get<std::string>();
        projectId = credentials["project_id"].get<std::string>();

        LOG_INFO("FirebaseAdminTokenVerifier::LoadServiceAccount - Loaded credentials for: {}", 
                 clientEmail);
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR("FirebaseAdminTokenVerifier::LoadServiceAccount - Exception: {}", e.what());
        return false;
    } catch (...) {
        LOG_ERROR("FirebaseAdminTokenVerifier::LoadServiceAccount - Unknown exception");
        return false;
    }
}

/**
 * Exchange a self-signed JWT for an OAuth 2.0 access token
 * Uses Google's token endpoint with the JWT bearer grant type
 */
// Caller MUST hold cacheMutex_.
std::string FirebaseAdminTokenVerifier::ExchangeJwtForAccessTokenLocked(const std::string& jwt) {
    try {
        const std::string tokenUrl = "https://oauth2.googleapis.com/token";
        
        std::string body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt;
        
        std::unordered_map<std::string, std::string> headers;
        headers["Content-Type"] = "application/x-www-form-urlencoded";
        
        LOG_INFO("FirebaseAdminTokenVerifier::ExchangeJwtForAccessToken - Requesting access token");
        
        auto [response, statusCode] = WebClient::Post(tokenUrl, body, headers);
        
        if (statusCode != 200) {
            LOG_ERROR("FirebaseAdminTokenVerifier::ExchangeJwtForAccessToken - Token exchange failed with status: {} response: {}",
                      statusCode, response);
            return "";
        }
        
        json responseJson = json::parse(response);
        
        if (!responseJson.contains("access_token")) {
            LOG_ERROR("FirebaseAdminTokenVerifier::ExchangeJwtForAccessToken - No access_token in response: {}", response);
            return "";
        }
        
        cachedAccessToken = responseJson["access_token"].get<std::string>();
        
        // Cache with expiry (default 3600s, use value from response if available)
        int expiresIn = 3600;
        if (responseJson.contains("expires_in")) {
            expiresIn = responseJson["expires_in"].get<int>();
        }
        accessTokenExpiry = std::chrono::system_clock::now() + std::chrono::seconds(expiresIn);
        
        LOG_INFO("FirebaseAdminTokenVerifier::ExchangeJwtForAccessToken - Access token obtained, expires in {} seconds", expiresIn);
        
        return cachedAccessToken;
        
    } catch (const std::exception& e) {
        LOG_ERROR("FirebaseAdminTokenVerifier::ExchangeJwtForAccessToken - Exception: {}", e.what());
        return "";
    }
}

/**
 * Create a new service account JWT for Firebase Admin API
 * JWT structure: header.payload.signature
 */
// Caller MUST hold cacheMutex_.
std::string FirebaseAdminTokenVerifier::CreateServiceAccountJwtLocked() {
    try {
        auto now = std::chrono::system_clock::now();
        auto expiry = now + std::chrono::seconds(JWT_LIFETIME_SECONDS);
        
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        auto expiry_time_t = std::chrono::system_clock::to_time_t(expiry);

        // Create JWT header
        json header = {
            {"alg", JWT_ALGORITHM},
            {"typ", "JWT"}
        };

        // Create JWT payload (claims)
        // aud must be the OAuth token endpoint for JWT-based auth
        json payload = {
            {"iss", clientEmail},
            {"sub", clientEmail},
            {"aud", "https://oauth2.googleapis.com/token"},
            {"iat", now_time_t},
            {"exp", expiry_time_t},
            {"scope", "https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/firebase"}
        };

        // Create header.payload
        std::string header_str = Base64UrlEncode(header.dump());
        std::string payload_str = Base64UrlEncode(payload.dump());
        std::string message = header_str + "." + payload_str;

        // Sign the message
        std::string signature = SignWithRS256(message);
        if (signature.empty()) {
            LOG_ERROR("FirebaseAdminTokenVerifier::CreateServiceAccountJwt - Failed to sign JWT");
            return "";
        }

        // Create final JWT token
        std::string jwt = message + "." + signature;

        // Cache the JWT
        cachedJwt = jwt;
        jwtExpiry = expiry;

        LOG_INFO("FirebaseAdminTokenVerifier::CreateServiceAccountJwt - JWT created, expires in {} seconds",
                 JWT_LIFETIME_SECONDS);

        return jwt;

    } catch (const std::exception& e) {
        LOG_ERROR("FirebaseAdminTokenVerifier::CreateServiceAccountJwt - Exception: {}", e.what());
        return "";
    }
}

/**
 * Constructor - Load service account from file
 */
FirebaseAdminTokenVerifier::FirebaseAdminTokenVerifier(const std::string& credentialJsonPath) {
    LOG_INFO("FirebaseAdminTokenVerifier::Constructor - Loading credentials from: {}", 
             credentialJsonPath);

    if (!LoadServiceAccount(credentialJsonPath)) {
        LOG_ERROR("FirebaseAdminTokenVerifier::Constructor - Failed to load service account");
        throw std::runtime_error("Failed to load Firebase service account credentials");
    }

    LOG_INFO("FirebaseAdminTokenVerifier::Constructor - Initialization complete");
}

/**
 * Verify an ID token with Firebase Admin API
 */
std::tuple<bool, std::string> FirebaseAdminTokenVerifier::VerifyIdToken(const std::string& idToken, const std::string& expectedEmail) {
    try {
        if (idToken.empty()) {
            LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Empty ID token provided");
            return {false, "Empty ID token"};
        }

        // Get or create a valid OAuth 2.0 access token.
        // Hold cacheMutex_ across the entire cache-check-and-refresh sequence
        // to prevent multiple threads from racing to create new JWTs/access tokens.
        std::string accessToken;
        {
            std::lock_guard<std::mutex> lock(cacheMutex_);

            // Check if cached access token is still valid
            auto now = std::chrono::system_clock::now();
            auto accessThreshold = accessTokenExpiry - std::chrono::minutes(JWT_REFRESH_THRESHOLD_MINUTES);

            if (!cachedAccessToken.empty() && now < accessThreshold) {
                accessToken = cachedAccessToken;
            } else {
                // Need a new access token — first ensure we have a valid JWT
                auto jwtThreshold = jwtExpiry - std::chrono::minutes(JWT_REFRESH_THRESHOLD_MINUTES);
                std::string jwt;
                if (!cachedJwt.empty() && now < jwtThreshold) {
                    jwt = cachedJwt;
                } else {
                    // Create a new service-account JWT (OpenSSL signing — done under lock)
                    jwt = CreateServiceAccountJwtLocked();
                    if (jwt.empty()) {
                        LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Failed to create JWT");
                        return {false, "Failed to create authentication token"};
                    }
                }

                // Exchange JWT for access token (HTTP call — done under lock)
                accessToken = ExchangeJwtForAccessTokenLocked(jwt);
                if (accessToken.empty()) {
                    LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Failed to get access token");
                    return {false, "Failed to obtain OAuth access token"};
                }
            }
        }

        // Prepare request headers with the OAuth access token
        std::unordered_map<std::string, std::string> headers;
        headers["Authorization"] = "Bearer " + accessToken;
        headers["Content-Type"] = "application/json";

        // Prepare request body
        json requestBody = {
            {"idToken", idToken}
        };
        std::string body = requestBody.dump();

        LOG_INFO("FirebaseAdminTokenVerifier::VerifyIdToken - Calling Firebase API");

        // Call Firebase Admin API
        auto [response, statusCode] = WebClient::Post(FIREBASE_API_ENDPOINT, body, headers);

        if (statusCode != 200) {
            LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Firebase API returned status: {} response: {}", statusCode, response);
            return {false, fmt::format("Firebase API error ({})", statusCode)};
        }

        // Parse response
        try {
            json responseJson = json::parse(response);
            
            // Check for errors in response
            if (responseJson.contains("error")) {
                std::string errorMsg = responseJson["error"].get<std::string>();
                LOG_ERROR("FirebaseAdminTokenVerifier::VerifyIdToken - Firebase error: {}", errorMsg);
                return {false, fmt::format("Firebase error: {}", errorMsg)};
            }

            // Extract user info from response
            if (!responseJson.contains("users") || responseJson["users"].empty()) {
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
