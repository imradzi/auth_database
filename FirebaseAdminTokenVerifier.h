#pragma once

#include <string>
#include <memory>
#include <tuple>
#include <chrono>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * FirebaseAdminTokenVerifier - Verifies Firebase ID tokens using Firebase Admin SDK
 * 
 * This class handles:
 * 1. Loading Firebase service account JSON (with private key)
 * 2. Creating signed JWT tokens (RS256) for Firebase Admin API authentication
 * 3. Calling Firebase Admin API to verify ID tokens
 * 4. Caching JWTs to avoid repeated signing operations
 * 5. Extracting and returning verified user email
 */
class FirebaseAdminTokenVerifier {
private:
    // Service account credentials
    std::string privateKey;           // RSA private key (PEM format)
    std::string clientEmail;          // Service account email
    std::string projectId;            // Firebase project ID
    std::string tokenUri;             // Token endpoint URI
    
    // JWT caching
    std::string cachedJwt;
    std::chrono::system_clock::time_point jwtExpiry;
    
    // OAuth access token caching
    std::string cachedAccessToken;
    std::chrono::system_clock::time_point accessTokenExpiry;
    
    // Constants
    static constexpr int JWT_LIFETIME_SECONDS = 3600;      // 1 hour
    static constexpr int JWT_REFRESH_THRESHOLD_MINUTES = 5; // Refresh before 5 min expiry
    static const std::string FIREBASE_API_ENDPOINT;
    static const std::string JWT_ALGORITHM;
    
private:
    /**
     * Load Firebase service account from JSON file
     * Extracts: private_key, client_email, project_id
     */
    bool LoadServiceAccount(const std::string& credentialJsonPath);
    
    /**
     * Create a base64url encoded string
     */
    static std::string Base64UrlEncode(const std::string& input);
    
    /**
     * Sign data using RSA private key (RS256 algorithm)
     * Returns base64url-encoded signature
     */
    std::string SignWithRS256(const std::string& message);
    
    /**
     * Check if cached JWT is still valid
     * Returns true if JWT is cached and not near expiration
     */
    bool IsCachedJwtValid() const;
    
    /**
     * Check if cached access token is still valid
     */
    bool IsCachedAccessTokenValid() const;
    
    /**
     * Exchange a self-signed JWT for an OAuth 2.0 access token
     */
    std::string ExchangeJwtForAccessToken(const std::string& jwt);
    
    /**
     * Create a new service account JWT
     * This JWT is used to authenticate with Firebase Admin API
     */
    std::string CreateServiceAccountJwt();

public:
    /**
     * Constructor - loads Firebase service account from credential file
     * @param credentialJsonPath Path to Firebase service account JSON file
     * @throws std::runtime_error if credential file cannot be loaded or parsed
     */
    FirebaseAdminTokenVerifier(const std::string& credentialJsonPath);
    
    ~FirebaseAdminTokenVerifier() = default;
    
    /**
     * Verify a Firebase ID token
     * @param idToken The ID token to verify (from client)
     * @param expectedEmail Optional email to validate against decoded token
     * @return {success, email_or_error_message}
     *         - success=true: email contains verified email from Firebase
     *         - success=false: email contains error description
     */
    std::tuple<bool, std::string> VerifyIdToken(const std::string& idToken, const std::string& expectedEmail = "");
};
