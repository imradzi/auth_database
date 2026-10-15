#pragma once

#include <string>
#include <tuple>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * FirebaseAdminTokenVerifier - keyless Firebase ID-token verification.
 *
 * Verifies Firebase ID tokens against the Identity Toolkit REST endpoint
 * (accounts:lookup) using the project's PUBLIC web API key. Google performs
 * the actual validation server-side (the same mechanism the Firebase client
 * SDKs rely on), so no service-account credential file is needed on ppServer
 * installs anymore.
 *
 * The service-account JSON now lives only on the ppGateway host, solely for
 * FCM push sending (FcmSender). See docs/keyless-firebase-verification-plan.md.
 */
class FirebaseAdminTokenVerifier {
public:
    /** No credentials to load — argument-less for call-site compatibility. */
    FirebaseAdminTokenVerifier();

    ~FirebaseAdminTokenVerifier() = default;

    /**
     * Verify a Firebase ID token
     * @param idToken The ID token to verify (from client)
     * @param expectedEmail Optional email to validate against the verified token
     * @return {success, email_or_error_message}
     *         - success=true: email contains verified email from Firebase
     *         - success=false: email contains error description
     */
    std::tuple<bool, std::string> VerifyIdToken(const std::string& idToken, const std::string& expectedEmail = "");
};
