#pragma once

// Public (non-secret) Firebase project identifiers for ppos-mobile.
//
// These values are API identifiers designed to ship inside client software
// (the same key is already embedded in ppClient/PWA flows via
// FirebaseAuthRest). They are NOT credentials — the service-account private
// key lives only on the ppGateway host (FCM) and is never distributed.
namespace FirebasePublicConfig {

// Web API key of the ppos-mobile Firebase project, used with the
// identitytoolkit / securetoken REST endpoints (e.g. ID-token verification
// via accounts:lookup). Same value as FIREBASE_API_KEY in
// appServer/FirebaseAuthRest.cpp (kept separate for include-path simplicity).
inline constexpr const char* webApiKey = "AIzaSyCv6EUjIMxN5dOrjpo4S_bzSTzzQkpTY5w";

}  // namespace FirebasePublicConfig
