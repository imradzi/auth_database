
#include <chrono>
#include <cmath>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <chrono>

#include <fmt/format.h>
#include <signal.h>
#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <filesystem>

#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include "authDB.h"
#include "beast.h"

#include "AuthenticationService.h"
#include "logger/logger.h"

// Read a client metadata value ("" when absent). Used by the PWA auth path.
static std::string GetMetaValue(::grpc::ServerContext* context, const std::string& key) {
    for (const auto& x : context->client_metadata()) {
        if (boost::iequals(x.first, key)) {
            return std::string(x.second.data(), x.second.size());
        }
    }
    return "";
}

std::tuple<bool, std::unique_ptr<AuthDatabaseProto::Session>, std::unique_ptr<AuthorizationDB>> AuthenticationService::ReadMetaData(const std::string& name, ::grpc::ServerContext* context, bool skipCheckEmailApproved, bool toValidateToken) {
    auto meta = context->client_metadata();
    auto session = ::GetSession(context);
    LOG_INFO("{}> Read MetaData -> email: {}, name: {}, telNo: {}, db: {}, appName: {}", name, session->user().email(), session->user().name(), session->user().tel_no(), session->db_name(), session->app_name()) ;
    try {
        auto authDb = std::make_unique<AuthorizationDB>();
        authDb->Open();

        // ── PWA path: no legacy session header; authenticate with the
        // Firebase ID token forwarded by the gateway (authorization: Bearer)
        // plus the database name (x-arham-db). Mirrors ppServer's
        // mustUseSessionKey=false path; legacy clients are unaffected.
        if (session->user().email().empty()) {
            auto bearer = GetMetaValue(context, "authorization");
            if (bearer.starts_with("Bearer ")) {
                std::string idToken = bearer.substr(7);
                if (!AuthorizationDB::EnsureFirebaseVerifier()) {
                    context->AddTrailingMetadata("error", "Cannot initialize Firebase verifier.");
                    context->AddTrailingMetadata("error-code", "-1");
                    return {false, nullptr, nullptr};
                }
                auto* verifier = AuthorizationDB::GetFirebaseVerifier();
                auto [tokenOk, emailOrError] = verifier->VerifyIdToken(idToken);
                if (!tokenOk) {
                    context->AddTrailingMetadata("error", "Invalid Firebase token: " + emailOrError);
                    context->AddTrailingMetadata("error-code", "-1");
                    return {false, nullptr, nullptr};
                }
                session->mutable_user()->set_email(emailOrError);
                session->set_app_name("arham-pwa");

                std::string dbName = GetMetaValue(context, "x-arham-db");
                if (!dbName.empty()) session->set_db_name(dbName);

                // Resolve the group filter (and confirm DB access) from the
                // user's database list.
                google::protobuf::RepeatedPtrField<AuthDatabaseProto::DBName> dbList;
                authDb->GetDBList(emailOrError, "", &dbList);
                const AuthDatabaseProto::DBName* match = nullptr;
                for (const auto& db : dbList) {
                    if (dbName.empty() || db.db_name() == dbName) { match = &db; break; }
                }
                if (match == nullptr && dbList.size() > 0) {
                    match = &dbList.Get(0);
                }
                if (match != nullptr) {
                    if (session->db_name().empty()) session->set_db_name(match->db_name());
                    session->set_group_filter(match->group_filter());
                }
            }
        }

        skipCheckEmailApproved = skipCheckEmailApproved || authDb->GetRegistry()->GetKey("skipCheckEmailApproved", true);
        if (skipCheckEmailApproved || authDb->IsEmailApproved(session->user().email())) {
            if (toValidateToken) {
                if (authDb->IsClientTokenExists(session->user().email())) {
                    return {true, std::move(session), std::move(authDb)};
                } else {
                    context->AddTrailingMetadata("error", "Token missing.");
                    context->AddTrailingMetadata("error-code", "-1");
                    return {false, nullptr, nullptr};
                }
            } else {
                return {true, std::move(session), std::move(authDb)};
            }
        } else {
            auto user = std::make_unique<AuthDatabaseProto::User>();
            user->set_email(session->user().email());
            authDb->NotifyAdminUserCreated(user.get());
            context->AddTrailingMetadata("error", "User not approved yet.");
            context->AddTrailingMetadata("error-code", "-2");
            return {false, nullptr, nullptr};
        }
        return {false, nullptr, nullptr};
    } catch (const std::exception& e) {
        context->AddTrailingMetadata("error", e.what());
    } catch (...) {
        context->AddTrailingMetadata("error", "exception");
    }
    return {false, nullptr, nullptr};
}
