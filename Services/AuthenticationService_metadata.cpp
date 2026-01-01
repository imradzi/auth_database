
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

#include <boost/uuid/uuid.hpp>
#include "authDB.h"
#include "beast.h"

#include "AuthenticationService.h"
#include "logger/logger.h"

std::tuple<bool, std::unique_ptr<AuthDatabaseProto::Session>, std::unique_ptr<AuthorizationDB>> AuthenticationService::ReadMetaData(const std::string& name, ::grpc::ServerContext* context, bool skipCheckEmailApproved, bool toValidateToken) {
    auto meta = context->client_metadata();
    auto session = ::GetSession(context);
    ShowLog(fmt::format("{}> Read MetaData -> email: {}, name: {}, telNo: {}, db: {}, appName: {}", name, session->user().email(), session->user().name(), session->user().tel_no(), session->db_name(), session->app_name())) ;
    try {
        auto authDb = std::make_unique<AuthorizationDB>();
        authDb->Open();
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
    } catch (wpSQLException& e) {
        context->AddTrailingMetadata("error", e.message);
    } catch (std::exception& e) {
        context->AddTrailingMetadata("error", e.what());
    } catch (...) {
        context->AddTrailingMetadata("error", "exception");
    }
    return {false, nullptr, nullptr};
}
