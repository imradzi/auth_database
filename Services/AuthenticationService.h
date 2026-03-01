#pragma once
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "auth_database.pb.h"
#include "auth_database.grpc.pb.h"
#include "protofunctions.h"

#include "authDB.h"
#include "GetSession.h"
#include "logger/logger.h"

using namespace std::chrono_literals;
namespace fs = std::filesystem;

bool DoGetConfig(AuthDatabaseProto::Session* session, AuthorizationDB* authDb, const AuthDatabaseProto::Config* req, AuthDatabaseProto::Config* r);

class AuthenticationService final : public ::AuthDatabaseProto::AuthenticationService::Service {
    template<typename Request, typename Response>
    int DoExecute(AuthDatabaseProto::Session* session, const Request* request, Response* response, std::function<bool(::AuthDatabaseProto::Session* session, AuthorizationDB*, const Request*, Response*)> fnCall, bool skipCheckEmailApproved = false, bool toValidateToken = false) {
        auto authDb = std::make_unique<AuthorizationDB>();
        authDb->Open();
        skipCheckEmailApproved = skipCheckEmailApproved || authDb->GetRegistry()->GetKey("skipCheckEmailApproved", true);
        if (skipCheckEmailApproved || authDb->IsEmailApproved(session->user().email())) {
            if (toValidateToken) {
                if (toValidateToken || authDb->IsClientTokenExists(session->user().email())) {
                    return fnCall(session, authDb.get(), request, response) ? 1 : 0;
                } else {
                    return -1;
                }
            } else {
                return fnCall(session, authDb.get(), request, response) ? 1 : 0;
            }
        } else {
            authDb->NotifyAdminUserCreated(&session->user());
            return -2;
        }
        return 1;
    }

public:
    template<typename Request, typename Response>
    int Execute(const char *name, boost::beast::string_view sessionString, const Request* request, Response* response, std::function<bool(::AuthDatabaseProto::Session* session, AuthorizationDB*, const Request *, Response*)> fnCall, bool skipCheckEmailApproved=false, bool toValidateToken=false) {
        auto session = ::GetSession(sessionString);
        LOG_INFO("{}> started -> session: email: {}, name:{}, telNo: {}, db:{}, appName:{}", name, session->user().email(), session->user().name(), session->user().tel_no(), session->db_name(), session->app_name());
        try {
            return DoExecute(session.get(), request, response, fnCall, skipCheckEmailApproved, toValidateToken);
        } catch (const std::exception& e) {
            LOG_ERROR("{}> sql exception: {}", name, e.what());
        } catch (...) {
            LOG_ERROR("{}> unknown exception", name);
        }
        return -1;
    }

    template<typename Request, typename Response>
    ::grpc::Status Execute(const char *name, ::grpc::ServerContext* context, const Request* request, Response* response, std::function<bool(::AuthDatabaseProto::Session* session, AuthorizationDB*, const Request *, Response*)> fnCall, bool skipCheckEmailApproved = false, bool toValidateToken = false) {
        auto session = GetSession(context);
        try {
            auto ret = DoExecute(session.get(), request, response, fnCall, skipCheckEmailApproved, toValidateToken);
            if (ret == -1) {
                context->AddTrailingMetadata("error", "Token missing.");
                context->AddTrailingMetadata("error-code", "-1");
            } else if (ret == -2) {
                context->AddTrailingMetadata("error", "User not approved yet.");
                context->AddTrailingMetadata("error-code", "-2");
            }
            return ::grpc::Status::OK;
        } catch (const std::exception& e) {
            LOG_ERROR("{}> sql exception: {}", name, e.what());
            context->AddTrailingMetadata("error", e.what());
        } catch (...) {
            LOG_ERROR("{}> unknown exception", name);
            context->AddTrailingMetadata("error", "exception");
        }
        return ::grpc::Status::CANCELLED;
    }

    static std::tuple<bool, std::unique_ptr<AuthDatabaseProto::Session>, std::unique_ptr<AuthorizationDB>> ReadMetaData(const std::string& name, ::grpc::ServerContext* context, bool skipCheckEmailApproved = false, bool toValidateToken = false);

public:
    explicit AuthenticationService() {}

    ::grpc::Status RegisterSession(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::User* response) override;
    ::grpc::Status UnRegisterSession(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status UnRegisterAllSession(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status ValidateToken(::grpc::ServerContext* context, const AuthDatabaseProto::IdToken* request, AuthDatabaseProto::BoolValue* response) override;
    //::grpc::Status GetConfig(::grpc::ServerContext* context, const AuthDatabaseProto::Config* request, AuthDatabaseProto::Config* config) override;
    //int GetConfig(boost::beast::string_view sessionString, const AuthDatabaseProto::Config* request, AuthDatabaseProto::Config* config);
     
    ::grpc::Status GetConfig(::grpc::ServerContext* context, const AuthDatabaseProto::Config* request, AuthDatabaseProto::Config* config) {
        return Execute<AuthDatabaseProto::Config, AuthDatabaseProto::Config>("GetConfig", context, request, config, DoGetConfig, true);
    }

    int GetConfig(boost::beast::string_view sessionString, const AuthDatabaseProto::Config* request, AuthDatabaseProto::Config* config) {
        return Execute<AuthDatabaseProto::Config, AuthDatabaseProto::Config>("GetConfig", sessionString, request, config, DoGetConfig, true);
    }

    
    ::grpc::Status RegisterUser(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* config) override;
    ::grpc::Status SaveUser(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* config) override;
    ::grpc::Status ApproveUser(::grpc::ServerContext* context, const AuthDatabaseProto::ApproveEmail*, AuthDatabaseProto::BoolValue* config) override;
    ::grpc::Status GetUserList(::grpc::ServerContext* context, const AuthDatabaseProto::SearchUser*, AuthDatabaseProto::UserList* config) override;
    ::grpc::Status PromoteUserToAdmin(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status RevokeUserAdmin(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status PromoteUserToDBAdmin(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status RevokeUserDBAdmin(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status PromoteUserToDBAccount(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status RevokeUserDBAccount(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status PromoteUserToDBOwner(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status RevokeUserDBOwner(::grpc::ServerContext* context, const AuthDatabaseProto::User*, AuthDatabaseProto::BoolValue* response) override;

    ::grpc::Status GetTypeList(::grpc::ServerContext* context, const AuthDatabaseProto::StringValue *, AuthDatabaseProto::TypeList* response) override;

    ::grpc::Status ShareDB(::grpc::ServerContext* context, const AuthDatabaseProto::ShareDBWith* request, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status GetDBList(::grpc::ServerContext* context, const AuthDatabaseProto::DBList* request, AuthDatabaseProto::DBList* response) override;

    ::grpc::Status SetApplicationName(::grpc::ServerContext* context, const AuthDatabaseProto::DBName* request, AuthDatabaseProto::BoolValue* response) override;
    ::grpc::Status CreateDatabase(::grpc::ServerContext* context, const AuthDatabaseProto::DBName* request, AuthDatabaseProto::DBList* list) override;
    ::grpc::Status DeleteDatabase(::grpc::ServerContext* context, const AuthDatabaseProto::DBName* request, AuthDatabaseProto::DBList* list) override;

    ::grpc::Status SaveParticipant(::grpc::ServerContext* context, const AuthDatabaseProto::Dependent* request, AuthDatabaseProto::Dependent* response) override;
    ::grpc::Status GetParticipantList(::grpc::ServerContext* context, const AuthDatabaseProto::SearchKey* request, AuthDatabaseProto::ParticipantList* response) override;

    ::grpc::Status SaveDependent(::grpc::ServerContext* context, const AuthDatabaseProto::Dependent* request, AuthDatabaseProto::Dependent* response) override;
    ::grpc::Status GetDependentList(::grpc::ServerContext* context, const AuthDatabaseProto::SearchKey* request, AuthDatabaseProto::ParticipantList* response) override;


};
