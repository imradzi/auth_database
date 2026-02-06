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
#include <boost/tokenizer.hpp>

#include <filesystem>

#include <boost/uuid/uuid.hpp>
#include "authDB.h"
#include "beast.h"

#include "AuthenticationService.h"
#include "logger/logger.h"

::grpc::Status AuthenticationService::RegisterSession(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::User* response) {
    LOG_INFO("Register Session....");
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::User>("RegisterSession", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::User* r) -> bool {
        *r = *req;
        db->RegisterEmail(session, r, session->device_token(), session->app_name(), session->chat_key());
        db->GetUser(*session, r);
        LOG_INFO("RegisterSession> return user: {}", Protobuf::ToJSON(*r));
        return true; 
    }, true);
}

::grpc::Status AuthenticationService::UnRegisterSession(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    LOG_INFO("Removing UnRegister Session....");
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("UnRegisterSession", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->DeRegisterDevice(session->device_token());
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::UnRegisterAllSession(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    LOG_INFO("Removing UnRegister All Session....");
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("UnRegisterAllSession", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->DeRegisterDevice(req);
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::ValidateToken(::grpc::ServerContext* context, const AuthDatabaseProto::IdToken* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::IdToken, AuthDatabaseProto::BoolValue>("ValidateToken", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::IdToken* req, AuthDatabaseProto::BoolValue* r) -> bool {
        if (db->IsValidClientToken(req->token(), req->email())) {
            r->set_value(true);
        } else {
            r->set_value(false);
        }
        return true; 
    }, true);
}

// this is for register other user or save their info
::grpc::Status AuthenticationService::RegisterUser(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("RegisterUser", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        if (!db->IsAuthorizer(session->user().email())) return false;
        r->set_value(db->CreateUser(session, req, session->chat_key()) != 0);
        return true;
    });
}

// this is for save own self.
::grpc::Status AuthenticationService::SaveUser(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("SaveUser", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        r->set_value(db->CreateUser(session, req, session->chat_key()) != 0);
        return true;
    });
}

::grpc::Status AuthenticationService::ApproveUser(::grpc::ServerContext* context, const AuthDatabaseProto::ApproveEmail* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::ApproveEmail, AuthDatabaseProto::BoolValue>("ApproveUser", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::ApproveEmail* req, AuthDatabaseProto::BoolValue* r) -> bool {
        if (!db->IsAuthorizer(session->user().email())) return false;
        r->set_value(db->ApproveEmail(req->email_to_approve()));
        return true;
    });
}

::grpc::Status AuthenticationService::GetUserList(::grpc::ServerContext* context, const AuthDatabaseProto::SearchUser* request, AuthDatabaseProto::UserList* result) {
    return Execute<AuthDatabaseProto::SearchUser, AuthDatabaseProto::UserList>("GetUserList", context, request, result, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::SearchUser* req, AuthDatabaseProto::UserList* r) -> bool {
        std::string sql, ftsSearch, partialSearch;
        if (!req->partial_text().empty()) {
            ftsSearch = "and userfts match @partial_search";
            partialSearch = BuildFTSSearch(req->partial_text());
        }
        if (req->admin_only()) {
            sql = fmt::format(
                "select "
                "   u.id, u.email, u.timeregistered, uf.name, uf.IC, uf.telNo, "
                "   (select group_concat(roleid) from userRoles where userid=u.id) "
                "from users u "
                "inner join userfts uf on uf.rowid=u.id "
                "where u.email != 'anonymous@public' "
                " and exists (select * from dbuserroles where userid=u.id and roleid = {} {} and dbid=(select id from databases where dbname='{}')) "
                "order by uf.name ",
                db->GetKey<std::string>("udbRoles_Admin", ""), ftsSearch, session->db_name());
        } else {
            sql = fmt::format(
                "select "
                  "   u.id, u.email, u.timeregistered, uf.name, uf.IC, uf.telNo, "
                  "   (select group_concat(roleid) from userRoles where userid=u.id) "
                  "from users u "
                  "inner join userfts uf on uf.rowid=u.id "
                  "where u.email != 'anonymous@public' {} "
                  "order by uf.name ", ftsSearch);
        }

        auto stt = db->GetSession().PrepareStatement(sql);
        if (!ftsSearch.empty()) {
            stt->Bind("@partial_search", partialSearch);
        }
        auto rs = stt->ExecuteQuery();
        bool res;
        std::shared_ptr<wpSQLStatement> sttGetType;
        std::shared_ptr<wpSQLStatement> sttGetUserDBRole;  // for cacched stmt;

        while (rs->NextRow()) {
            auto user = r->add_list();
            user->set_id(rs->Get(0));
            user->set_email(rs->Get(1));
            SetTimestamp(user->mutable_time_registered(), rs->Get<int64_t>(2));
            user->set_name(rs->Get(3));
            user->set_ic(rs->Get(4));
            user->set_tel_no(rs->Get(5));
            auto roles = rs->Get(6);
            boost::tokenizer<boost::char_separator<char>> tok(roles, boost::char_separator<char>(",", "", boost::drop_empty_tokens));
            for (auto x : tok) {              
                //user->mutable_user_roles()->Add()->set_id(x);
                std::tie(res, sttGetType) = db->GetTypeRecord(x, user->add_user_roles(), sttGetType);
            }
            sttGetUserDBRole = db->GetDBUserRoles(session->db_name(), user, sttGetUserDBRole);
        }
        return true;
    });
}

::grpc::Status AuthenticationService::PromoteUserToAdmin(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("PromoteUserToAdmin", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->SetRoleAdmin(req->email());
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::RevokeUserAdmin(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("RevokeUserAdmin", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->RevokeRoleAdmin(req->email());
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::PromoteUserToDBAdmin(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("PromoteUserToAdmin", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->SetDBRoleAdmin(session->db_name(), req->email());
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::RevokeUserDBAdmin(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("RevokeUserAdmin", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->RevokeDBRoleAdmin(session->db_name(), req->email());
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::PromoteUserToDBAccount(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("PromoteUserToAdmin", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->SetDBRoleAccount(session->db_name(), req->email());
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::RevokeUserDBAccount(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("RevokeUserAdmin", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->RevokeDBRoleAccount(session->db_name(), req->email());
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::PromoteUserToDBOwner(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("PromoteUserToAdmin", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->SetDBRoleOwner(session->db_name(), req->email());
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::RevokeUserDBOwner(::grpc::ServerContext* context, const AuthDatabaseProto::User* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::User, AuthDatabaseProto::BoolValue>("RevokeUserAdmin", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::User* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->RevokeDBRoleOwner(session->db_name(), req->email());
        r->set_value(true);
        return true;
    });
}

::grpc::Status AuthenticationService::GetTypeList(::grpc::ServerContext* context, const AuthDatabaseProto::StringValue* request, AuthDatabaseProto::TypeList* response) {
    return Execute<AuthDatabaseProto::StringValue, AuthDatabaseProto::TypeList>("GetTypeList", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::StringValue* req, AuthDatabaseProto::TypeList* r) -> bool {
        db->GetTypeList(req->value(), r);
        return true;
    });
}
