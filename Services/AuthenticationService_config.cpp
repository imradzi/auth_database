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
#include "activityTrackkerDB.h"

#include "beast.h"

#include "AuthenticationService.h"
#include "logger/logger.h"

using namespace std::chrono_literals;
namespace fs = std::filesystem;

::grpc::Status AuthenticationService::SetApplicationName(::grpc::ServerContext* context, const AuthDatabaseProto::DBName* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::DBName, AuthDatabaseProto::BoolValue>("SetApplicationName", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::DBName* req, AuthDatabaseProto::BoolValue* r) -> bool {
        db->SetApplicationName(req->db_name(), req->app_name());

        std::string folderName = db->GetFolderNameInternal(req->db_name());
        auto d = std::make_unique<ActivityTrackkerDB>(folderName, req->db_name());
        d->Open();
        d->SetApplicationName(req->app_name());
        r->set_value(true);
        return true;
    });
}

bool DoGetConfig(AuthDatabaseProto::Session* session, AuthorizationDB* authDb, const AuthDatabaseProto::Config* req, AuthDatabaseProto::Config* r) {
    *r = *req;
    r->set_version(sqlite3_sourceid());

    authDb->GetDBList(session->user().email(), session->group_filter(), r->mutable_db_list());
    if (r->db().db_name().empty() && r->db_list_size() > 0) {
        *r->mutable_db() = r->db_list().at(0);
    } else {
        for (auto x : r->db_list()) {
            if (boost::equals(x.db_name(), r->db().db_name())) {
                *r->mutable_db() = x;
                break;
            }
        }
    }   
    if (session->db_name().empty()) session->set_db_name(r->db().db_name());
    auto folderName = AuthorizationDB::GetFolderName(session->db_name());
    if (!folderName.empty()) {
        if (!session->db_name().empty()) {
            fs::create_directory(folderName);
            // TODO: need to get the app name from ppos server
        }
    }
    authDb->GetUser(*session, r->mutable_user());
    auto reg = authDb->GetRegistry();
    auto adminRole = reg->GetKey<int>("uRoles_Admin");
    auto authorizeEmailRole = reg->GetKey<int>("uRoles_Authorizer");
    bool toGetApprovalList = false;
    for (auto t : r->user().user_roles()) {
        auto tid = to_number<int>(t.id());
        if (tid == adminRole || tid == authorizeEmailRole)
            toGetApprovalList = true;
    }
    if (toGetApprovalList) authDb->GetUserRequiresApproval(r->mutable_require_approval());
    authDb->GetTypeList("dbPrivacyType", r->mutable_privacy_list());
    authDb->GetTypeList("userDBRoleGroupID", r->mutable_db_roles_list());
    authDb->GetTypeList("userRoleGroupID", r->mutable_user_roles_list());
    ShowLog(fmt::format("GetConfig returns user: ", r->user().email()));
    return true;
};

std::shared_ptr<std::vector<char>> ExecuteCommand(boost::beast::string_view command, boost::beast::string_view sessionString, boost::beast::string_view body) {
    auto session = ::GetSession(sessionString);
    if (boost::iequals(command.substr(0, 9), "getconfig")) {
        AuthenticationService authService;
        AuthDatabaseProto::Config cfg;
        cfg.ParseFromArray(body.data(), body.size());

        auto out = std::make_unique<AuthDatabaseProto::Config>();
        authService.GetConfig(sessionString, &cfg, out.get());
        auto sz = out->ByteSizeLong();
        auto res = std::make_shared<std::vector<char>>(sz, ' ');
        cfg.SerializeToArray(res->data(), sz);
        return res;
    }
    return nullptr;
}
