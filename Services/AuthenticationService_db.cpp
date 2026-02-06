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
#include "authDB.h"
#include "activityTrackkerDB.h"

using namespace std::chrono_literals;
namespace fs = std::filesystem;

::grpc::Status AuthenticationService::ShareDB(::grpc::ServerContext* context, const AuthDatabaseProto::ShareDBWith* request, AuthDatabaseProto::BoolValue* response) {
    return Execute<AuthDatabaseProto::ShareDBWith, AuthDatabaseProto::BoolValue>("ShareDB", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::ShareDBWith* req, AuthDatabaseProto::BoolValue* r) -> bool {
        r->set_value(db->ShareDB(req->db().owner_email(), req->db().db_name(), req->emails()));
        return true;
    });
}

::grpc::Status AuthenticationService::GetDBList(::grpc::ServerContext* context, const AuthDatabaseProto::DBList* request, AuthDatabaseProto::DBList* response) {
    return Execute<AuthDatabaseProto::DBList, AuthDatabaseProto::DBList>("GetDBList", context, request, response, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::DBList* req, AuthDatabaseProto::DBList* r) -> bool {
        db->GetDBList(session->user().email(), session->group_filter(), r->mutable_list());
        LOG_INFO("AuthenticationService::GetDBList> email:{} >> no of databases: ", session->user().email(), r->list_size());
        return true;
    });
}

::grpc::Status AuthenticationService::CreateDatabase(::grpc::ServerContext* context, const AuthDatabaseProto::DBName* request, AuthDatabaseProto::DBList* list) {
    return Execute<AuthDatabaseProto::DBName, AuthDatabaseProto::DBList>("CreateDatabase", context, request, list, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::DBName* req, AuthDatabaseProto::DBList* r) -> bool {
        db->RegisterDB(req);
        db->GetDBList(session->user().email(), session->group_filter(), r->mutable_list());
        return true;
    });
}

::grpc::Status AuthenticationService::DeleteDatabase(::grpc::ServerContext* context, const AuthDatabaseProto::DBName* request, AuthDatabaseProto::DBList* list) {
    return Execute<AuthDatabaseProto::DBName, AuthDatabaseProto::DBList>("DeleteDatabase", context, request, list, [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::DBName* req, AuthDatabaseProto::DBList* r) -> bool {
        db->DeRegisterDB(session->user().email(), req);
        db->GetDBList(session->user().email(), session->group_filter(), r->mutable_list());
        return true;
    });
}
