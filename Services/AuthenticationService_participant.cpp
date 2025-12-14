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


::grpc::Status AuthenticationService::GetParticipantList(::grpc::ServerContext* context, const AuthDatabaseProto::SearchKey* request, AuthDatabaseProto::ParticipantList* response) {
    return Execute<AuthDatabaseProto::SearchKey, AuthDatabaseProto::ParticipantList>(
        "GetParticipantList", context, request, response,
        [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::SearchKey* req, AuthDatabaseProto::ParticipantList* r) -> bool {
            db->GetUserList(r);
            return true;
        });
}

::grpc::Status AuthenticationService::SaveParticipant(::grpc::ServerContext* context, const AuthDatabaseProto::Dependent* request, AuthDatabaseProto::Dependent* response) {
    return Execute<AuthDatabaseProto::Dependent, AuthDatabaseProto::Dependent>(
        "SaveParticipant", context, request, response,
        [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::Dependent* req, AuthDatabaseProto::Dependent* r) -> bool {
            *r = *req;
            return db->SaveUser(session, r->mutable_user());
        });
}

::grpc::Status AuthenticationService::GetDependentList(::grpc::ServerContext* context, const AuthDatabaseProto::SearchKey* request, AuthDatabaseProto::ParticipantList* response) {
    return Execute<AuthDatabaseProto::SearchKey, AuthDatabaseProto::ParticipantList>(
        "GetDependentList", context, request, response,
        [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::SearchKey* req, AuthDatabaseProto::ParticipantList* r) -> bool {
            db->GetDependentList(session->user().email(), r);
            return true;
        });
}

::grpc::Status AuthenticationService::SaveDependent(::grpc::ServerContext* context, const AuthDatabaseProto::Dependent* request, AuthDatabaseProto::Dependent* response) {
    return Execute<AuthDatabaseProto::Dependent, AuthDatabaseProto::Dependent>(
        "SaveDependent", context, request, response,
        [](AuthDatabaseProto::Session* session, AuthorizationDB* db, const AuthDatabaseProto::Dependent* req, AuthDatabaseProto::Dependent* r) -> bool {
            *r = *req;
            return db->SaveDependent(session, r->primary_email(), r->mutable_user());
        });
}
