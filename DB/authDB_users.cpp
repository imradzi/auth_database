#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#ifdef _WIN32
#include "winsock2.h"
#endif

#ifdef __clang__
#if __has_warning("-Wdeprecated-enum-enum-conversion")
#pragma clang diagnostic ignored "-Wdeprecated-enum-enum-conversion"  // warning: bitwise operation between different enumeration types ("XXXFlags_" and "XXXFlagsPrivate_") is deprecated
#endif
#endif

#ifdef __WX__
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif
#include "wx/tokenzr.h"
#endif
#ifdef _USEPOSTGRESQL
#undef _USEPOSTGRESQL
#endif

#include "authDB.h"
#include "AuthChatService.h"
#include "timefunctions.h"
#include <tuple>

void AuthorizationDB::GetUser(const AuthDatabaseProto::Session &session, AuthDatabaseProto::User *user) {
    user->Clear();
    LOG_INFO("***AuthorizationDB::GetUser> {}", session.user().email());
    auto stt = GetSession().PrepareStatement(
        "select id, email, uf.name, uf.telNo, timeRegistered, timeAccepted, uf.IC "
        "from users u "
        "inner join userFTS uf on uf.rowid=u.id "
        "where email=@email");
    stt->Bind("@email", session.user().email());
    auto rs = stt->ExecuteQuery();
    if (rs->NextRow()) {
        user->set_id(rs->Get(0));
        user->set_email(rs->Get(1));
        user->set_name(rs->Get(2));
        user->set_tel_no(rs->Get(3));
        SetTimestamp(user->mutable_time_registered(), rs->Get<int64_t>(4));
        if (rs->IsNull(5))
            SetNullTimestamp(user->mutable_time_accepted());
        else
            SetTimestamp(user->mutable_time_accepted(), rs->Get<int64_t>(5));
        user->set_ic(rs->Get(6));
        LOG_INFO("AuthorizationDB::GetUser> email: {} id: {}, name: {}, telNo: {}", user->email(), user->id(), user->name(), user->tel_no());
    } else {  // missing user should be added since this call after all auth ok
        LOG_INFO("AuthorizationDB::GetUser> {} NOT FOUND!", session.user().email());
        *user = session.user();
        user->set_id(std::to_string(SaveUser(&session, user)));
    }

    std::shared_ptr<wpSQLStatement> sttGetType;
    bool res = false;

    stt = GetSession().PrepareStatement("select roleId from userRoles where userId=@uid");
    stt->Bind("@uid", user->id());
    rs = stt->ExecuteQuery();
    while (rs->NextRow()) {
        std::tie(res, sttGetType) = GetTypeRecord(rs->Get(0), user->add_user_roles(), sttGetType);
    }
    GetDBUserRoles(session.db_name(), user, nullptr);
}

std::shared_ptr<wpSQLStatement> AuthorizationDB::GetDBUserRoles(const std::string &dbName, AuthDatabaseProto::User *user, std::shared_ptr<wpSQLStatement> stt) {
    if (stt == nullptr) {
        stt = GetSession().PrepareStatement(
            "select db.dbname, roleId "
            "from dbUserRoles u "
            "inner join databases db on db.id=u.dbId "
            "where u.userId=@uid and db.dbname=@dbName and ifnull(u.timeApproved,0) > 0 ");
    }
    stt->Bind("@uid", user->id());
    stt->Bind("@dbName", dbName);
    auto rs = stt->ExecuteQuery();
    bool res;
    std::shared_ptr<wpSQLStatement> sttGetType;
    while (rs->NextRow()) {
        auto x = user->add_user_db_roles();
        x->set_db_name(rs->Get(0));
        std::tie(res, sttGetType) = GetTypeRecord(rs->Get(1), x->mutable_roles(), sttGetType);
    }
    
    LOG_INFO("AuthorizationDB::GetDBUserRoles> user: {} for db: {} -> roles", user->email(), dbName, user->user_db_roles_size());
    return stt;
}

void AuthorizationDB::GetUserRequiresApproval(google::protobuf::RepeatedPtrField<AuthDatabaseProto::User> *userList) {
    userList->Clear();
    auto rs = GetSession().ExecuteQuery("select id, email, uf.name, uf.telNo, timeRegistered from users u inner join userFTS uf on uf.rowid=u.id where timeAccepted is null");
    if (rs->NextRow()) {
        auto user = userList->Add();
        user->set_id(rs->Get(0));
        user->set_email(rs->Get(1));
        user->set_name(rs->Get(2));
        user->set_tel_no(rs->Get(3));
        SetTimestamp(user->mutable_time_registered(), rs->Get<int64_t>(4));

        auto stt = GetSession().PrepareStatement("select roleId from userRoles where userId=@uid");
        stt->Bind("@uid", user->id());
        rs = stt->ExecuteQuery();
        while (rs->NextRow()) {
            user->mutable_user_roles()->Add()->set_id(rs->Get(0));
        }
    }
}

bool AuthorizationDB::GetUserList(AuthDatabaseProto::ParticipantList *list) {
    auto stt = GetSession().PrepareStatement(
        "select u.id, uf.name, u.email from users u "
        "inner join userfts uf on uf.rowid=u.id order by uf.name ");
    auto rs = stt->ExecuteQuery();
    while (rs->NextRow()) {
        auto u = list->add_list();
        u->set_id(rs->Get(0));
        u->set_name(rs->Get(1));
        u->set_email(rs->Get(2));
    }
    return true;
}

int64_t AuthorizationDB::CreateUser(const AuthDatabaseProto::Session *session, const AuthDatabaseProto::User *user, const std::string &chatId) {
    LOG_INFO("Create user (id: {}, name: {}, tel: {})", user->id(), user->name(), user->tel_no());
    auto id = SaveUser(session, user);
    LOG_INFO("Create user returns id = {}", id);
    if (id > 0) {
        NotifyAdminUserCreated(user);
    }
    return id;
}

int64_t AuthorizationDB::SaveUser(const AuthDatabaseProto::Session *session, const AuthDatabaseProto::User *user) {
    LOG_INFO("AuthorizationDB::SaveUser> id: {}, name: {}, tel: {}", user->id(), user->name(), user->tel_no());
    int64_t uid=0;
    bool isNew = true;
    try {
        auto x = GetSession().GetAutoCommitter();
        std::chrono::system_clock::time_point timeAccepted = epochNull;
        uid = to_number<int64_t>(user->id());
        if (uid > 0) {
            auto stt = GetSession().PrepareStatement("select timeAccepted from users where id = @id");
            stt->Bind("@id", user->id());
            auto rs = stt->ExecuteQuery();
            if (!rs->NextRow()) {
                uid = 0;
                timeAccepted = rs->Get<TimePoint>(0);
            }
        }

        auto stt = GetSession().PrepareStatement("select id from users where email=@email");
        stt->Bind("@email", user->email());
        auto rs = stt->ExecuteQuery();
        if (rs->NextRow()) {
            uid = rs->Get<int64_t>(0);
        }
        isNew = uid == 0;

        stt = GetSession().PrepareStatement("replace into userFTS (rowid, name, IC, address, telNo, description) values (@ftsId, @name, @IC, @address, @telNo, @description)");
        stt->Bind("@name", boost::to_upper_copy(user->name()));
        stt->Bind("@IC", boost::erase_all_copy(user->ic(), "-"));
        stt->Bind("@address", boost::to_upper_copy(user->address()));
        stt->Bind("@telNo", boost::erase_all_copy(user->tel_no(), "-"));
        stt->Bind("@description", user->description());

        if (uid <= 0)
            stt->BindNull("@ftsId");
        else
            stt->Bind("@ftsId", uid);
        stt->ExecuteUpdate();
        if (uid <= 0) {
            uid = GetSession().GetLastRowId<int64_t>();
        }
        stt = GetSession().PrepareStatement("replace into users(id, email, timeRegistered, timeAccepted) values(@id, @email, @time, @timeAccepted)");
        stt->Bind("@email", user->email());
        stt->Bind("@id", uid);
        stt->Bind("@time", std::chrono::system_clock::now());
        stt->Bind("@timeAccepted", timeAccepted);
        stt->ExecuteUpdate();
        x->SetOK();
    } catch (const std::exception &e) {
        LOG_ERROR("exception in RegisterEmail: {}", e.what());
        uid = 0;
    } catch (...) {
        LOG_ERROR("unknown exception in RegisterEmail");
        uid = 0;
    }
    if (uid > 0 && session != nullptr) {
        LOG_INFO("Sending message new user");
        auto m = MessageSender::Create(AuthChatProto::EventType::ev_user, *session, true);
        m->Add(isNew ? "created" : "updated", "id", std::to_string(uid));
        m->Commit();
    }
    return uid;
}

bool AuthorizationDB::SaveDependent(const AuthDatabaseProto::Session *session, const std::string &email, AuthDatabaseProto::User *user) {
    if (!SaveUser(session, user)) return false;
    if (user->id().empty()) return false;
    try {
        auto stt = GetSession().PrepareStatement("select id from users where email=@email");
        stt->Bind("@email", email);
        auto parentId = stt->ExecuteScalar();
        if (parentId > 0) {
            stt = GetSession().PrepareStatement("replace into UserDependency(userid, dependentId) values (@uid, @depId)");
            stt->Bind("@uid", parentId);
            stt->Bind("@depId", user->id());
            stt->ExecuteUpdate();
            return true;
        }
    } catch (const std::exception &e) {
        LOG_ERROR("exception in RegisterEmail: {}", e.what());
    } catch (...) {
        LOG_ERROR("unknown exception in RegisterEmail");
    }
    return false;
}

bool AuthorizationDB::GetDependentList(const std::string &email, AuthDatabaseProto::ParticipantList *list) {
    auto stt = GetSession().PrepareStatement(
        "select u2.id, uf.name, u2.email from users u "
        "inner join UserDependency ud on ud.userid=u.id "
        "inner join users u2 on u2.id = ud.dependentId "
        "inner join userfts uf on uf.rowid=u2.id "
        "where u.email = @email order by uf.name ");
    stt->Bind("@email", email);
    auto rs = stt->ExecuteQuery();
    while (rs->NextRow()) {
        auto u = list->add_list();
        u->set_id(rs->Get(0));
        u->set_name(rs->Get(1));
        u->set_email(rs->Get(2));
    }
    return true;
}
