
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

#include "activityTrackkerDB.h"
#include "authDB.h"
#include "guid.h"
#include <boost/uuid/random_generator.hpp>
extern boost::uuids::random_generator_mt19937 uuidGen;

// dbname is unique name

TimePoint GetDateFromIC(const std::string &code) {
    auto fnIsAllDigit = [](const std::string &s) {
        for (const auto &x : s) {
            if (!std::isdigit(x)) return false;
        }
        return true;
    };
    try {
        if (!code.empty() && fnIsAllDigit(code)) {
            auto yr = std::stoi(code.substr(0, 2));
            auto mth = std::stoi(code.substr(2, 2));
            auto day = std::stoi(code.substr(4, 2));
            if (yr < 30)
                yr = 2000 + yr;
            else
                yr = 1900 + yr;

            return GetYMD(std::chrono::year {yr} / mth / day);
        }
    } catch (...) {}
    return epochNull;
}

std::string AuthorizationDB::RegisterDB(const AuthDatabaseProto::DBName *db, CreateDbFunction fnCreateDb) {
    auto GetPathName = [this](int64_t id) -> std::string {
        auto stt = GetSession().PrepareStatement("select path from paths where id=@id");
        stt->Bind("@id", id);
        auto rs = stt->ExecuteQuery();
        if (rs->NextRow()) return rs->Get(0);
        return "";
    };
    LOG_INFO("RegisterDB: name={}, app={}, privacyId={}", db->db_name(), db->app_name(), db->privacy_type().id());
    try {
        auto x = GetSession().GetAutoCommitter();
        std::string dbName;
        if (db->db_name().empty()) {
            auto stt = GetSession().PrepareStatement("select 1 from databases db where db.dbname = @dbname");
            while (true) {
                dbName = FNVHash32(boost::uuids::to_string(uuidGen()));
                stt->Bind("@dbname", dbName);
                auto rs = stt->ExecuteQuery();
                if (!rs->NextRow()) break;
            }
        } else {
            dbName = db->db_name();
            auto stt = GetSession().PrepareStatement("select id from databases db where db.dbname = @dbname");
            stt->Bind("@dbname", dbName);
            auto rs = stt->ExecuteQuery();
            if (rs->NextRow()) {
                LOG_INFO("RegisterDB: db.dbname already exists");
                return "";
            }  // already registered
        }
        auto stt = GetSession().PrepareStatement(
            "insert into databases(pathId, dbname, privacyType, timecreated, appname, master, trans, groupFilter) "
            "values (@path, @dbname, @privacy, @time, @appname, @master, @trans, @filter)");
        auto pathId = GetAvailablePathId();
        stt->Bind("@path", pathId);
        stt->Bind("@dbname", dbName);
        stt->Bind("@time", std::chrono::system_clock::now());
        stt->Bind("@appname", db->app_name());
        stt->Bind("@privacy", db->privacy_type().id());
        stt->Bind("@master", db->master_name());
        stt->Bind("@trans", db->trans_name());
        stt->Bind("@filter", db->group_filter());
        stt->ExecuteUpdate();

        auto dbID = GetSession().GetLastRowId();

        stt = GetSession().PrepareStatement("select id from users where email=@email");
        stt->Bind("@email", db->owner_email());
        auto rs = stt->ExecuteQuery();
        if (!rs->NextRow()) {
            LOG_INFO("RegisterDB: user {} not registered.", db->owner_email());
            return "";
        }
        auto uid = rs->Get<int64_t>(0);

        stt = GetSession().PrepareStatement("insert into dbUsers(dbId, userId, isOwner) values(@id, @uid, true)");
        stt->Bind("@id", dbID);
        stt->Bind("@uid", uid);
        stt->ExecuteUpdate();

        stt = GetSession().PrepareStatement("replace into dbUserRoles(dbId, userId, roleId, timeCreated) values(@id, @uid, @roleid, @time)");
        stt->Bind("@id", dbID);
        stt->Bind("@uid", uid);
        stt->Bind("@roleid", GetRegistry()->GetKey("udbRoles_Owner"));
        stt->Bind("@time", std::chrono::system_clock::now());
        stt->ExecuteUpdate();
        auto folderName = GetPathName(pathId);
        if (!folderName.empty()) {  // create as owner
            std::filesystem::create_directory(folderName);
            if (fnCreateDb != nullptr)
                fnCreateDb(folderName, dbName, db);
            else {
                auto d = std::make_unique<ActivityTrackkerDB>(folderName, dbName);
                d->Open(true);
                d->SetApplicationName(db->app_name());
                d->SetKey("master", db->master_name());
                d->SetKey("trans", db->trans_name());
            }
        }
        x->SetOK();
        LOG_INFO("RegisterDB: registered db in folder : {}", folderName);
        return folderName;
    } catch (const std::exception &e) {
        LOG_ERROR("exception in RegisterDB: {}", e.what());
    } catch (...) {
        LOG_ERROR("unknown exception in RegisterDB");
    }
    return "";
}

std::string AuthorizationDB::DeRegisterDB(const std::string &email, const AuthDatabaseProto::DBName *db, CreateDbFunction fnDeleteDb) {
    try {
        auto x = GetSession().GetAutoCommitter();
        auto stt = GetSession().PrepareStatement(
            "select db.id, p.path, dbu.isOwner, us.id from databases db "
            "inner join paths p on p.id=db.pathId "
            "inner join dbUsers dbu on db.id=dbu.dbId "
            "inner join users us on us.id=dbu.userId "
            "where db.dbname = @dbname and us.email = @email");
        stt->Bind("@dbname", db->db_name());
        stt->Bind("@email", email);
        auto rs = stt->ExecuteQuery();
        if (!rs->NextRow()) return "";  // not found - either path not fould or email not the owner
        auto isOwner = rs->Get<bool>(2);
        auto uid = rs->Get<int64_t>(3);
        auto dbid = rs->Get<int64_t>(0);
        std::string folderName;
        if (isOwner) {
            stt = GetSession().PrepareStatement("delete from dbUsers where dbId=@id");
            stt->Bind("@id", dbid);
            stt->ExecuteUpdate();
            stt = GetSession().PrepareStatement("delete from databases where id=@id");
            stt->Bind("@id", dbid);
            stt->ExecuteUpdate();
            folderName = rs->Get(1);
            if (!folderName.empty()) {
                if (fnDeleteDb != nullptr) fnDeleteDb(folderName, db->db_name(), db);
                std::filesystem::remove(AuthorizationDB::GetFullName(folderName, db->db_name()));
            }
        } else {
            stt = GetSession().PrepareStatement("delete from dbUsers where dbId=@id and userId=@uid");
            stt->Bind("@id", dbid);
            stt->Bind("@uid", uid);
            stt->ExecuteUpdate();
        }
        x->SetOK();
        return folderName;
    } catch (const std::exception &e) {
        LOG_ERROR("exception in DeRegisterDB: {}", e.what());
    } catch (...) {
        LOG_ERROR("unknown exception in DeRegisterDB");
    }
    return "";
}

int AuthorizationDB::GetDBList(const std::string &email, const std::string &groupFilter, google::protobuf::RepeatedPtrField<AuthDatabaseProto::DBName> *response) {
    try {
        auto stt = GetSession().PrepareStatement(
            "select p.path, db.dbname, db.privacyType, us.email, master, trans, appname, groupFilter "
            "from databases db "
            "left join paths p on p.id=db.pathId "
            "left join dbUsers dbu on (dbu.dbId = db.id) "
            "left join users us on us.id=dbu.userId "
            "where db.groupFilter=@filter and (us.email = @email or db.privacyType in (@public, @restricted)) order by db.appname");
        stt->Bind("@email", email);
        stt->Bind("@filter", groupFilter);
        stt->Bind("@public", GetRegistry()->GetKey("dbPrivacy_Public"));
        stt->Bind("@restricted", GetRegistry()->GetKey("dbPrivacy_Restricted"));
        auto rs = stt->ExecuteQuery();
        response->Clear();
        while (rs->NextRow()) {
            auto dbName = response->Add();
            dbName->set_folder_name(rs->Get(0));
            dbName->set_db_name(rs->Get(1));
            dbName->mutable_privacy_type()->set_id(rs->Get(2));
            dbName->set_owner_email(rs->Get(3));
            dbName->set_master_name(rs->Get(4));
            dbName->set_trans_name(rs->Get(5));
            dbName->set_app_name(rs->Get(6));
            dbName->set_group_filter(rs->Get(7));
        }
        LOG_INFO("GetDBList for {} retuns {} ", email, response->size());
        return response->size();
    } catch (const std::exception &e) {
        LOG_ERROR("exception in GetDBList: {}", e.what());
    } catch (...) {
        LOG_ERROR("unknown exception in GetDBList");
    }
    return 0;
}

int AuthorizationDB::GetDBList(google::protobuf::RepeatedPtrField<AuthDatabaseProto::DBName> *response) {
    try {
        auto rs = GetSession().ExecuteQuery("select p.path, db.dbname, appname from databases db inner join paths p on p.id=db.pathId");
        response->Clear();
        while (rs->NextRow()) {
            auto dbName = response->Add();
            dbName->set_folder_name(rs->Get(0));
            dbName->set_db_name(rs->Get(1));
            dbName->set_app_name(rs->Get(2));
        }
        return response->size();
    } catch (const std::exception &e) {
        LOG_ERROR("exception in GetDBList: {}", e.what());
    } catch (...) {
        LOG_ERROR("unknown exception in GetDBList");
    }
    return 0;
}

bool AuthorizationDB::ShareDB(const std::string &email, const std::string &dbname, const google::protobuf::RepeatedPtrField<std::string> &emails) {
    try {
        auto fnGetUid = [](std::shared_ptr<wpSQLStatement> stt, const std::string &email) -> std::string {
            stt->Bind("@email", email);
            auto rs = stt->ExecuteQuery();
            if (!rs->NextRow()) return "";
            return rs->Get(0);
        };

        auto stt = GetSession().PrepareStatement(
            "select * from databases db "
            "inner join db_users dbu on dbu.dbId=db.id "
            "inner join users us on us.id=dbu.userId "
            "where us.email = @email and db.dbname = @dbname and dbu.isOwner=1");
        stt->Bind("@email", email);
        stt->Bind("@dbname", dbname);
        auto rs = stt->ExecuteQuery();
        if (rs->NextRow()) return false;  // no db found return

        stt = GetSession().PrepareStatement("select id from databases where dbname=@dbname");
        stt->Bind("@dbname", dbname);
        rs = stt->ExecuteQuery();
        if (!rs->NextRow()) return false;  // not found in existing databse;
        auto dbId = rs->Get<int64_t>(0);

        auto sttGetUid = GetSession().PrepareStatement("select id from users where email=@email");

        stt = GetSession().PrepareStatement("insert into dbUsers(dbId, userId) values(@id, @uid)");
        for (auto s : emails) {
            stt->Bind("@id", dbId);
            stt->Bind("@uid", fnGetUid(sttGetUid, s));
            stt->ExecuteUpdate();
        }
        return true;
    } catch (const std::exception &e) {
        LOG_ERROR("exception in ShareDB: {}", e.what());
    } catch (...) {
        LOG_ERROR("unknown exception in ShareDB");
    }
    return false;
}
