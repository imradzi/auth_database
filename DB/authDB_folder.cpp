
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

#include "sqlexception.h"
#include "authDB.h"
#include "logger.h"

#include <boost/uuid/random_generator.hpp>
extern boost::uuids::random_generator_mt19937 uuidGen;

constexpr int MAX_FILE_PER_FOLDER = 200;

std::string AuthorizationDB::GetFolderNameInternal(const std::string &dbName) {
    if (dbName.empty()) return "";
    try {
        auto stt = GetSession().PrepareStatement(
            "select p.path from databases db "
            "inner join paths p on p.id=db.pathId "
            "where dbname=@db");
        stt->Bind("@db", dbName);
        auto rs = stt->ExecuteQuery();
        if (rs->NextRow()) {
            return rs->Get(0);
        }
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in GetFolderNameInternal: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in GetFolderNameInternal: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in GetFolderNameInternal");
    }
    return "";
}

std::string AuthorizationDB::GetFolderName(const std::string &dbName) {
    try {
        auto authDb = std::make_unique<AuthorizationDB>();
        authDb->Open();
        return authDb->GetFolderNameInternal(dbName);

    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in GetFolderName: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in GetFolderName: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in GetFolderName");
    }
    return "";
}

std::string AuthorizationDB::GetFullPath(const std::string &dbName) {
    auto f = GetFolderName(dbName);
    if (!f.empty()) return GetFullName(f, dbName);
    return f;
}

int64_t AuthorizationDB::GetAvailablePathId() {
    auto rs = GetSession().ExecuteQuery(fmt::format("select pathId, count(*) from databases group by pathId having count(*) < {}", MAX_FILE_PER_FOLDER));
    if (rs->NextRow()) {
        return rs->Get<int64_t>(0);
    }
    std::string uuid;
    auto sttFind = GetSession().PrepareStatement("select 1 from paths where path = @uuid");
    while (true) {
        uuid = FNVHash32(boost::uuids::to_string(uuidGen()));
        sttFind->Bind("@uuid", uuid);
        auto rs = sttFind->Execute();
        if (!rs->NextRow()) break;
    }
    auto stt = GetSession().PrepareStatement("insert into paths(path) values(@uuid)");
    stt->Bind("@uuid", uuid);
    stt->ExecuteUpdate();
    return GetSession().GetLastRowId<int64_t>();
}

auto AuthorizationDB::GetFullName(const std::string &path, const std::string &name) -> std::string {
    std::string sep;
    sep.push_back(std::filesystem::path::preferred_separator);
    return fmt::format("{}{}{}", path, sep, name);
}
