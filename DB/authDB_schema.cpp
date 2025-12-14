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

std::vector<DB::DBObjects> AuthorizationDB::objectList() const {
    std::vector<DB::DBObjects> list {
        {"ul_keys", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "key text, "
             "value text, "
             "description text, "
             "isDeleted integer, "
             "unique(key) "
             ")",
                "create index idx_<TABLENAME>_key on <TABLENAME>(key)"}},

        {"UL_LocalKeys", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "key text, "
             "value text, "
             "description text, "
             "isDeleted integer, "
             "unique(key) "
             ")",
                "create index idx_<TABLENAME>_key on <TABLENAME>(key)"}},

        {"Types", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "parentID integer, "
             "code text, "
             "name text, "
             "limitvalue text, "
             "defaultvalue text, "
             "isDeleted integer, "
             "foreign key(parentID) references types(id)"
             ")"}},

        {"UserFTS", DB::Table,
            {"create virtual table <TABLENAME> using FTS5(name, IC, address, telNo, description)"}},

        {"Users", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "  // also using same for ftsId,
             "email text, "
             "timeRegistered integer, "
             "timeAccepted integer "
             ")",
                "create index idx_<TABLENAME>_email on <TABLENAME>(email)"}},

        {"UserDependency", DB::Table,
            {"create table <TABLENAME>("
             "userid integer, "
             "dependentId integer, "
             "primary key(userId, dependentId) "
             ")"}},

        {"UserIdentity", DB::Table,
            {"create table <TABLENAME>("
             "userid integer, "
             "identity text, "  // identity can be QR or NFC uuid
             "isNFC integer "
             ")",
                "create index idx_<TABLENAME>_uid on <TABLENAME>(userid)",
                "create index idx_<TABLENAME>_identity on <TABLENAME>(identity)"}},

        {"userDeviceTokens", DB::Table,
            {"create table <TABLENAME>("
             "userId int references Users(id), "
             "deviceToken text, "
             "primary key (userId, deviceToken) "
             ")",
                "create index idx_<TABLENAME>_uid on <TABLENAME>(userId)",
                "create index idx_<TABLENAME>_did on <TABLENAME>(deviceToken)"}},

        {"paths", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "path text "
             ")"}},

        {"databases", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "pathId int references paths(id), "
             "dbname text, "
             "master text, "
             "trans text, "
             "appname text,"
             "groupFilter text,"
             "privacyType int references types(id),"
             "timeCreated int, "
             "unique(dbname) "
             ")",
                "create index idx_<TABLENAME>_name on <TABLENAME>(dbname)",
                "create index idx_<TABLENAME>_path on <TABLENAME>(pathId)"}},

        {"userRoles", DB::Table,
            {"create table <TABLENAME>("
             "userId integer references users(id), "
             "roleId integer references types(id), "
             "timeCreated integer, "
             "primary key(userId, roleId) "
             ")",
                "create index idx_<TABLENAME>_uid on <TABLENAME>(userId)"}},

        {"dbUserRoles", DB::Table,
            {"create table <TABLENAME>("
             "userId integer references users(id), "
             "dbId integer references databases(id), "
             "roleId integer references types(id), "  // dbUserRoles id
             "timeCreated integer, "
             "timeApproved integer, "
             "primary key(userId, dbId, roleId) "
             ")",
                "create index idx_<TABLENAME>_id on <TABLENAME>(dbId)",
                "create index idx_<TABLENAME>_uid on <TABLENAME>(userId)"}},

        {"dbUsers", DB::Table,
            {"create table <TABLENAME>("
             "dbId integer references databases(id), "
             "userId integer references users(id), "
             "isOwner int, "
             "primary key(dbId, userId) "
             ")",
                "create index idx_<TABLENAME>_id on <TABLENAME>(dbId)",
                "create index idx_<TABLENAME>_uid on <TABLENAME>(userId)"}},

        {"idTokens", DB::Table,
            {"create table <TABLENAME>("
             "email text primary key, "
             "dateChecked integer "
             ")"}},

        {"failedToyyibMessages", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "timeCreated integer, "
             "contentType text, "
             "message text "
             ")"}},

        {"toyyibMessages", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "timeCreated integer, "
             "message text "
             ")"}},

    };
    auto ol = DB::SQLiteBase::objectList();
    ol.insert(ol.end(), list.begin(), list.end());
    return ol;
}