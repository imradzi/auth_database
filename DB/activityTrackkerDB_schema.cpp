
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
#include <boost/tokenizer.hpp>

std::vector<DB::DBObjects> ActivityTrackkerDB::objectList() const {
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

        {"entityFTS", DB::Table,
            {"create virtual table <TABLENAME> using FTS5(code, name, description, telephone, address, addressGroup, houseNo)"}},  // code is IC

        // entity can appears in more than 1 types
        {"entity", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "ftsId integer references entityfts(rowid), "
             "activeFlag text,"
             "isDeleted integer, "
             "periodCreated integer, "
             "dateCreated integer, "
             "dateOfBirth integer "
             ")",
                "create index idx_<TABLENAME>_ftsId on <TABLENAME>(ftsId)"}},

        {"entitytypes", DB::Table,
            {"create table <TABLENAME>("
             "entityid integer references entity(id), "
             "typeId integer references types(id), "
             "primary key(entityId, typeId) "
             ")",
                "create index idx_<TABLENAME>_key on <TABLENAME>(entityId, typeId)",
                "create index idx_<TABLENAME>_parentId on <TABLENAME>(typeId)"}},

        {"entityrelationship", DB::Table,
            {"create table <TABLENAME>("
             "entityid integer references entity(id), "
             "relatedTo integer references entity(id), "
             "typeId integer references types(id), "
             "primary key(entityId, relatedTo) "
             ")",
                "create index idx_<TABLENAME>_key1 on <TABLENAME>(entityId, relatedTo)",
                "create index idx_<TABLENAME>_key2 on <TABLENAME>(relatedTo, entityId)"}},

        {"Item", DB::Table,
            {"create table <TABLENAME>("
             "entityId integer primary key references entity(id), "  // same rowid in itemfts
             "value double, "
             "dateCreated integer, "
             "isDeleted integer "
             ")"}},

        {"Event", DB::Table,
            {"create table <TABLENAME>("
             "entityid integer primary key references entity(id), "  // use for ftsId same id key.
             "isRecurring integer, "
             "privacyType integer, "
             "notifyPrimary integer, "
             "dateCreated integer, "
             "isDeleted integer "
             ")"}},

        {"EventModerator", DB::Table,
            {"create table <TABLENAME>("
             "eventID integer, "
             "participantId integer "
             ")"}},

        {"EventParticipant", DB::Table,
            {"create table <TABLENAME>("
             "eventID integer, "
             "participantId integer "
             ")"}},

        {"Activity", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "eventId integer, "
             "dateCreated integer "
             ")"}},

        {"ActivityParticipant", DB::Table,
            {"create table <TABLENAME>("
             "id integer primary key, "
             "activityId integer, "
             "participantId integer "
             ")"}},

        {"ActivityParticipantDetail", DB::Table,
            {"create table <TABLENAME>("
             "activityParticipantId integer primary key, "
             "itemId integer, "
             "value double"
             ")"}},

    };
    auto ol = DB::SQLiteBase::objectList();
    ol.insert(ol.end(), list.begin(), list.end());
    return ol;
};
