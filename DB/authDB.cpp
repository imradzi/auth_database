
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

#include <boost/tokenizer.hpp>
#include "protofunctions.h"

#include "authDB.h"

void AuthorizationDB::GetTypeList(const std::string &regKey, google::protobuf::RepeatedPtrField<AuthDatabaseProto::TypeRecord> *list) {
    auto parentId = GetRegistry()->GetKey(regKey);
    auto stt = GetSession().PrepareStatement("select id, parentID, code, name, limitvalue, defaultvalue from types where parentId = @parentId and isDeleted is NULL");
    stt->Bind("@parentId", parentId);
    auto rs = stt->ExecuteQuery();
    while (rs->NextRow()) {
        auto trec = list->Add();
        trec->set_id(rs->Get(0));
        trec->mutable_parent()->set_id(rs->Get(1));
        trec->set_code(rs->Get(2));
        trec->set_name(rs->Get(3));
        trec->set_limit_value(rs->Get(4));
        trec->set_default_value(rs->Get(5));
    }
}

std::tuple<bool, std::shared_ptr<wpSQLStatement>> AuthorizationDB::GetTypeRecord(const std::string& id, AuthDatabaseProto::TypeRecord* rec, std::shared_ptr<wpSQLStatement> stt) {
    if (stt == nullptr) stt = GetSession().PrepareStatement("select id, parentID, code, name, limitvalue, defaultvalue from types where id = @id");
    stt->Bind("@id", id);
    auto rs = stt->ExecuteQuery();
    bool res = false;
    if (rs->NextRow()) {
        rec->set_id(rs->Get(0));
        rec->mutable_parent()->set_id(rs->Get(1));
        rec->set_code(rs->Get(2));
        rec->set_name(rs->Get(3));
        rec->set_limit_value(rs->Get(4));
        rec->set_default_value(rs->Get(5));
        res = true;
    }
    return {res, stt};
}

bool AuthorizationDB::DeRegisterDevice(const std::string &deviceToken) {
    try {
        if (!deviceToken.empty()) {
            auto stt = GetSession().PrepareStatement("delete from userDeviceTokens where deviceToken=@token");
            stt->Bind("@token", deviceToken);
            stt->ExecuteUpdate();
        }
        return true;
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in DeRegisterDevice by deviceToken: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in DeRegisterDevice by deviceToken: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in DeRegisterDevice by deviceToken");
    }
    return false;
}

bool AuthorizationDB::DeRegisterDevice(const AuthDatabaseProto::User *user) {
    try {
        auto stt = GetSession().PrepareStatement("delete from userDeviceTokens where userId=(select id from users where email=@email)");
        stt->Bind("@email", user->email());
        stt->ExecuteUpdate();
        return true;
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in DeRegisterDevice by email: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in DeRegisterDevice by email: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in DeRegisterDevice by email");
    }
    return false;
}

std::string AuthorizationDB::RegisterEmail(const AuthDatabaseProto::Session *session, AuthDatabaseProto::User *user, const std::string &deviceToken, const std::string &appName, const std::string &chatId) {
    try {
        if (user->email().empty()) return "";
        auto stt = GetSession().PrepareStatement("select id from users where email = @email");
        stt->Bind("@email", user->email());
        auto rs = stt->ExecuteQuery();
        int64_t uid = 0;
        if (rs->NextRow()) {
            uid = rs->Get<int64_t>(0);
        } else {
            uid = CreateUser(session, user, chatId);
        }
        ShowLog(fmt::format("RegisterEmail: UserFTS updated: {} uid: {}", user->email(), uid));
        if (!deviceToken.empty()) {
            DeRegisterDevice(deviceToken);
            stt = GetSession().PrepareStatement("replace into userDeviceTokens(userId, deviceToken) values(@uid, @token)");
            stt->Bind("@uid", uid);
            stt->Bind("@token", deviceToken);
            stt->ExecuteUpdate();
            SendNotification(deviceToken, appName, fmt::format("{} successfully logged in", user->name()));
        }
        return std::to_string(uid);
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in RegisterEmail: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in RegisterEmail: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in RegisterEmail");
    }
    return "";
}

void AuthorizationDB::SetApplicationName(const std::string &dbName, const std::string &appName) {
    try {
        auto stt = GetSession().PrepareStatement("update databases set appname=@appname where dbname=@dbname");
        stt->Bind("@dbname", dbName);
        stt->Bind("@appname", appName);
        stt->ExecuteUpdate();
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in SetApplicationName: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in SetApplicationName: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in SetApplicationName ");
    }
}

bool AuthorizationDB::ApproveEmail(const std::string &email) {
    try {
        auto stt = GetSession().PrepareStatement("select * from users where email = @email");
        stt->Bind("@email", email);
        auto rs = stt->ExecuteQuery();
        if (!rs->NextRow()) return false;  // email not exists;

        stt = GetSession().PrepareStatement("update users set timeAccepted=@time where email = @email");
        stt->Bind("@email", email);
        stt->Bind("@time", std::chrono::system_clock::now());
        stt->ExecuteUpdate();
        return true;
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in ApproveEmail: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in ApproveEmail: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in ApproveEmail");
    }
    return false;
}

bool AuthorizationDB::IsEmailApproved(const std::string &email) {
    try {
        if (GetRegistry()->GetKey("mustValidateEmail", true)) {
            auto stt = GetSession().PrepareStatement("select timeAccepted, timeRegistered from users where email = @email and timeAccepted is not null");
            stt->Bind("@email", email);
            auto rs = stt->ExecuteQuery();
            if (!rs->NextRow()) return false;  // email not exists;
            auto approveOn = rs->Get<int64_t>(0);
            auto registerOn = rs->Get<int64_t>(1);
            return approveOn > registerOn;
        }
        return true;
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in IsEmailApproved: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in IsEmailApproved: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in IsEmailApproved");
    }
    return false;
}

bool AuthorizationDB::IsAuthorizer(const std::string &email) {
    try {
        auto stt = GetSession().PrepareStatement(
            "select * from users u "
            "inner join userRoles ur on ur.userId=u.id"
            "where u.email = @email and ur.roleId = @role");
        stt->Bind("@email", email);
        stt->Bind("@role", GetRegistry()->GetKey("uRoles_Authorizer"));

        auto rs = stt->ExecuteQuery();
        if (!rs->NextRow()) return false;  // email not exists;
        return rs->Get<bool>(0);
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in IsAuthorizer: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in IsAuthorizer: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in IsAuthorizer");
    }
    return false;
}

void AuthorizationDB::SetRole(const std::string &email, const std::string &roleId) {
    try {
        auto stt = GetSession().PrepareStatement("replace into userRoles (userId, roleId) values((select id from users where email=@email), @role)");
        stt->Bind("@email", email);
        stt->Bind("@role", roleId);
        stt->ExecuteUpdate();
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in SetRole: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in SetRole: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in SetRole");
    }
}

void AuthorizationDB::ClearRole(const std::string &email, const std::string &roleId) {
    try {
        auto stt = GetSession().PrepareStatement("delete from userRoles where userId = (select id from users where email=@email) and roleid = @role");
        stt->Bind("@email", email);
        stt->Bind("@role", roleId);
        stt->ExecuteUpdate();
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in ClearRole: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in ClearRole: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in ClearRole");
    }
}

void AuthorizationDB::SetDBRole(const std::string &dbName, const std::string &email, const std::string &roleId) {
    try {
        auto stt = GetSession().PrepareStatement(
        "replace into dbUserRoles (dbId, userId, roleId, timeCreated, timeApproved) values("
        "(select id from databases where dbname=@dbname), "
        "(select id from users where email=@email), "
        "@role, @date, @date)");
        stt->Bind("@email", email);
        stt->Bind("@role", roleId);
        stt->Bind("@dbname", dbName);
        stt->Bind("@date", std::chrono::system_clock::now());
        stt->ExecuteUpdate();
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in SetDBRole: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in SetDBRole: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in SetRole");
    }
}

void AuthorizationDB::ClearDBRole(const std::string &dbName, const std::string &email, const std::string &roleId) {
    try {
        auto stt = GetSession().PrepareStatement(
        "delete from dbUserRoles where "
        "userId = (select id from users where email=@email) "
        "and dbId = (select id from databases where dbName=@dbname) "
        "and roleid = @role");
        stt->Bind("@dbname", dbName);
        stt->Bind("@email", email);
        stt->Bind("@role", roleId);
        stt->ExecuteUpdate();
    } catch (wpSQLException &e) {
        ShowLog(fmt::format("sql exception in ClearDBRole: {}", e.message));
    } catch (std::exception &e) {
        ShowLog(fmt::format("exception in ClearDBRole: {}", e.what()));
    } catch (...) {
        ShowLog("unknown exception in ClearDBRole");
    }
}

std::string AuthorizationDB::CheckFTSCharacters(const std::string& matchStr) {
    std::string res;
    int sz = matchStr.length();
    if (sz == 0) return "";
    bool prevBlank = false;
    for (const auto &it : matchStr) {
        bool isSpc = isspace(it);
        if (isSpc && prevBlank) continue;
        auto v = it;
        if (isalnum(v)) {
            res.push_back(v);
            prevBlank = isSpc;
            continue;
        }
        switch (v) {
            case ',':
            case '.':
            case '/':
            case '-':
            case ':':
            case ';':
            case '\'':
            case '"':
            case '(':
            case ')':
            case '<':
            case '>':
            case '{':
            case '}':
            case '!':
            case '|':
            case '~':
            case '^':
            case '`':
            case '%':
            case '?':
            case '\\':
            case '@':
            case '&':
            case '$':
            //case '*':
            case '#':
            case '=':
            case '[':
            case ']':
            case '+':
                res.append(" ");
                isSpc = true;
                break;
            default:
                if (std::isprint(v))
                    res.push_back(std::tolower(v));
                else {
                    res.append(" ");
                    isSpc = true;
                }
                break;
        }
        prevBlank = isSpc;
    }
    boost::tokenizer<boost::char_separator<char>> tok(res, boost::char_separator<char>(" ", "", boost::drop_empty_tokens));
    std::string res2;
    std::string delim;
    int i = 0;
    for (auto const &t : tok) {
        if (t.size() > 1) {
            i++;
            if (t.find("*") != t.length() - 1) {
                boost::replace_all(res, "*", " ");
            }
            res2.append(delim + t);
            delim = " ";
        }
    }
    return res2;
}
