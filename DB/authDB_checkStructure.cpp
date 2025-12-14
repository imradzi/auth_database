
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
#include "activityTrackkerDB.h"

size_t to_uppercase_and_count(std::string &str) {
    size_t modified = 0;
    for (char &ch : str) {
        const unsigned char uch = static_cast<unsigned char>(ch);
        if (std::islower(uch)) {
            ch = static_cast<char>(std::toupper(uch));
            ++modified;
        }
    }
    return modified;
}

extern int CreateDbFromPPOS(std::function<void(AuthDatabaseProto::DBName *)>);

void AuthorizationDB::CheckStructure() {
    DB::SQLiteBase::CheckStructure();
    auto x = GetSession().GetAutoCommitter();
    auto typeReg = DB::TypeRegistry(*this);
    auto typeId = typeReg.SetGroup("userRoleGroupID", "User Roles Group ID");
    typeReg.Set("uRoles_Admin", "Admin", "Admin", "", typeId);
    typeReg.Set("uRoles_CreateDB", "CreateDB", "Create DB", "", typeId);
    typeReg.Set("uRoles_Authorizer", "emailAuthorizer", "email Authorizer", "", typeId);

    typeId = typeReg.SetGroup("userDBRoleGroupID", "User DB Roles Group ID");
    typeReg.Set("udbRoles_Owner", "Owner", "DB Owner", "", typeId);
    typeReg.Set("udbRoles_Authorizer", "Authorizer", "email Authorizer", "", typeId);
    typeReg.Set("udbRoles_Admin", "Admin", "Admin", "", typeId);
    typeReg.Set("udbRoles_Moderator", "Moderator", "Moderator", "", typeId);
    typeReg.Set("udbRoles_Primary", "Primary", "Primary", "", typeId);
    typeReg.Set("udbRoles_Merchant", "Merchant", "Merchant", "", typeId);
    typeReg.Set("udbRoles_Participant", "Participant", "Participant", "", typeId);
    typeReg.Set("udbRoles_Account", "Account", "Account", "", typeId);

    typeId = typeReg.SetGroup("userConnectAsGroupID", "User Connect As Group ID");
    typeReg.Set("udbConnectAs_Admin", "Admin", "Administrator", "", typeId);
    typeReg.Set("udbConnectAs_Account", "Account", "Accounting", "", typeId);
    typeReg.Set("udbConnectAs_Customer", "Customer", "Customer", "", typeId);
    typeReg.Set("udbConnectAs_SalesRep", "SalesRep", "Sales Rep (Supplier)", "", typeId);
    typeReg.Set("udbConnectAs_CreditCustomer", "CreditCustomer", "Wholesales Customer", "", typeId);
    typeReg.Set("udbConnectAs_SalesPromoter", "SalesPromoter", "Sales Rep (Own)", "", typeId);
    typeReg.Set("udbConnectAs_InventoryController", "InventoryController", "InventoryController", "", typeId);

    typeId = typeReg.SetGroup("dbPrivacyType", "Privacy Type");
    typeReg.Set("dbPrivacy_Public", "Public", "Public", "", typeId);
    typeReg.Set("dbPrivacy_Private", "Private", "Private", "", typeId);
    typeReg.Set("dbPrivacy_Restricted", "Restricted", "Restricted", "", typeId);

    auto reg = GetRegistry();
    if (reg->GetKey("app_firebase_admin_credential_json_file").empty())
        reg->SetKey("app_firebase_admin_credential_json_file", default_google_credential_file);

    if (GetSession().ExecuteScalar("select count(*) from users") == 0) {
        auto user = std::make_unique<AuthDatabaseProto::User>();
        user->set_email(ActivityTrackkerDB::OWNER_EMAIL);
        user->set_name(ActivityTrackkerDB::OWNER_NAME);
        user->set_tel_no(ActivityTrackkerDB::OWNER_PHONE);
        SaveUser(nullptr, user.get());
    }
    auto privacyPublic = reg->GetKey<int64_t>("dbPrivacy_Public");

    auto fnSave = [&](AuthDatabaseProto::DBName *db) {
        db->set_db_name("");  // use default.
        db->set_owner_email(ActivityTrackkerDB::OWNER_EMAIL);
        db->mutable_privacy_type()->set_id(std::to_string(privacyPublic));  // need to create activitytrakkerdb  and populate the keys.
        RegisterDB(db); // returns folder name
    };

    if (GetSession().ExecuteScalar("select count(*) from databases") == 0) {
        if (CreateDbFromPPOS(fnSave) <= 0) {
            auto db = std::make_unique<AuthDatabaseProto::DBName>();
            db->set_db_name("");  // use default.
            db->set_app_name(ActivityTrackkerDB::APPNAME);
            db->set_owner_email(ActivityTrackkerDB::OWNER_EMAIL);
            db->mutable_privacy_type()->set_id(std::to_string(privacyPublic));  // need to create activitytrakkerdb  and populate the keys.
            RegisterDB(db.get(), fnCreateDb);  // returns folder name
        }
    }
    if (!reg->IsKeyExists("cleanup_ic_and_uppercase")) {
        auto rs = GetSession().ExecuteQuery("select rowid, IC, name, address, telNo from userFTS");
        auto stt = GetSession().PrepareStatement("update userFTS set ic=@ic, name=@name, telNo=@tel, address=@address where rowid=@rowid");
        while (rs->NextRow()) {
            auto rowid = rs->Get<int64_t>(0);
            std::string ic = rs->Get(1);
            std::string name = rs->Get(2);
            std::string address = rs->Get(3);
            std::string tel = rs->Get(4);
            bool toUpdate = false;
            if (ic.contains("-")) {
                toUpdate = true;
                boost::erase_all(ic, "-");
            }
            if (tel.contains("-")) {
                toUpdate = true;
                boost::erase_all(tel, "-");
            }

            auto fnCheckUpperCase = [&](std::string &c) {
                auto nUpdated = to_uppercase_and_count(c);
                return nUpdated > 0 || toUpdate;
            };

            toUpdate = fnCheckUpperCase(name);
            toUpdate = fnCheckUpperCase(address);

            if (toUpdate) {
                stt->Bind("@ic", ic);
                stt->Bind("@name", name);
                stt->Bind("@tel", tel);
                stt->Bind("@address", address);
                stt->Bind("@rowid", rowid);
                stt->ExecuteUpdate();
            }
        }
        reg->SetKey("cleanup_ic_and_uppercase", 1);
    }

    x->SetOK();
}
