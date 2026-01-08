#pragma once
#include "net.h"
#include "rDb.h"
#include <vector>
#include <filesystem>

#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "auth_database.pb.h"
#include "auth_database.grpc.pb.h"


typedef std::function<void(const std::string&, const std::string&, const AuthDatabaseProto::DBName *)> CreateDbFunction;

class AuthorizationDB : public DB::SQLiteBase {
    static std::string default_google_credential_file;
protected:
    std::vector<DB::DBObjects> objectList() const override;
    // int GetPrivacyType(AuthDatabaseProto::PrivacyType protoType);
    // AuthDatabaseProto::PrivacyType GetPrivacyType(int type);

public:
    static std::string CheckFTSCharacters(const std::string& matchStr);
protected:
    CreateDbFunction fnCreateDb;
    CreateDbFunction fnDeleteDb;
public:
    AuthorizationDB(CreateDbFunction fn = nullptr, CreateDbFunction fnDel=nullptr) : DB::SQLiteBase("authorization_internal.db"), fnCreateDb(fn), fnDeleteDb(fn) {}
    virtual ~AuthorizationDB() { Close(); }
    void CheckStructure() override;
    static auto GetFullName(const std::string& path, const std::string& name) -> std::string;

public:
    std::string RegisterEmail(const AuthDatabaseProto::Session *session, AuthDatabaseProto::User* user, const std::string& deviceToken, const std::string &appName, const std::string &chatId);
    bool DeRegisterDevice(const AuthDatabaseProto::User* user);
    bool DeRegisterDevice(const std::string& deviceToken);
    std::string RegisterDB(const AuthDatabaseProto::DBName* db, CreateDbFunction fnCreateDb = nullptr);  // returns folder name
    std::string DeRegisterDB(const std::string& email, const AuthDatabaseProto::DBName* db, CreateDbFunction fnDeleteDb = nullptr);
    void SetApplicationName(const std::string& dbName, const std::string& appName);
    bool ShareDB(const std::string& email, const std::string& dbname, const google::protobuf::RepeatedPtrField<std::string>& emails);
    int GetDBList(const std::string& email, const std::string &groupFilter, google::protobuf::RepeatedPtrField<AuthDatabaseProto::DBName>* response);
    int GetDBList(google::protobuf::RepeatedPtrField<AuthDatabaseProto::DBName>* response);
    bool ApproveEmail(const std::string& email);
    bool IsEmailApproved(const std::string& email);
    bool IsAuthorizer(const std::string& email);
    void SetRoleAuthorizer(const std::string& email) {SetRole(email, GetRegistry()->GetKey("uRoles_Authorizer"));}
    void SetRoleAdmin(const std::string& email) { SetRole(email, GetRegistry()->GetKey("uRoles_Admin")); }
    void RevokeRoleAdmin(const std::string& email) { ClearRole(email, GetRegistry()->GetKey("uRoles_Admin")); }
    void SetRole(const std::string& email, const std::string& roleId);
    void ClearRole(const std::string& email, const std::string& roleId);

    void SetDBRoleAdmin(const std::string& dbName, const std::string& email) { SetDBRole(dbName, email, GetRegistry()->GetKey("udbRoles_Admin")); }
    void SetDBRoleOwner(const std::string& dbName, const std::string& email) { SetDBRole(dbName, email, GetRegistry()->GetKey("udbRoles_Owner")); }
    void SetDBRoleAccount(const std::string& dbName, const std::string& email) { SetDBRole(dbName, email, GetRegistry()->GetKey("udbRoles_Account")); }
    void RevokeDBRoleAdmin(const std::string& dbName, const std::string& email) { ClearDBRole(dbName, email, GetRegistry()->GetKey("udbRoles_Admin")); }
    void RevokeDBRoleOwner(const std::string& dbName, const std::string& email) { ClearDBRole(dbName, email, GetRegistry()->GetKey("udbRoles_Owner")); }
    void RevokeDBRoleAccount(const std::string& dbName, const std::string& email) { ClearDBRole(dbName, email, GetRegistry()->GetKey("udbRoles_Account")); }

    void SetDBRole(const std::string& dbName, const std::string& email, const std::string& roleId);
    void ClearDBRole(const std::string& dbName, const std::string& email, const std::string& roleId);

    std::string GetFolderNameInternal(const std::string& dbName);
    static std::string GetFolderName(const std::string& dbName);
    static std::string GetFullPath(const std::string& dbName);

    int64_t GetAvailablePathId();

    void GetUser(const AuthDatabaseProto::Session &session, AuthDatabaseProto::User* user);
    void GetUserRequiresApproval(google::protobuf::RepeatedPtrField<AuthDatabaseProto::User>* user);

    int64_t CreateUser(const AuthDatabaseProto::Session* session, const AuthDatabaseProto::User* user, const std::string& chatId);
    int64_t SaveUser(const AuthDatabaseProto::Session *session, const AuthDatabaseProto::User* user);
    bool GetUserList(AuthDatabaseProto::ParticipantList* list);
    bool SaveDependent(const AuthDatabaseProto::Session* session, const std::string& email, AuthDatabaseProto::User* user);
    bool GetDependentList(const std::string& email, AuthDatabaseProto::ParticipantList* list);

    std::shared_ptr<wpSQLStatement> GetDBUserRoles(const std::string& dbName, AuthDatabaseProto::User* user, std::shared_ptr<wpSQLStatement> stt);

    bool IsValidClientToken(const std::string& token, const std::string& email);
    bool IsClientTokenExists(const std::string& email);

    bool CheckClientToken(const std::string& idToken, const std::string& email);
    bool SendNotification(const std::string& deviceToken, const std::string& title, const std::string& message);
    bool SendGroupNotification(const std::vector<std::string>& deviceTokens, const std::string& title, const std::string& message);
    bool NotifyAdminUserCreated(const AuthDatabaseProto::User* user);

    void GetTypeList(const std::string& regKey, AuthDatabaseProto::TypeList* result) {
        GetTypeList(regKey, result->mutable_list());
    }
    std::tuple<bool, std::shared_ptr<wpSQLStatement>> GetTypeRecord(const std::string& id, AuthDatabaseProto::TypeRecord* rec, std::shared_ptr<wpSQLStatement> stt);  // stt = GetSession().PrepareStatement("select id, parentID, code, name, limitvalue, defaultvalue from types where id = @id")
    void GetTypeList(const std::string& regKey, google::protobuf::RepeatedPtrField<AuthDatabaseProto::TypeRecord>* list);
};