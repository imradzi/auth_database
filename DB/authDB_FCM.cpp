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
#include <boost/asio.hpp>
#include <boost/asio/readable_pipe.hpp>
#include <boost/asio/writable_pipe.hpp>
#include <boost/process.hpp>
#include <filesystem>
#include <future>
#include <iostream>
#include <string>

#include "authDB.h"
using namespace std::chrono_literals;

std::tuple<std::string, std::string> executeCommand(const std::string& command, const std::vector<std::string>& args, const std::vector<std::string>& input) {
    std::string output, error_output;
    try {
        boost::asio::io_context ctx;
        boost::asio::readable_pipe pipeOut(ctx);
        boost::asio::writable_pipe pipeIn(ctx);
        
        // boost::process::v2::process proc(ctx, "/usr/bin/g++", {"--version"}, boost::process::process_stdio {pipeIn, pipeOut, pipeOut});
        boost::process::v2::process proc(ctx, command, args, boost::process::process_stdio {pipeIn, pipeOut, pipeOut});

        //TODO: check if the pipes should be populated before or after the process is started
        for (auto& str : input) {
            pipeIn.write_some(boost::asio::buffer(str + "\n"));
        }

        std::vector<char> buffer(1024);  // Buffer to hold read data
        boost::system::error_code ec;
        size_t bytes_read;
        do {
            bytes_read = pipeOut.read_some(boost::asio::buffer(buffer), ec);
            if (ec) {
                if (ec == boost::asio::error::eof) {
                    break;
                } else {
                    error_output = ec.message();
                    break;
                }
            }
            output.append(buffer.data(), bytes_read);
        } while (bytes_read > 0);

        do {
            bytes_read = pipeOut.read_some(boost::asio::buffer(buffer), ec);
            if (ec) break;
            error_output.append(buffer.data(), bytes_read);
        } while (bytes_read > 0);

        proc.wait();
    } catch (const std::exception& e) {
        LOG_ERROR("executeCommand exception: {}", e.what());
        return {"", e.what()};
    } catch (...) {
        LOG_ERROR("executeCommand unknown exception");
        return {"", "Unknown error"};
    }
    return {output, error_output};
}

bool AuthorizationDB::CheckClientToken(const std::string& idToken, const std::string& email) {
    LOG_INFO("CheckClientToken - Verifying token for email: {}", email);
    
    // Use shared lazy-initialized Firebase verifier
    if (!EnsureFirebaseVerifier()) {
        return false;
    }
    
    // Call Firebase Admin API to verify the token
    auto [success, verified_email] = sFirebaseVerifier->VerifyIdToken(idToken, email);
    
    if (!success) {
        LOG_ERROR("CheckClientToken - Firebase verification failed: {}", verified_email);
        return false;
    }
    
    // Verify the returned email matches expected email
    bool result = (verified_email == email);
    if (result) {
        LOG_INFO("CheckClientToken - Token verified successfully for email: {}", email);
    } else {
        LOG_ERROR("CheckClientToken - Email mismatch: {} != {}", verified_email, email);
    }
    return result;
}

bool AuthorizationDB::SendNotification(const std::string& deviceToken, const std::string& title, const std::string& message) {
    static std::string notificationExecutable = "/usr/local/bin/sendnotification";

    if (!std::filesystem::exists(notificationExecutable)) {
        LOG_INFO("Notification module: {} does not exists", notificationExecutable);
        return false;
    }
    auto googleServiceJsonFile = GetRegistry()->GetKey("app_firebase_admin_credential_json_file");
    if (googleServiceJsonFile.empty()) {
        LOG_ERROR("SendNotification: Firebase credential path not configured" );
        return false;
    }
    if (!std::filesystem::exists(googleServiceJsonFile)) {
        LOG_ERROR("GoogleServiceJSON: {} does not exist!", googleServiceJsonFile);
        return false;
    }

    LOG_INFO("SendNotification called:  {}", deviceToken);
    LOG_INFO("SendNotification message: {} : {}", title, message);
    auto [result, errString] = executeCommand(notificationExecutable, {googleServiceJsonFile}, {deviceToken, title, message});
    if (errString.empty()) {
        LOG_INFO("SendNotification - result: {}", result);
        return true;
    }
    LOG_ERROR("SendNotification - result failed: ", errString);
    return false;
}

bool AuthorizationDB::SendGroupNotification(const std::vector<std::string>& deviceTokens, const std::string& title, const std::string& message) {
    // TODO
    return false;
}

bool AuthorizationDB::NotifyAdminUserCreated(const AuthDatabaseProto::User* user) {
    auto authorizer = GetRegistry()->GetKey("uRoles_Authorizer");
    auto admin = GetRegistry()->GetKey("uRoles_Admin");
    auto sql = fmt::format("select devicetoken from userdevicetokens where userid in (select distinct userid from userroles where roleid in ({},{}))", authorizer, admin);
    LOG_INFO(sql);
    auto rs = GetSession().ExecuteQuery(sql);
    int nAuthorizer = 0;
    while (rs->NextRow()) {
        nAuthorizer++;
        SendNotification(rs->Get(0), "Access Request", fmt::format("User: {} ({}) request to access the system", user->name(), user->email()));
    }
    LOG_INFO("NotifiyAdminUserCreated: No of authorizers notified = {}", nAuthorizer);
    return true;
}
