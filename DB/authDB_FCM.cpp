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
        return {"", e.what()};
    } catch (...) {
        return {"", "Unknown error"};
    }
    return {output, error_output};
}

bool AuthorizationDB::CheckClientToken(const std::string& idToken, const std::string& email) {
    ShowLog(fmt::format("email: {}", email));
    ShowLog(fmt::format("token: {}", idToken));
    auto [result, err] = executeCommand("/usr/local/bin/checktoken", {GetRegistry()->GetKey("app_firebase_admin_credential_json_file")}, {idToken});
    ShowLog(fmt::format("CheckClientToken - result: {}, email: {}, error: [{}]", result, email, err));
    return boost::iequals(boost::trim_copy(result), boost::trim_copy(email));
}
    // -------to rewrite using boost::asio::process
    // try {
    //     auto googleServiceJsonFile = GetRegistry()->GetKey("app_firebase_admin_credential_json_file");
    //     ShowLog(fmt::format("Google cred file at {}", googleServiceJsonFile));
    //     namespace bp = boost::process;

    //     boost::asio::io_context ios;

    //     bp::opstream in;
    //     in << idToken << std::endl;
    //     std::future<std::string> data;
    //     std::future<std::string> errData;

    //     bp::child childProcess("/usr/local/bin/checktoken", googleServiceJsonFile, bp::std_in<in, bp::std_out> data, bp::std_err > errData, ios);
    //     ios.run();

    //     auto err = errData.get();
    //     auto result = boost::trim_copy(data.get());
    //     ShowLog(fmt::format("CheckClientToken - result: {}, email: {}", result, email));
    //     return boost::iequals(result, boost::trim_copy(email));
    // } catch (...) {
    //     return false;
    // }

bool AuthorizationDB::SendNotification(const std::string& deviceToken, const std::string& title, const std::string& message) {
    static std::string notificationExecutable = "/usr/local/bin/sendnotification";

    if (!std::filesystem::exists(notificationExecutable)) {
        ShowLog(fmt::format("Notification module: {} does not exists", notificationExecutable));
        return false;
    }
    auto googleServiceJsonFile = GetRegistry()->GetKey("app_firebase_admin_credential_json_file");

    if (!std::filesystem::exists(googleServiceJsonFile)) {
        ShowLog(fmt::format("GoogleServiceJSON: {} does not exist!", googleServiceJsonFile));
        return false;
    }

    ShowLog(fmt::format("SendNotification called:  {}", deviceToken));
    ShowLog(fmt::format("SendNotification message: {} : {}", title, message));
    auto [result, errString] = executeCommand(notificationExecutable, {googleServiceJsonFile}, {deviceToken, title, message});
    if (errString.empty()) {
        ShowLog(fmt::format("SendNotification - result: {}", result));
        return true;
    }
    ShowLog(fmt::format("SendNotification - result failed: ", errString));
    return false;
}
// -------to rewrite using boost::asio::process
// try {
//     auto googleServiceJsonFile = GetRegistry()->GetKey("app_firebase_admin_credential_json_file");

//     if (!std::filesystem::exists(googleServiceJsonFile)) {
//         ShowLog(fmt::format("GoogleServiceJSON: {} does not exist!", googleServiceJsonFile));
//         return false;
//     }
//     namespace bp = boost::process;
//     boost::asio::io_context ios;

//     bp::opstream in;
//     in << deviceToken << std::endl;
//     in << title << std::endl;
//     in << message << std::endl;
//     std::future<std::string> data;
//     std::future<std::string> errData;

//     bp::child childProcess(notificationExecutable, googleServiceJsonFile, bp::std_in<in, bp::std_out> data, bp::std_err > errData, ios);
//     ios.run();

//     auto result = data.get();
//     ShowLog(fmt::format("SendNotification - result: ", result));
//     return true;
// } catch (...) {
//     ShowLog("SendNotification - unknown exception");
//     return false;
// }

bool AuthorizationDB::SendGroupNotification(const std::vector<std::string>& deviceTokens, const std::string& title, const std::string& message) {
    // TODO
    return false;
}

bool AuthorizationDB::NotifyAdminUserCreated(const AuthDatabaseProto::User* user) {
    auto authorizer = GetRegistry()->GetKey("uRoles_Authorizer");
    auto admin = GetRegistry()->GetKey("uRoles_Admin");
    auto sql = fmt::format("select devicetoken from userdevicetokens where userid in (select distinct userid from userroles where roleid in ({},{}))", authorizer, admin);
    ShowLog(sql);
    auto rs = GetSession().ExecuteQuery(sql);
    int nAuthorizer = 0;
    while (rs->NextRow()) {
        nAuthorizer++;
        SendNotification(rs->Get(0), "Access Request", fmt::format("User: {} ({}) request to access the system", user->name(), user->email()));
    }
    ShowLog(fmt::format("NotifiyAdminUserCreated: No of authorizers notified = {}", nAuthorizer));
    return true;
}
