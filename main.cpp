#include <chrono>
#include <cmath>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <chrono>

#include <fmt/format.h>
#include <signal.h>
#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid.hpp>
#include <filesystem>

#include "authDB.h"
#include "sqlexception.h"
#include "beast.h"
#include "logger.h"

#include "AuthenticationService.h"

boost::uuids::random_generator_mt19937 uuidGen;

unsigned int portNumber = AuthDatabaseProto::ServerSetting::GRPCPortNo;
unsigned int webPortNo = AuthDatabaseProto::ServerSetting::WebPortNo;

std::unique_ptr<grpc::Server> doc_service_thread;

void StartService() {
    std::thread _local([] {
        try {
            std::string url = fmt::format("0.0.0.0:{}", portNumber);
            std::string server_address(url);

            ShowLog("Initializing service...");
            AuthenticationService service;

            ShowLog("Initializing builder...");
            grpc::ServerBuilder builder;
            

            ShowLog("Add listener...");
            builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
            

            ShowLog("Register service...");
            builder.RegisterService(&service);

            ShowLog("creating thread...");
            doc_service_thread = builder.BuildAndStart();
            if (doc_service_thread) {
                ShowLog(fmt::format("PPOSAuth Service started on {url}", fmt::arg("url", url)));
                doc_service_thread->Wait();
            } else
                ShowLog(fmt::format("PPOSAuth Service fail to start on {url}", fmt::arg("url", url)));
        } catch (std::exception& e) {
            ShowLog(e.what());
        }
    });
    _local.detach();
}

void StopService() {
    ShowLog("Stopping PPOSAuth Service... ");
    if (doc_service_thread) {
        ShowLog("Waiting for PPOSAuth Service thread");
        doc_service_thread->Shutdown();
    }
    ShowLog("PPOSAuth Service - stopped.");
}

extern std::atomic<bool> isShuttingDown {false};

#ifdef _WIN32
BOOL WINAPI ConsoleHandler(DWORD event) {
    bool rc = false;  // return true is telling we are not handling anything; so it should continue;
    switch (event) {
        case CTRL_C_EVENT:
            ShowLog("CTRL-C pressed");
            rc = isShuttingDown = true;
            break;
        case CTRL_BREAK_EVENT:
            ShowLog("CTRL-BREAK pressed");
            rc = isShuttingDown = true;
            break;
        case CTRL_CLOSE_EVENT:
            ShowLog("Window is closing");
            rc = isShuttingDown = true;
            break;
        case CTRL_LOGOFF_EVENT:
            ShowLog("User is logging off");
            rc = isShuttingDown = true;
            break;
        case CTRL_SHUTDOWN_EVENT:
            ShowLog("System is shutting down");
            rc = isShuttingDown = true;
            break;
    }
    return rc;
}

#else
void ConsoleHandler(int signal) {
    ShowLog("ConsoleHandler() - calling ShuttingDown().");
    switch (signal) {
        case SIGABRT:
            ShowLog("SIGABRT received");
            isShuttingDown = true;
            break;
        case SIGTERM:
            ShowLog("SIGTERM received");
            isShuttingDown = true;
            break;
        case SIGINT:
            ShowLog("SIGINT received");
            isShuttingDown = true;
            break;
        default:
            ShowLog("SIGNAL " + std::to_string(signal));
    }
}
#endif

int main(int argc, char* argv[]) {
    srand(time(NULL));
#ifdef _WIN32
    if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE) == FALSE) {
        ShowLog("Cannot set control-c handler");
    }
#else
    signal(SIGABRT, ConsoleHandler);
    signal(SIGTERM, ConsoleHandler);
    signal(SIGINT, ConsoleHandler);
#endif
    try {
        ShowLog("SQLite3 version " << sqlite3_version);
        auto authDb = std::make_unique<AuthorizationDB>();
        authDb->Open(true);
        authDb->CheckSchemaAndRestructure();

        auto user = AuthDatabaseProto::User();
        user.set_email("imradzi@gmail.com");
        user.set_name("Radzi");
        user.set_tel_no("0199581105");
        auto res = authDb->RegisterEmail(&user, "", "");
        ShowLog(fmt::format("register email returns {}", res);
        res = authDb->ApproveEmail("imradzi@gmail.com");
        authDb->SetRole("imradzi@gmail.com", authDb->GetRegistry()->GetKey("uRoles_Admin"));
        authDb->SetRole("imradzi@gmail.com", authDb->GetRegistry()->GetKey("uRoles_CreateDB"));
        authDb->SetRole("imradzi@gmail.com", authDb->GetRegistry()->GetKey("uRoles_Authorizer"));
        ShowLog(fmt::format("authorize email returns ", res);
    } catch (wpSQLException& e) {
        ShowLog(fmt::format("Error starting the db: ", e.message);
        return 1;
    } catch (std::exception& e) {
        ShowLog(fmt::format("Error starting the db: ", e.what());
        return 1;
    }

    StartWebServer("0.0.0.0", webPortNo, "www", 3, "chain.pem", "private.pem", "");  // 1 worker thread for web call
    StartService();
    while (!isShuttingDown) {
        std::this_thread::yield();
        std::this_thread::sleep_for(200ms);
    }
    ShowLog("Loop broken...");
    StopService();
    StopWebServer();
    return 0;
}
