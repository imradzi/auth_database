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
#include "beast.h"
#include "logger/logger.h"

#include "AuthenticationService.h"
#include "WakeableSleeper.h
"
boost::uuids::random_generator_mt19937 uuidGen;

unsigned int portNumber = AuthDatabaseProto::ServerSetting::GRPCPortNo;
unsigned int webPortNo = AuthDatabaseProto::ServerSetting::WebPortNo;

std::unique_ptr<grpc::Server> doc_service_thread;

void StartService() {
    std::thread _local([] {
        try {
            std::string url = fmt::format("0.0.0.0:{}", portNumber);
            std::string server_address(url);

            LOG_INFO("Initializing service...");
            AuthenticationService service;

            LOG_INFO("Initializing builder...");
            grpc::ServerBuilder builder;
            

            LOG_INFO("Add listener...");
            builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
            

            LOG_INFO("Register service...");
            builder.RegisterService(&service);

            LOG_INFO("creating thread...");
            doc_service_thread = builder.BuildAndStart();
            if (doc_service_thread) {
                LOG_INFO("PPOSAuth Service started on {url}", fmt::arg("url", url);
                doc_service_thread->Wait();
            } else
                LOG_ERROR("PPOSAuth Service fail to start on {url}", fmt::arg("url", url);
        } catch (const std::exception& e) {
            LOG_ERROR("StartService exception: {}", e.what());
        }
    });
    _local.detach();
}

void StopService() {
    LOG_INFO("Stopping PPOSAuth Service... ");
    if (doc_service_thread) {
        LOG_INFO("Waiting for PPOSAuth Service thread");
        doc_service_thread->Shutdown();
    }
    LOG_INFO("PPOSAuth Service - stopped.");
}

ObservableAtomic isShuttingDown {false};

#ifdef _WIN32
BOOL WINAPI ConsoleHandler(DWORD event) {
    bool rc = false;  // return true is telling we are not handling anything; so it should continue;
    switch (event) {
        case CTRL_C_EVENT:
            LOG_INFO("CTRL-C pressed");
            isShuttingDown.store(rc=true);
            break;
        case CTRL_BREAK_EVENT:
            LOG_INFO("CTRL-BREAK pressed");
            isShuttingDown.store(rc=true);
            break;
        case CTRL_CLOSE_EVENT:
            LOG_INFO("Window is closing");
            isShuttingDown.store(rc=true);
            break;
        case CTRL_LOGOFF_EVENT:
            LOG_INFO("User is logging off");
            isShuttingDown.store(rc=true);
            break;
        case CTRL_SHUTDOWN_EVENT:
            LOG_INFO("System is shutting down");
            isShuttingDown.store(rc=true);
            break;
    }
    return rc;
}

#else
void ConsoleHandler(int signal) {
    LOG_INFO("ConsoleHandler() - calling ShuttingDown().");
    switch (signal) {
        case SIGABRT:
            LOG_INFO("SIGABRT received");
            isShuttingDown.store(true);
            break;
        case SIGTERM:
            LOG_INFO("SIGTERM received");
            isShuttingDown.store(true);
            break;
        case SIGINT:
            LOG_INFO("SIGINT received");
            isShuttingDown.store(true);
            break;
        default:
            LOG_INFO("SIGNAL {}", std::to_string(signal);
    }
}
#endif

int main(int argc, char* argv[]) {
    srand(time(NULL));
#ifdef _WIN32
    if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE) == FALSE) {
        LOG_INFO("Cannot set control-c handler");
    }
#else
    signal(SIGABRT, ConsoleHandler);
    signal(SIGTERM, ConsoleHandler);
    signal(SIGINT, ConsoleHandler);
#endif
    try {
        LOG_INFO("SQLite3 version " << sqlite3_version);
        auto authDb = std::make_unique<AuthorizationDB>();
        authDb->Open(true);

        auto user = AuthDatabaseProto::User();
        user.set_email("imradzi@gmail.com");
        user.set_name("Radzi");
        user.set_tel_no("0199581105");
        auto res = authDb->RegisterEmail(&user, "", "");
        LOG_INFO("register email returns {}", res);
        res = authDb->ApproveEmail("imradzi@gmail.com");
        authDb->SetRole("imradzi@gmail.com", authDb->GetRegistry()->GetKey("uRoles_Admin"));
        authDb->SetRole("imradzi@gmail.com", authDb->GetRegistry()->GetKey("uRoles_CreateDB"));
        authDb->SetRole("imradzi@gmail.com", authDb->GetRegistry()->GetKey("uRoles_Authorizer"));
        LOG_INFO("authorize email returns ", res);
    } catch (const std::exception& e) {
        LOG_ERROR("Error starting the db: {}", e.what());
        return 1;
    }

    StartWebServer("0.0.0.0", webPortNo, "www", 3, "chain.pem", "private.pem", "");  // 1 worker thread for web call
    StartService();
    while (!isShuttingDown.load()) {
        std::this_thread::yield();
        std::this_thread::sleep_for(200ms);
    }
    LOG_INFO("Loop broken...");
    StopService();
    StopWebServer();
    return 0;
}
