#include <chrono>
#include <cmath>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <chrono>

#include <fmt/format.h>
#include <signal.h>
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <filesystem>

#include "auth_database.pb.h"
#include "auth_database.grpc.pb.h"
#include <boost/uuid/uuid.hpp>
#include "authDB.h"
#include "beast.h"

#include "AuthChatService.h"
#include "logger/logger.h"
#include "WakeableSleeper.h"

using namespace std::chrono_literals;
namespace fs = std::filesystem;

// kena ada MessageQueue global vector which has folder/dbname to allow message to sent to the same db
// and session -> so that is only for same user -> also check email

ObservableAtomic isShuttingDown {false};

MQ::EventHandler<MQ::Queue<AuthChatProto::ServerEventMessage>, AuthChatProto::ServerEventMessage, AuthDatabaseProto::Session> globalMessage([](const std::string& queueKey) {
    AuthChatProto::ServerEventMessage event;
    event.set_type(AuthChatProto::EventType::ev_chat);
    auto m = event.add_messages();
    m->set_key("chat_killed");
    m->set_value(queueKey);
    LOG_INFO("Sending kill event for {}", queueKey);
    return event;
});

void MonitorChatList() {
    while (!isShuttingDown.load()) {
        globalMessage.removeExpired();
        std::this_thread::yield();
        std::this_thread::sleep_for(300ms);
    }
}

void ShutdownAllChats() {
    LOG_INFO("ShutdownAllChats: closing all active chat queues...");
    globalMessage.closeAll();
    LOG_INFO("ShutdownAllChats: done.");
}

static bool disableChat = false;

::grpc::Status AuthChatService::StartChat(::grpc::ServerContext* context, const ::AuthDatabaseProto::Config* request, ::grpc::ServerWriter<::AuthChatProto::ServerEventMessage>* writer) {
    if (disableChat) return grpc::Status::OK;

    auto [isOk, session, authDb] = AuthenticationService::ReadMetaData("Arham::StartChat", context, false);

    auto queueKey = globalMessage.add(*session);  // need to know which config on which queue so that can send notification based on db/user/
    LOG_INFO("AuthChatService::StartChat: started: {}", queueKey);

    // inform client of the chat key;
    AuthChatProto::ServerEventMessage event;
    event.set_type(AuthChatProto::EventType::ev_chat);
    auto m = event.add_messages();
    m->set_key("chat_key");
    m->set_value(queueKey);
    writer->Write(event);
    auto sess = globalMessage.getSession(queueKey).lock();
    sess->set_chat_key(queueKey);
    while (!isShuttingDown.load()) {
        std::this_thread::yield();
        auto queue = globalMessage.getQ(queueKey).lock();
        if (!queue) break;  // chat deleted.
        if (queue->isClosed()) break;
        if (queue->receive(event) == MQ::ReturnCode::OK) {
            if (event.type() == AuthChatProto::ev_close_chat) break;
            writer->Write(event);
            globalMessage.resetExpiry(queueKey);
        } else { 
            break; // chat already closed.
        }
    }
    globalMessage.remove(queueKey);
    LOG_INFO("AuthChatService::StartChat:{} stopped", queueKey);
    return isOk ? grpc::Status::OK : grpc::Status::CANCELLED;
}

::grpc::Status AuthChatService::StopChat(::grpc::ServerContext* context, const google::protobuf::Empty* request, google::protobuf::Empty* response) {
    auto [isOk, session, authDb] = AuthenticationService::ReadMetaData("Arham::StopChat", context, false);
    LOG_INFO("AuthChatService::StopChat: {} stopping", session->chat_key());
    globalMessage.remove(session->chat_key());
    return grpc::Status::OK;
}

::grpc::Status AuthChatService::KeepAlive(::grpc::ServerContext* context, const ::AuthChatProto::KeepAliveMessage* request, google::protobuf::Empty* response) {
    auto [isOk, session, authDb] = AuthenticationService::ReadMetaData("Arham::KeepAlive", context, false);
    LOG_INFO("AuthChatService: keeping {} alive for next {} minutes", session->chat_key(), request->duration());
    if (request->duration() <= 0)
        globalMessage.setExpiry(session->chat_key(), std::chrono::system_clock::now() + MQ::intervalToExpire);
    else
        globalMessage.setExpiry(session->chat_key(), std::chrono::system_clock::now() + std::chrono::seconds(request->duration()));
    return grpc::Status::OK;
}

void MessageSender::Add(const std::string& description, const std::string& key, const std::string& value) {
    auto m = msg.add_messages();
    m->set_description(description);
    m->set_key(key);
    m->set_value(value);
}

MessageSender::~MessageSender() {
    if (commit) {
        if (isBroadcast) {
            globalMessage.broadcast(msg, [&](const AuthDatabaseProto::Session* dest) {
                return originator.db_name() == dest->db_name() && originator.group_filter() == dest->group_filter() && originator.chat_key() != dest->chat_key();
            });
        } else {
            auto start = std::chrono::system_clock::now();
            while (true) {
                auto msgQ = globalMessage.getQ(originator.chat_key()).lock();
                if (!msgQ) break;
                LOG_INFO("MessageSender::sending final message.");
                if (msgQ->send(msg) == MQ::OK) break;
                if (std::chrono::system_clock::now() - start > 60s) {
                    break;  // give up trying after 60 secs.
                }
            }
        }
    }
}
