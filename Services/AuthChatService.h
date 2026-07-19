#pragma once
#include "messageQueue.h"
using namespace std::chrono_literals;
#include "AuthenticationService.h"
#include "messageQueue.h"

#include "auth_chat.pb.h"
#include "auth_chat.grpc.pb.h"

class AuthChatService final : public ::AuthChatProto::Chat::Service {
public:
    explicit AuthChatService() {}

    ::grpc::Status StartChat(::grpc::ServerContext* context, const ::AuthDatabaseProto::Config* request, ::grpc::ServerWriter<::AuthChatProto::ServerEventMessage>* writer) override;
    ::grpc::Status StopChat(::grpc::ServerContext* context, const google::protobuf::Empty* request, google::protobuf::Empty* response) override;
    ::grpc::Status KeepAlive(::grpc::ServerContext* context, const ::AuthChatProto::KeepAliveMessage* request, google::protobuf::Empty* response) override;
};

extern MQ::EventHandler<MQ::Queue<AuthChatProto::ServerEventMessage>, AuthChatProto::ServerEventMessage, AuthDatabaseProto::Session> globalMessage;

/*
        auto sender = MessageSender::Create(AuthChatProto::EventType::ev_paymentreceived);
        sender->Add(message.at("status"), "status", message.at("status"));
        sender->Add("", "reason", message.at("reason"));
        sender->Add("", "billId", billId);
        sender->Add("", "amount", message.at("amount"));
        sender->Add("", "billcode", message.at("billcode"));
        sender->Commit();
*/

class MessageSender {
    AuthChatProto::ServerEventMessage msg;
    bool commit = false;
    AuthDatabaseProto::Session originator;
    bool isBroadcast = false;

public:
    MessageSender(AuthChatProto::EventType type, const AuthDatabaseProto::Session &session, bool isBroadcast): originator(session), isBroadcast(isBroadcast) {
        msg.set_type(type);
    }
    static auto Create(AuthChatProto::EventType type, const AuthDatabaseProto::Session &session, bool isBroadcast) {
        return std::make_shared<MessageSender>(type, session, isBroadcast);
    }

    void Commit() { commit = true; }
    void Add(const std::string& description, const std::string& key, const std::string& value);
    ~MessageSender();
};

extern MQ::EventHandler<MQ::Queue<AuthChatProto::ServerEventMessage>, AuthChatProto::ServerEventMessage, AuthDatabaseProto::Session> globalMessage;
void ShutdownAllChats();
