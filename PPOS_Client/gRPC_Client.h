#pragma once
#include <string>
#include <memory>
#include <grpcpp/grpcpp.h>
#include "ppos.grpc.pb.h"
#include <fstream>

class PPOSClient {
    std::unique_ptr<PPOS::Auth::Stub> authStub;
    std::unique_ptr<PPOS::Chat::Stub> chatStub;
    std::unique_ptr<PPOS::Config::Stub> configStub;
    std::unique_ptr<PPOS::SQL::Stub> sqlStub;
    std::unique_ptr<PPOS::Sales::Stub> salesStub;
    std::unique_ptr<PPOS::Purchases::Stub> purchasesStub;
    std::unique_ptr<PPOS::Stock::Stub> stockStub;
    std::unique_ptr<PPOS::Membership::Stub> membershipStub;
    std::unique_ptr<PPOS::Company::Stub> companyStub;
    std::unique_ptr<PPOS::Report::Stub> reportStub;

    std::string hostname {"demo.pharmapos.com"};
    int portNo {33001};
    std::shared_ptr<grpc::Channel> grpcChannel;
    bool keepConnectionAlive {false};

public:
    PPOSClient(bool keepAlive, const std::string &host = "", int pNo = 0);
};
