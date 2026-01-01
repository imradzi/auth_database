#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/tokenizer.hpp>

#include <iomanip>
#include "gRPC_Client.h"
#include "net.h"
#include "logger/logger.h"
#include <fmt/format.h>
#include <memory>

#include <fstream>

constexpr auto URL = "{host}:{port}";

PPOSClient::PPOSClient(bool keepAlive, const std::string &host, int pno) : keepConnectionAlive(keepAlive) {
    if (!host.empty()) hostname = host;
    if (pno > 0) portNo = pno;
    try {
        std::string hostIP {GetHostIP(hostname)};
        std::string url = fmt::format(URL, fmt::arg("host", hostIP), fmt::arg("port", portNo));
        grpcChannel = grpc::CreateChannel(url, grpc::InsecureChannelCredentials());
        authStub = PPOS::Auth::NewStub(grpcChannel);
        chatStub = PPOS::Chat::NewStub(grpcChannel);
        configStub = PPOS::Config::NewStub(grpcChannel);
        sqlStub = PPOS::SQL::NewStub(grpcChannel);
        salesStub = PPOS::Sales::NewStub(grpcChannel);
        purchasesStub = PPOS::Purchases::NewStub(grpcChannel);
        stockStub = PPOS::Stock::NewStub(grpcChannel);
        membershipStub = PPOS::Membership::NewStub(grpcChannel);
        companyStub = PPOS::Company::NewStub(grpcChannel);
        reportStub = PPOS::Report::NewStub(grpcChannel);
    } catch (std::exception &e) {
        LOG_ERROR(fmt::format("AuthClient constructor: grpc exception: {}", e.what()));
    } catch (...) {
        LOG_ERROR("AuthClient constructor: unknown exception..");
    }
}
