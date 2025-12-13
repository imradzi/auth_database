// #include "net.h"
// #include "rDb.h"
// #include <vector>
// #include <filesystem>

// #include <boost/uuid/string_generator.hpp>
// #include <boost/uuid/random_generator.hpp>
// #include <boost/uuid/uuid.hpp>
// #include <boost/uuid/uuid_io.hpp>

#include <boost/algorithm/string.hpp>

#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <boost/beast/core/string.hpp>
#include "auth_database.pb.h"
#include "auth_database.grpc.pb.h"
#include "protofunctions.h"
#include "GetSession.h"
#include "logger.h"

static int GetInt(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

static std::tuple<const unsigned char*, int> GetBufferFromString(std::string_view s) {
    unsigned char* buffer = new unsigned char[s.size()];
    size_t i = 0;
    int len = 0;
    unsigned char* o = buffer;
    for (const char* p = s.data(); i < s.length(); i += 2, p += 2) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            v = v * 16 + GetInt(*(p + k));
        }
        *o = v;
        ++o;
        ++len;
    }
    return {buffer, len};
}

static void DumpBuffer(const unsigned char* buf, int len) {
    std::stringstream ss;
    ss << "buf: ";
    for (int i = 0; i < len; i++, buf++) {
        ss << std::ios::hex << int(*buf) << ",";
    }
    ss << "\n";
    ShowLog(ss.str());
}

constexpr bool toDump = false;

std::unique_ptr<AuthDatabaseProto::Session> GetSession(::grpc::ServerContext* context) {
    const auto& meta = context->client_metadata();
    auto session = std::make_unique<AuthDatabaseProto::Session>();
    for (auto& x : meta) {
        if (boost::iequals(x.first, "at-auth-session")) {
            return GetSession(std::string_view(x.second.begin(), x.second.end()));
        }
    }
    return session;
}

boost::beast::string_view GetSessionString(::grpc::ServerContext* context) {
    auto meta = context->client_metadata();
    for (auto x : meta) {
        if (boost::iequals(x.first, "at-auth-session")) {
            return boost::beast::string_view(x.second.begin(), x.second.end());
        }
    }
    return "";
}

std::unique_ptr<AuthDatabaseProto::Session> GetSession(std::string_view str) {
    auto session = std::make_unique<AuthDatabaseProto::Session>();
    auto [buf, len] = GetBufferFromString(str);
    if (toDump) DumpBuffer(buf, len);
    session->ParseFromArray(buf, len);
    delete[] buf;
    return session;
}
