#pragma once

#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <fmt/format.h>
#include <boost/beast/core/string.hpp>

inline std::string toHexString(const std::string& s) {
    std::string res;
    for (auto const& x : s) {
        res.append(fmt::format("{:02X}", x));
    }
    return res;
}

template<typename T> auto SerializeHexString(const T& rec) {
    return toHexString(rec.SerializeAsString());
}

extern std::unique_ptr<AuthDatabaseProto::Session> GetSession(::grpc::ServerContext* context);
extern std::unique_ptr<AuthDatabaseProto::Session> GetSession(std::string_view str);
boost::beast::string_view GetSessionString(::grpc::ServerContext* context);
/*
    // -- the pair in Dart to create this string:
  static String getHexString(List<int> list) {
    return [
      for (var byte in list) byte.toRadixString(16).padLeft(2, '0').toUpperCase()
    ].join();
  }

  CallOptions getCallOption({required Session session}) {
    var s = session;
    if (s.appName.isEmpty) s.appName = appName;
    return CallOptions(metadata: {
      "at-auth-session": getHexString(s.writeToBuffer())
    });
  }

*/
