#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <iostream>
#include <fmt/format.h>

// process_web_command will return filename to be send over to client.
// returns 0 = filename
//          1 = string

std::tuple<int, std::string, std::shared_ptr<std::vector<char>>> process_web_command(boost::beast::http::verb method, boost::beast::string_view command, boost::beast::string_view body, std::function<boost::beast::string_view(boost::beast::string_view key)> fnHeader) {
    auto contentType = fnHeader("Content-Type");
    auto verbString = boost::beast::http::to_string(method);

    std::string verbString = to_string(method);
    return {1, fmt::format("<h1>AuthDatabase: processed command ({}) {} content={} <br/> {} </h1>", verbString, std::string(cmd), std::string(contentType), std::string(body))};
}
