#include "pushover.hh"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "fmt/format.h"

PushoverReporter::PushoverReporter(const std::string& user, const std::string& apikey) : d_user(user), d_apikey(apikey)
{
  
}

void PushoverReporter::alert(const std::string& msg)
{
  httplib::Client cli("https://api.pushover.net");
  // https://api.pushover.net/1/messages.json
  httplib::Params items = {
    { "user", d_user},
    { "token", d_apikey},
    { "message", msg}
  };

  auto res = cli.Post("/1/messages.json", items);
  if(!res)
    throw std::runtime_error("Could not send post");
  if(res->status != 200)
    throw std::runtime_error(fmt::format("Post to pushover failed, res = {}", res->status));

  fmt::print("{}\n", res->body);
                             
}
