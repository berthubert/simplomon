#include "notifiers.hh"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "fmt/format.h"

PushoverNotifier::PushoverNotifier(const std::string& user, const std::string& apikey) : d_user(user), d_apikey(apikey)
{
  
}

void PushoverNotifier::alert(const std::string& msg)
{
  httplib::Client cli("https://api.pushover.net");
  // https://api.pushover.net/1/messages.json
  httplib::Params items = {
    { "user", d_user},
    { "token", d_apikey},
    { "message", msg}
  };

  auto res = cli.Post("/1/messages.json", items);
  if(!res) {
    auto err = res.error();
    
    throw std::runtime_error(fmt::format("Could not send post: {}", httplib::to_string(err)));
  }
  if(res->status != 200)
    throw std::runtime_error(fmt::format("Post to pushover failed, res = {}", res->status));

  fmt::print("{}\n", res->body);
                             
}

void NtfyNotifier::alert(const std::string& msg)
{
  httplib::Client cli("https://ntfy.sh");

  auto res = cli.Post("/"+d_topic, msg, "text/plain");
  if(!res) {
    auto err = res.error();
    
    throw std::runtime_error(fmt::format("Could not send post to ntfy: {}", httplib::to_string(err)));
  }
  if(res->status != 200)
    throw std::runtime_error(fmt::format("Post to ntfy failed, res = {}", res->status));

  fmt::print("{}\n", res->body);
                             
}
