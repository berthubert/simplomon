#include "notifiers.hh"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "fmt/format.h"

#include "simplomon.hh"

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


NtfyNotifier::NtfyNotifier(sol::table data)
{
  checkLuaTable(data, {"topic"}, {"auth"});
  d_auth = data.get_or("auth", string(""));
  d_url = data.get_or("url", string("https://ntfy.sh"));
  d_topic = data.get<string>("topic");
}

void NtfyNotifier::alert(const std::string& msg)
{
  httplib::Client cli(d_url);
  httplib::Headers headers = {};

  if (!d_auth.empty())
    httplib::Headers headers = {{"Authorization", d_auth}};

  auto res = cli.Post("/"+d_topic, headers, msg, "text/plain");

  if(!res) {
    auto err = res.error();
    
    throw std::runtime_error(fmt::format("Could not send post to ntfy: {}", httplib::to_string(err)));
  }
  if(res->status != 200)
    throw std::runtime_error(fmt::format("Post to ntfy failed, res = {}", res->status));

  fmt::print("{}\n", res->body);
                             
}

static uint64_t getRandom64()
{
  static std::random_device rd; // 32 bits at a time. At least on recent Linux and gcc this does not block
  return ((uint64_t)rd() << 32) | rd();
}


static void sendAsciiEmailAsync(const std::string& server, const std::string& from, const std::string& to, const std::string& subject, const std::string& textBody)
{
  const char* allowed="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-.@";
  if(from.find_first_not_of(allowed) != string::npos || to.find_first_not_of(allowed) != string::npos) {
    throw std::runtime_error("Illegal character in from or to address");
  }

  ComboAddress mailserver(server, 25);
  Socket s(mailserver.sin4.sin_family, SOCK_STREAM);

  SocketCommunicator sc(s);
  sc.connect(mailserver);
  string line;
  auto sponge= [&](int expected) {
    while(sc.getLine(line)) {
      if(line.size() < 4)
        throw std::runtime_error("Invalid response from SMTP server: '"+line+"'");
      if(stoi(line.substr(0,3)) != expected)
        throw std::runtime_error("Unexpected response from SMTP server: '"+line+"'");
      if(line.at(3) == ' ')
        break;
    }
  };

  sponge(220);
  sc.writen("EHLO dan\r\n");
  sponge(250);

  sc.writen("MAIL From:<"+from+">\r\n");
  sponge(250);

  sc.writen("RCPT To:<"+to+">\r\n");
  sponge(250);

  sc.writen("DATA\r\n");
  sponge(354);
  sc.writen("From: "+from+"\r\n");
  sc.writen("To: "+to+"\r\n");
  sc.writen("Subject: "+subject+"\r\n");

  sc.writen(fmt::format("Message-Id: <{}@simplomon.hostname>\r\n", getRandom64()));
  
  //Date: Thu, 28 Dec 2023 14:31:37 +0100 (CET)
  sc.writen(fmt::format("Date: {:%a, %d %b %Y %H:%M:%S %z (%Z)}\r\n", fmt::localtime(time(0))));
  sc.writen("\r\n");

  string withCrlf;
  for(auto iter = textBody.cbegin(); iter != textBody.cend(); ++iter) {
    if(*iter=='\n' && (iter == textBody.cbegin() || *std::prev(iter)!='\r'))
      withCrlf.append(1, '\r');
    if(*iter=='.' && (iter != textBody.cbegin() && *std::prev(iter)=='\n'))
      withCrlf.append(1, '.');
        
    withCrlf.append(1, *iter);
  }
  
  sc.writen(withCrlf);
  sc.writen("\r\n.\r\n");
  sponge(250);
}

EmailNotifier::EmailNotifier(sol::table data)
{
  checkLuaTable(data, {"from", "to", "server"});
  d_from = data.get<string>("from");
  d_to = data.get<string>("to");
  d_server = ComboAddress(data.get<string>("server"), 25);
}

void EmailNotifier::alert(const std::string& textBody)
{
  // sendAsciiEmailAsync(const std::string& server, const std::string& from, const std::string& to, const std::string& subject, const std::string& textBody)
  sendAsciiEmailAsync(d_server.toStringWithPort(),
                      d_from,
                      d_to,
                      "Simplomon notification",
                      textBody);
}
