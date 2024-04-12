#include "notifiers.hh"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "fmt/format.h"
#include "simplomon.hh"
using namespace std;

PushoverNotifier::PushoverNotifier(sol::table data) : Notifier(data)
{
  checkLuaTable(data, {"user", "apikey"});
  d_user = data.get<string>("user");
  d_apikey = data.get<string>("apikey");
  d_notifierName="PushOver";
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

  //  fmt::print("{}\n", res->body);
}


NtfyNotifier::NtfyNotifier(sol::table data) : Notifier(data)
{
  checkLuaTable(data, {"topic"}, {"auth", "url"});
  d_auth = data.get_or("auth", string(""));
  d_url = data.get_or("url", string("https://ntfy.sh"));
  d_topic = data.get<string>("topic");
  d_notifierName="Ntfy";
}

void NtfyNotifier::alert(const std::string& msg)
{
  httplib::Client cli(d_url);
  httplib::Headers headers = {};

  if (!d_auth.empty())
    headers = {{"Authorization", d_auth}};

  auto res = cli.Post("/"+d_topic, headers, msg, "text/plain");

  if(!res) {
    auto err = res.error();
    
    throw std::runtime_error(fmt::format("Could not send post to ntfy: {}", httplib::to_string(err)));
  }
  if(res->status != 200)
    throw std::runtime_error(fmt::format("Post to ntfy failed, res = {}", res->status));

  //  fmt::print("{}\n", res->body);
                             
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

EmailNotifier::EmailNotifier(sol::table data) : Notifier(data)
{
  checkLuaTable(data, {"from", "to", "server"});
  d_from = data.get<string>("from");
  d_to = data.get<string>("to");
  d_server = ComboAddress(data.get<string>("server"), 25);
  d_notifierName="Email";
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

void Notifier::bulkAlert(const std::string& textBody)
{
  if(d_verbose)
    fmt::print("Got: {}\n", textBody);
  d_reported.insert(textBody);
}

void SQLiteWriterNotifier::alert(const std::string& str)
{
  if(g_sqlw)
    g_sqlw->addValue({{"tstamp", (int64_t)time(nullptr)}, {"message", str}}, "notifications");
}

void Notifier::bulkDone()
{
  decltype(d_reported) diff;
  set_difference(d_reported.begin(), d_reported.end(),
                 d_prevReported.begin(), d_prevReported.end(),
                 inserter(diff, diff.begin()));
    
  //  fmt::print("got {} NEW results, ", diff.size());
  for(const auto& d : diff) {
    d_times[d] = time(nullptr);
  }
    
  diff.clear();
  set_difference(d_prevReported.begin(), d_prevReported.end(),
                 d_reported.begin(), d_reported.end(),
                 inserter(diff, diff.begin()));
  //  fmt::print("{} alerts were resolved\n", diff.size());

  map<string, time_t> deltime;
  for(const auto& d : diff) {
    deltime[d] = d_times[d];
    d_times.erase(d);
  }

  d_prevReported = d_reported;
  d_reported.clear();
  // in d_times, we now have a list of active alerts, and since how long

  time_t lim = time(nullptr) - d_minMinutes * 60;

  d_oldEnough.clear();
  for(const auto& r : d_prevReported)
    if(d_times[r] <= lim)
      d_oldEnough.insert(r);
  //  fmt::print("There are {} reports that are old enough (prev {})\n", d_oldEnough.size(),
  //             d_prevOldEnough.size());
  
  diff.clear();
  set_difference(d_oldEnough.begin(), d_oldEnough.end(),
                 d_prevOldEnough.begin(), d_prevOldEnough.end(),
                 inserter(diff, diff.begin()));
    
  //  fmt::print("got {} NEW results that are old enough\n", diff.size());
  for(const auto& str : diff) {
    string desc = getAgeDesc(d_times[str]);
    //    fmt::print("Reporting {}\n", str);
    if(d_minMinutes)
      this->alert("("+desc+" already) " +str);
    else
      this->alert(str);
  }

  diff.clear();
  set_difference(d_prevOldEnough.begin(), d_prevOldEnough.end(),
                 d_oldEnough.begin(), d_oldEnough.end(),
                 inserter(diff, diff.begin()));
  //  fmt::print("There are {} results that used to be old enough & are gone now\n",
  //         diff.size());
  for(const auto& str : diff) {
    string desc = getAgeDesc(deltime[str]);
    this->alert(fmt::format("🎉 after {}, the following alert is over: {}",
                            desc,
                            str));
  }

  d_prevOldEnough = d_oldEnough;
}


TelegramNotifier::TelegramNotifier(sol::table data) : Notifier(data) 
{ 
  checkLuaTable(data, {"bot_id", "apikey", "chat_id"});
  d_botid = data.get<string>("bot_id");
  d_apikey = data.get<string>("apikey");
  d_chatid = data.get<string>("chat_id");
}

void TelegramNotifier::alert(const std::string& message)
{
  httplib::Client cli("https://api.telegram.org");

  httplib::Params items = {
    { "chat_id", d_chatid},
    { "text", message}
  };

  std::string path;
  path = "/bot" + d_botid + ":" + d_apikey + "/sendMessage";

  auto res = cli.Post(path, items);
  if(!res) {
    auto err = res.error();
    
    throw std::runtime_error(fmt::format("\nCould not send post: {}", httplib::to_string(err)));
  }
  if(res->status != 200)
    throw std::runtime_error(fmt::format("\nPost to Telegram failed, res = {}\n{}", res->status, res->body));

  // fmt::print("{}\n", res->body);
}

