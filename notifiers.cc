#include "notifiers.hh"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "fmt/format.h"

#include "simplomon.hh"

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

EmailNotifier::EmailNotifier(sol::table data) : Notifier(data), d_url(curl_url(), curl_url_cleanup)
{
  checkLuaTable(data, {"from", "to", "server"});
  d_from = data.get<string>("from");
  d_to = data.get<string>("to");

  const char* allowed="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-.@";
  if(d_from.find_first_not_of(allowed) != string::npos || d_to.find_first_not_of(allowed) != string::npos)
    throw std::runtime_error("Illegal character in from or to address");

  // 'server' can be "192.0.2.3" or "example.org" or "smtp://192.0.2.3" or "smtps://user:pass@example.org:465" or ...
  std::string server = data.get<string>("server");

  char* scheme;
  if(curl_url_set(d_url.get(), CURLUPART_URL, server.c_str(), CURLU_DEFAULT_SCHEME))
    throw std::runtime_error("EmailNotifier could not parse server field");
  if(curl_url_get(d_url.get(), CURLUPART_SCHEME, &scheme, 0))
    throw std::runtime_error("curl_url_get failed");
  if(strcmp(scheme, "smtps") != 0)
    curl_url_set(d_url.get(), CURLUPART_SCHEME, "smtp", 0);
  curl_free(scheme);

  d_notifierName="Email";
}

void EmailNotifier::alert(const std::string& textBody)
{
  std::string message;
  auto msg = std::back_inserter(message);

  fmt::format_to(msg, "From: {}\r\n", d_from);
  fmt::format_to(msg, "To: {}\r\n", d_to);
  fmt::format_to(msg, "Subject: {}\r\n", "Simplomon notification");
  fmt::format_to(msg, "Message-Id: <{}@simplomon.hostname>\r\n", getRandom64());
  fmt::format_to(msg, "Date: {:%a, %d %b %Y %H:%M:%S %z (%Z)}\r\n", fmt::localtime(time(nullptr)));
  fmt::format_to(msg, "\r\n");
  fmt::format_to(msg, "{}\r\n", textBody);

  MiniCurl mc;
  char errorBuffer[CURL_ERROR_SIZE] = {};
  FILE *messageFile = fmemopen(message.data(), message.size(), "r");
  curl_slist* rcpt = curl_slist_append(nullptr, d_to.c_str());

  bool failure = (messageFile == nullptr) || (rcpt == nullptr) ||
    curl_easy_setopt(mc.d_curl, CURLOPT_ERRORBUFFER, errorBuffer) ||
    curl_easy_setopt(mc.d_curl, CURLOPT_CURLU, d_url.get()) ||
    curl_easy_setopt(mc.d_curl, CURLOPT_MAIL_FROM, d_from.c_str()) ||
    curl_easy_setopt(mc.d_curl, CURLOPT_MAIL_RCPT, rcpt) ||
    curl_easy_setopt(mc.d_curl, CURLOPT_UPLOAD, 1L) ||
    curl_easy_setopt(mc.d_curl, CURLOPT_READDATA, messageFile) ||
    curl_easy_perform(mc.d_curl);

  if(rcpt != nullptr)
    curl_slist_free_all(rcpt);
  if(messageFile != nullptr)
    fclose(messageFile);

  if(failure)
    throw std::runtime_error(fmt::format("Could not send email notification ({})", errorBuffer));
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
    g_sqlw->addValue({{"tstamp", time(nullptr)}, {"message", str}}, "notifications");
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

