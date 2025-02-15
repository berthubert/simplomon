#include <fmt/ranges.h>
#include "simplomon.hh"
#include "sol/sol.hpp"
#include <fmt/chrono.h>

#ifdef __FreeBSD__

#include <limits.h>

#ifndef HOST_NAME_MAX
#ifdef _POSIX_HOST_NAME_MAX
#define	HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#else
#define	HOST_NAME_MAX 255
#endif
#endif

#endif

using namespace std;

sol::state g_lua;
int g_intervalSeconds=60;
int g_maxWorkers = 16;

/* every checker has a table of properties, and you get an error if you put unexpected things in there.
   DailyChime{utcHour=11}
   DNSChecker{server="100.25.31.6", domain="berthub.eu", type="A", acceptable={"86.82.68.237", "217.100.190.174"}}
   DNSChecker{server="10.0.0.1", domain="hubertnet.nl", type="MX", acceptable={"5 server.hubertnet.nl.", "10 ziggo.berthub.eu."}, minAlerts=3, alertWindow=180}
 */

/*
  function that checks if mandatory fields are present, allows optional fields
  and panics over other fields */

void checkLuaTable(sol::table data,
                       const set<string>& mandatory,
                       const set<string>& opt)
{
  set<string> mand = mandatory;
  data.for_each([&](sol::object key, sol::object value) {
    string k = key.as<string>();
    auto iter = mand.find(k);
    if(iter != mand.end()) {
      mand.erase(iter);
      return;
    }
    
    if(!mandatory.count(k) && !opt.count(k)) {
      if(k=="1")
        throw std::runtime_error("This function requires a table {} as input, for example: f{param=1}");

      throw std::runtime_error(fmt::format("Unknown parameter '{}' passed", k));
    }
  });
    
  if(!mand.empty())
    throw std::runtime_error(fmt::format("Missing mandatory fields '{}'", mand));
}


class DailyChimeChecker : public Checker
{
public:
  DailyChimeChecker(sol::table data) : Checker(data)
  {
    checkLuaTable(data, {"utcHour"}, {"instance"});
    d_utcHour = data["utcHour"];
    d_instance = data.get_or("instance", getHostName());
  }

  CheckResult perform()
  {
    time_t now = time(nullptr);
    now -= d_utcHour * 3600;
    struct tm tm;
    gmtime_r(&now, &tm);
    return fmt::format("Your daily chime from {} for {:%Y-%m-%d}. This is not an alert.", d_instance, tm);
  }

  std::string getCheckerName() override { return "chime";  }
  
  std::string getDescription() override
  {
    return fmt::format("Daily chime at {}:00 UTC", d_utcHour);
  }

  static std::string getHostName()
  {
    char tmp[HOST_NAME_MAX]={};
    gethostname(tmp, sizeof(tmp) -1);
    return tmp;
  }
  
private:
  int d_utcHour;
  string d_instance;
};


void initLua()
{
  g_lua.open_libraries(sol::lib::base, sol::lib::package);

  g_lua.set_function("dailyChime", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<DailyChimeChecker>(data));
  });

  g_lua.set_function("https", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<HTTPSChecker>(data));
  });
  g_lua.set_function("dnssoa", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<DNSSOAChecker>(data));
  });
  g_lua.set_function("tcpportclosed", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<TCPPortClosedChecker>(data));
  });
  g_lua.set_function("dns", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<DNSChecker>(data));
  });

  g_lua.set_function("httpredir", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<HTTPRedirChecker>(data));
  });

  g_lua.set_function("rrsig", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<RRSIGChecker>(data));
  });
  g_lua.set_function("ping", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<PINGChecker>(data));
  });
  
  g_lua.set_function("prometheusExp", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<PrometheusChecker>(data));
  });
  

  g_lua.set_function("smtp", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<SMTPChecker>(data));
  });

  g_lua.set_function("imap", [&](sol::table data) {
    g_checkers.emplace_back(make_unique<IMAPChecker>(data));
  });

  g_lua.set_function("addPushoverNotifier", [&](sol::table data) {
    g_notifiers.emplace_back(make_shared<PushoverNotifier>(data));
    return *g_notifiers.rbegin();
  });
  g_lua.set_function("createPushoverNotifier", [&](sol::table data) {
    return make_shared<PushoverNotifier>(data);
  });

  g_lua.set_function("addNtfyNotifier", [&](sol::table data) {
    g_notifiers.emplace_back(make_shared<NtfyNotifier>(data));
    return *g_notifiers.rbegin();
  });
  g_lua.set_function("createNtfyNotifier", [&](sol::table data) {
    return make_shared<NtfyNotifier>(data);
  });

  g_lua.set_function("addEmailNotifier", [&](sol::table data) {
    g_notifiers.emplace_back(make_shared<EmailNotifier>(data));
    return *g_notifiers.rbegin();
  });
  g_lua.set_function("createEmailNotifier", [&](sol::table data) {
    return make_shared<EmailNotifier>(data);
  });

  g_lua.set_function("setNotifiers", [&](vector<shared_ptr<Notifier>> notifs) {
    g_notifiers.resize(2); // need to keep the system notifiers
    
    //    fmt::print("Setting {} notifiers\n", notifs.size());
    for(auto& n : notifs)
      g_notifiers.push_back(n);
    
  });

  g_lua.set_function("intervalSeconds", [&](int seconds) {
    g_intervalSeconds = seconds;
  });

  g_lua.set_function("maxWorkers", [&](int workers) {
    if(workers <= 0)
      throw std::runtime_error("maxWorkers must be a positive number");
    g_maxWorkers = workers;
  });

  
  g_lua.set_function("Logger", [&](sol::table data) {
    checkLuaTable(data, {"filename"});
    
    g_sqlw = std::make_unique<SQLiteWriter>((string)data["filename"]);
  });

  g_lua.set_function("doIPv6", [&](bool ipv6) {
    g_haveIPv6 = ipv6;
  });
  
  g_lua.set_function("Webserver", startWebService);
  
  // Telegram notifier
  g_lua.set_function("addTelegramNotifier", [&](sol::table data) {
    g_notifiers.emplace_back(make_shared<TelegramNotifier>(data));
    return *g_notifiers.rbegin();
  });
  g_lua.set_function("createTelegramNotifier", [&](sol::table data) {
    return make_shared<TelegramNotifier>(data);
  });

}
