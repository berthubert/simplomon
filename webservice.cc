#include "simplomon.hh"
#include <nlohmann/json.hpp>
#include "httplib.h"
#include <mutex>

static std::mutex s_lock;
static nlohmann::json s_state;
static nlohmann::json s_checkerstates;
void giveToWebService(const std::set<pair<Checker*, std::string>>& cs,
                      const std::map<std::string, time_t>& startAlerts)
{
  std::lock_guard<mutex> m(s_lock);
  s_state = nlohmann::json::object();

  auto arr = nlohmann::json::array();
  for(const auto& c: cs) {
    time_t start = 0;
    if(auto iter=startAlerts.find(c.second); iter != startAlerts.end())
      start = iter->second;
    else {
      ; //fmt::print("Could not find '{} {}' in {} alerts\n",
      //       c.first->getCheckerName(), c.second, startAlerts.size());
    }
    arr.push_back(getAgeDesc(start)+": "+c.second);
  }
  s_state["alerts"] = arr;
}


static nlohmann::json toJson(const SQLiteWriter::var_t& var)
{
  nlohmann::json j;
  std::visit([&j](auto&& arg) {
    using T = std::decay_t<decltype(arg)>;
    if constexpr (std::is_same_v<T, nullptr_t>)
                   return;
    else  {
      j = arg;
    }
    
  }, var);
  return j;
  
}

void updateWebService()
{
  std::lock_guard<mutex> m(s_lock);
  s_checkerstates = nlohmann::json::object();

  for(auto &c : g_checkers) {
    nlohmann::json cstate;
    
    auto attr = c->d_attributes;
    nlohmann::json jattr=nlohmann::json::object(), jresults= nlohmann::json::object(), jreasons = nlohmann::json::object();
    for(const auto& a : c->d_attributes)
      jattr[a.first] = toJson(a.second);

    for(const auto& r: c->d_results) {
      for(const auto& res : r.second)
        jresults[r.first][res.first] = toJson(res.second);
    }

    for(const auto& r: c->d_reasons.d_reasons) {
      for(const auto& res : r.second)
        jreasons[r.first].push_back(res);
    }

    
    cstate["attr"] = jattr;
    cstate["results"] = jresults;
    cstate["reasons"] = jreasons;
    s_checkerstates[c->getCheckerName()].push_back(cstate);
  }
}

static void webserverThread(std::unique_ptr<httplib::Server> svr, string addr)
{
  ComboAddress ca(addr, 8080);
  if(svr->listen(ca.toString(), ntohs(ca.sin4.sin_port))) {
    cout<<"Error launching server: "<<strerror(errno)<<endl;
    exit(EXIT_FAILURE);
  }
}

static std::optional<string> g_webpassword;
static std::optional<string> g_webuser;

static bool checkAuth(const httplib::Request& req, httplib::Response &res)
{
  if (g_webuser && !g_webuser->empty() && g_webpassword && !g_webpassword->empty()) {
    const auto& [expectHeader, expectValue] = httplib::make_basic_authentication_header(*g_webuser, *g_webpassword);

    const std::string actualValue = req.get_header_value(expectHeader);

    if (actualValue == expectValue) {
      return true;
    } else if (!actualValue.empty()) {
      fmt::println("Unknown username or wrong password");
    }
  }

  res.set_header("WWW-Authenticate", "Basic realm=\"Simplomon\"");
  res.status = 401;
  return false;
  // WWW-Authenticate: Basic realm="User Visible Realm"
}

void startWebService(sol::table data)
{
  checkLuaTable(data, {"address"}, { "password", "user"});
  auto svr = make_unique<httplib::Server>();
  g_webpassword = data["password"];
  g_webuser = data["user"]; // std::optional

  svr->set_socket_options([](socket_t sock) {
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const void *>(&yes), sizeof(yes));
  });

  svr->Get("/health", [](const httplib::Request &, httplib::Response &res) {
    nlohmann::json j;
    j["health"]="ok";
    res.set_content(j.dump(), "application/json");
  });

  svr->Get("/state", [](const auto& req, auto& res) {
    if(!checkAuth(req, res))
      return;
    std::lock_guard<mutex> m(s_lock);
    res.set_content(s_state.dump(), "application/json");
  });

  svr->Get("/checker-states/?", [](const auto& req, auto& res) {
    if(!checkAuth(req, res))
      return;

    std::lock_guard<mutex> m(s_lock);
    res.set_content(s_checkerstates.dump(), "application/json");
  });

  svr->set_mount_point("/", "./html");  

  
  std::thread t(webserverThread, std::move(svr), data.get_or("address", string("0.0.0.0:8080")));
  t.detach();
}

