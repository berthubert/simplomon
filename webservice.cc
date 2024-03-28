#include "simplomon.hh"
#include <nlohmann/json.hpp>
#include "httplib.h"
#include <mutex>
#include <openssl/bio.h>
#include <openssl/evp.h>

static std::mutex s_lock;
static nlohmann::json s_state;
static nlohmann::json s_checkerstates;
void giveToWebService(const std::set<std::pair<Checker*, std::string>>& cs,
                      const std::map<std::string, time_t>& startAlerts)
{
  std::lock_guard<std::mutex> m(s_lock);
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
  std::lock_guard<std::mutex> m(s_lock);
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

static void webserverThread(std::unique_ptr<httplib::Server> svr, std::string addr)
{
  ComboAddress ca(addr, 8080);
  if(svr->listen(ca.toString(), ntohs(ca.sin4.sin_port))) {
    std::cout<<"Error launching server: "<<strerror(errno)<<std::endl;
    exit(EXIT_FAILURE);
  }
}


static int B64Decode(const std::string& src, std::string& dst)
{
  if (src.empty() ) {
    dst.clear();
    return 0;
  }
  int dlen = ( src.length() * 6 + 7 ) / 8 ;
  ssize_t olen = 0;
  dst.resize(dlen);
  BIO *bio, *b64;
  bio = BIO_new(BIO_s_mem());
  BIO_write(bio, src.c_str(), src.length());
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  olen = BIO_read(b64, &dst.at(0), dlen);
  if ((olen == 0 || olen == -1) && BIO_should_retry(bio)) {
    BIO_free_all(bio);
    throw std::runtime_error("BIO_read failed to read all data from memory buffer");
  }
  BIO_free_all(bio);
  if (olen > 0) {
    dst.resize(olen);
    return 0;
  }
  return -1;
}

static std::optional<std::string> g_webpassword;
static std::optional<std::string> g_webuser;

static bool checkAuth(const httplib::Request& req, httplib::Response &res)
{
  std::string user;
  std::string password;
  std::string dec;
  std::string::size_type pos;

  
  //  Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== 
  std::string auth = req.get_header_value("Authorization");
  if(auth.find("Basic ") != 0)
    goto fail;

  if(!g_webpassword || g_webpassword->empty())
    goto fail;

  
  if(B64Decode(auth.substr(6), dec))
    goto fail;

  pos = dec.find(':');
  if(pos == std::string::npos)
    goto fail;
  user = dec.substr(0, pos);
  password = dec.substr(pos+1);

  if(g_webuser && !g_webuser->empty() && *g_webuser != user) {
    fmt::print("User specified '{}' did not match configured user '{}'\n",
               user, *g_webuser);
    goto fail;
  }

  if(g_webpassword != password) {
    fmt::print("Wrong password");
    goto fail;
  }
  
  //  fmt::print("User '{}', password '{}'\n", user, password);
  return true;
  
 fail:;
  res.set_header("WWW-Authenticate", "Basic realm=\"Simplomon\"");
  res.status = 401;
  return false;
  // WWW-Authenticate: Basic realm="User Visible Realm"
}

void startWebService(sol::table data)
{
  checkLuaTable(data, {"address"}, { "password", "user"});
  auto svr = std::make_unique<httplib::Server>();
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
    std::lock_guard<std::mutex> m(s_lock);
    res.set_content(s_state.dump(), "application/json");
  });

  svr->Get("/checker-states/?", [](const auto& req, auto& res) {
    if(!checkAuth(req, res))
      return;

    std::lock_guard<std::mutex> m(s_lock);
    res.set_content(s_checkerstates.dump(), "application/json");
  });

  svr->set_mount_point("/", "./html");  

  
  std::thread t(webserverThread, std::move(svr), data.get_or("address", std::string("0.0.0.0:8080")));
  t.detach();
}

