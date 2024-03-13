#include "simplomon.hh"
#include <nlohmann/json.hpp>
#include "httplib.h"
#include <mutex>

static std::mutex s_lock;
static nlohmann::json s_state;
void giveToWebService(const std::set<pair<Checker*, std::string>>& cs)
{
  std::lock_guard<mutex> m(s_lock);
  s_state = nlohmann::json::object();

  auto arr = nlohmann::json::array();
  for(const auto& c: cs) {
    arr.push_back(c.second);
  }
  s_state["alerts"] = arr;
}

static void webserverThread(std::unique_ptr<httplib::Server> svr)
{
  if(svr->listen("0.0.0.0", 8080)) {
    cout<<"Error launching server: "<<strerror(errno)<<endl;
    exit(EXIT_FAILURE);
  }
}

void startWebService()
{
  auto svr = make_unique<httplib::Server>();
  
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
    std::lock_guard<mutex> m(s_lock);
    res.set_content(s_state.dump(), "application/json");
  });
  
  std::thread t(webserverThread, std::move(svr));
  t.detach();

  
}

