#pragma once
#include <mutex>
#include <string>
#include "record-types.hh"
#include "sclasses.hh"
#include "notifiers.hh"
#include "sol/sol.hpp"

#include <fmt/chrono.h>
using namespace std;

extern sol::state g_lua;

void initLua();

// sets alert status if there have been more than x alerts in y seconds
struct AlertFilter
{
  explicit AlertFilter(int maxseconds=3600) : d_maxseconds(maxseconds) {}
  void reportAlert(time_t t)
  {
    alerts.insert(t);
  }
  void reportAlert()
  {
    alerts.insert(time(nullptr));
  }

  bool shouldAlert(int numalerts, int numseconds)
  {
    time_t lim =time(nullptr) - d_maxseconds;
    std::erase_if(alerts, [&](const auto& i) { return i < lim; });

    lim = time(nullptr) - numseconds;
    int count=0;
    for(auto iter = alerts.lower_bound(lim); iter != alerts.end(); ++iter)
      ++count;
    
    return count >= numalerts;
  }
  std::set<time_t> alerts;
  int d_maxseconds;
};

struct CheckResult
{
  CheckResult() {}
  CheckResult(const char* reason) : d_reason(reason) {}
  CheckResult(const std::string& reason) : d_reason(reason) {}
  std::string d_reason;
};

class Checker
{
public:
  Checker() {}
  Checker(const Checker&) = delete;
  virtual CheckResult perform() = 0;

  CheckResult getStatus() 
  {
    std::lock_guard<std::mutex> l(d_m);
    return d_status;
  }
  void setStatus(const CheckResult& cr) 
  {
    std::lock_guard<std::mutex> l(d_m);
    d_status = cr; 
  }
  
  AlertFilter d_af;
  int d_minalerts=1;
  int d_alertwindow = 60;
  std::string d_alertedreason;
  
private:
  CheckResult d_status;
  std::mutex d_m;


};


class DNSChecker : public Checker
{
public:
  DNSChecker(const std::string& nsip,
             const std::string& qname,
             const std::string& qtype,
             const std::set<std::string>& acceptable);
  DNSChecker(sol::table data);
  CheckResult perform() override;

private:
  ComboAddress d_nsip;
  DNSName d_qname;
  DNSType d_qtype;
  std::set<std::string> d_acceptable;
};

class RRSIGChecker : public Checker
{
public:
  RRSIGChecker(sol::table data);
  CheckResult perform() override;

private:
  ComboAddress d_nsip;
  DNSName d_qname;
  DNSType d_qtype;
  int d_minDays=0;
};


class DNSSOAChecker : public Checker
{
public:
  DNSSOAChecker(const std::string& doain,
             const std::set<std::string>& servers);
  DNSSOAChecker(sol::table data);
  CheckResult perform() override;

private:
  DNSName d_domain;
  std::set<ComboAddress> d_servers;
};


class TCPPortClosedChecker : public Checker
{
public:
  TCPPortClosedChecker(const std::set<std::string>& servers,
             const std::set<int>& ports);
  TCPPortClosedChecker(sol::table data);
  CheckResult perform() override;

private:
  std::set<ComboAddress> d_servers;
  std::set<int> d_ports;
};

class HTTPSChecker : public Checker
{
public:
  HTTPSChecker(sol::table data);
  ~HTTPSChecker()
  {
  }
  CheckResult perform() override;

private:
  std::string d_url;
  int d_maxAgeMinutes = 0;
  unsigned int d_minBytes = 0;
  unsigned int d_minCertDays = 14;
  std::optional<ComboAddress> d_serverIP;
};

class HTTPRedirChecker : public Checker
{
public:
  HTTPRedirChecker(sol::table data);
  CheckResult perform() override;

private:
  std::string d_fromhostpart, d_frompath, d_tourl;
};



extern std::vector<std::unique_ptr<Checker>> g_checkers;
void checkLuaTable(sol::table data,
                   const std::set<std::string>& mandatory,
                   const std::set<std::string>& opt = std::set<std::string>());
extern std::vector<std::unique_ptr<Notifier>> g_notifiers;
