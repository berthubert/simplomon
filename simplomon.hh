#pragma once
#include <mutex>
#include <regex>
#include <string>
#include "record-types.hh"
#include "sclasses.hh"
#include "notifiers.hh"
#include "sol/sol.hpp"
#include "nlohmann/json.hpp"
#include <fmt/chrono.h>
#include <fmt/ranges.h>
#include "sqlwriter.hh"
using namespace std;

extern sol::state g_lua;

void initLua();

struct CheckResult
{
  CheckResult() {}
  CheckResult(const char* reason) : d_reasons({{"", {reason}}})
  {
    if(!*reason)
      d_reasons.clear();
  }
  CheckResult(const std::string& reason) : d_reasons({{"", {reason}}})
  {
    if(reason.empty())
      d_reasons.clear();
  }
  std::map<std::string,vector<std::string>> d_reasons;
};

extern std::vector<std::shared_ptr<Notifier>> g_notifiers;

class Checker
{
public:
  Checker(sol::table& data, int minFailures = -1) 
  {
    if(minFailures >= 0)
      d_minfailures = minFailures;
    d_minfailures = data.get_or("minFailures", d_minfailures);
    d_failurewin =  data.get_or("failureWindow", d_failurewin);
    d_mute = data.get_or("mute", false);
    data["mute"] = sol::lua_nil;
    
    data["subject"] = sol::lua_nil;
    data["minFailures"] = sol::lua_nil;
    data["failureWindow"] = sol::lua_nil;
    // bake in
    //    fmt::print("Baking in {} notifiers\n", g_notifiers.size());
    std::optional<vector<shared_ptr<Notifier>>> spec = data["notifiers"];
    if(spec) {
      //      fmt::print("Got {} specific notifiers\n", spec->size());
      notifiers.push_back(g_notifiers[0]);
      notifiers.push_back(g_notifiers[1]);
      for(auto& n : *spec)
        notifiers.push_back(n);
      data["notifiers"] = sol::lua_nil;
    }
    else notifiers = g_notifiers;
    
    //    for(const auto& n : notifiers)
    //  fmt::print("Adding notifier {}\n", n->getNotifierName());
  }
  Checker(const Checker&) = delete;
  void Perform()
  {
    d_reasons = this->perform();
  }
  virtual CheckResult perform() = 0;
  virtual std::string getDescription() = 0;
  virtual std::string getCheckerName() = 0;
  std::map<std::string, SQLiteWriter::var_t> d_attributes;
  std::map<std::string, std::map<std::string, SQLiteWriter::var_t>> d_results;
  int d_minfailures=1;
  int d_failurewin = 120;

  std::vector<std::shared_ptr<Notifier>> notifiers;
  bool d_mute = false;
  CheckResult d_reasons;
private:

  std::mutex d_m;
};

// sets alert status if there have been more than x alerts in y seconds
struct CheckResultFilter
{
  explicit CheckResultFilter(int maxseconds=3600) : d_maxseconds(maxseconds) {}
  void reportResult(Checker* source, const std::string& subject, const std::string& cr, time_t t)
  {
    d_reports[source][subject][cr].insert(t);
  }
  void reportResult(Checker* source, const std::string& subject, const std::string& cr)
  {
    reportResult(source, subject, cr, time(nullptr));
  }

  std::set<pair<Checker*, std::string>> getFilteredResults();

  std::map<Checker*, std::map<std::string, map<std::string, std::set<time_t>> >> d_reports;
  
  int d_maxseconds;
};



class DNSChecker : public Checker
{
public:
  DNSChecker(sol::table data);
  CheckResult perform() override;
  std::string getCheckerName() override { return "dns"; }
  std::string getDescription() override
  {
    return fmt::format("DNS check, server {}, qname {}, qtype {}, acceptable: {}",
                       d_nsip.toStringWithPort(), d_qname.toString(), toString(d_qtype), d_acceptable);
  }
private:
  ComboAddress d_nsip;
  std::optional<ComboAddress> d_localIP;
  DNSName d_qname;
  DNSType d_qtype;
  std::set<std::string> d_acceptable;
  bool d_rd = true;
};

class RRSIGChecker : public Checker
{
public:
  RRSIGChecker(sol::table data);
  CheckResult perform() override;
  std::string getCheckerName() override { return "rrsig"; }
  std::string getDescription() override
  {
    return fmt::format("RRSIG check, server {}, qname {}, qtype {}, minDays: {}",
                       d_nsip.toStringWithPort(), d_qname.toString(), toString(d_qtype), d_minDays);
  }

private:
  ComboAddress d_nsip;
  DNSName d_qname;
  DNSType d_qtype;
  int d_minDays=0;
};


class DNSSOAChecker : public Checker
{
public:
  DNSSOAChecker(sol::table data);
  CheckResult perform() override;
  std::string getCheckerName() override { return "dnssoa"; }
  std::string getDescription() override
  {
    std::vector<string> servers;
    for(const auto& s : d_servers) servers.push_back(s.toStringWithPort());
    return fmt::format("DNS SOA check, servers {}, domain {}",
                       servers, d_domain.toString());
  }

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
  std::string getCheckerName() override { return "tcpportclosed"; }
  std::string getDescription() override
  {
    std::vector<string> servers;
    for(const auto& s : d_servers) servers.push_back(s.toString());
    return fmt::format("TCP closed check, servers {}, ports {}",
                       servers, d_ports);
  }

  
private:
  std::set<ComboAddress> d_servers;
  std::set<int> d_ports;
};


class PINGChecker : public Checker
{
public:
  PINGChecker(sol::table data);
  CheckResult perform() override;
  std::string getCheckerName() override { return "ping"; }
  std::string getDescription() override
  {
    std::vector<string> servers;
    for(const auto& s : d_servers) servers.push_back(s.toString());
    return fmt::format("PING check, servers {}", servers);

  }

private:
  std::set<ComboAddress> d_servers;
  std::optional<ComboAddress> d_localIP;
};


class HTTPSChecker : public Checker
{
public:
  HTTPSChecker(sol::table data);
  ~HTTPSChecker()
  {
  }
  CheckResult perform() override;
  std::string getCheckerName() override { return "https"; }
  std::string getDescription() override
  {
    return fmt::format("HTTPS check, URL {}, method {}",
                       d_url, d_method); // XX needs more
  }

private:
  std::string d_url;
  int d_maxAgeMinutes = 0;
  unsigned int d_minBytes = 0;
  unsigned int d_minCertDays = 14;
  std::optional<ComboAddress> d_serverIP, d_localIP4, d_localIP6;
  std::vector<ComboAddress> d_dns;
  std::string d_regexStr;
  std::regex d_regex;

  std::string d_method;
  std::string d_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";
};


class PrometheusChecker : public Checker
{
public:
  PrometheusChecker(sol::table data);
  CheckResult perform() override;
  std::string getCheckerName() override { return "prometheus"; }
  std::string getDescription() override
  {
    return fmt::format("Prometheus check, IP {}",
                       d_serverIP.toStringWithPort());
  }

private:
  ComboAddress d_serverIP;

};


class HTTPRedirChecker : public Checker
{
public:
  HTTPRedirChecker(sol::table data);
  CheckResult perform() override;
  std::string getCheckerName() override { return "redir"; }
  std::string getDescription() override
  {
    return fmt::format("HTTP(s) redir check, from {}, to{}",
                       d_fromhostpart+d_frompath, d_tourl);
  }

private:
  std::string d_fromhostpart, d_frompath, d_tourl;
};

class SMTPChecker : public Checker
{
public:
  SMTPChecker(sol::table data);
  CheckResult perform() override;
  std::string getCheckerName() override { return "smtp"; }
  std::string getDescription() override
  {
    return fmt::format("SMTP check for {}",
                       d_server.toStringWithPort());
  }

private:
  ComboAddress d_server;
};


extern std::vector<std::unique_ptr<Checker>> g_checkers;
extern std::unique_ptr<SQLiteWriter> g_sqlw;
extern std::optional<bool> g_haveIPv6;

void checkLuaTable(sol::table data,
                   const std::set<std::string>& mandatory,
                   const std::set<std::string>& opt = std::set<std::string>());

void startWebService(sol::table data);
void giveToWebService(const std::set<pair<Checker*, std::string>>&,
                      const std::map<std::string, time_t>& startAlerts);
void updateWebService();
bool checkForWorkingIPv6();
std::vector<ComboAddress> DNSResolveAt(const DNSName& name, const DNSType& type,
                                       const std::vector<ComboAddress>& servers,
                                       std::optional<ComboAddress> local4 = std::optional<ComboAddress>(),
                                       std::optional<ComboAddress> local6 = std::optional<ComboAddress>()
                                       );
std::vector<ComboAddress> getResolvers();
std::string getAgeDesc(time_t then);
