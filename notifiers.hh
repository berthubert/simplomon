#pragma once
#include <string>
#include "sol/sol.hpp"
#include "sclasses.hh"
#include <set>
#include "sqlwriter.hh"
#include "fmt/core.h"

class Notifier
{
public:
  Notifier(sol::table& data)
  {
    d_minMinutes = data.get_or("minMinutes", 0);
    data["minMinutes"] = sol::lua_nil;
  }
  Notifier(bool)
  {
  }

  ~Notifier()
  {
    //    fmt::print("A notifier was destroyed\n");
  }
  virtual void alert(const std::string& message) = 0;
  std::string getNotifierName() { return d_notifierName; }
  void bulkAlert(const std::string& textBody);
  void bulkDone();
protected:
  std::map<std::string, time_t> d_times;
  bool d_verbose = false;
  std::string d_notifierName;
private:
  std::set<std::string> d_reported, d_prevReported;
  std::set<std::string> d_oldEnough, d_prevOldEnough;
  int d_minMinutes=0;

};

class InternalWebNotifier : public Notifier
{
public:
  InternalWebNotifier() : Notifier(false)
  {
    //    d_verbose=true;
    d_notifierName="InternalWeb";
  }
  std::map<std::string, time_t> getTimes()
  {
    return d_times;
  }
  
  void alert(const std::string& message) {}
};


class SQLiteWriterNotifier : public Notifier
{
public:
  SQLiteWriterNotifier() : Notifier(false)
  {
    d_notifierName="SQLiteWriter";
  }

  void alert(const std::string& message) override;
};

class PushoverNotifier : public Notifier
{
public:
  PushoverNotifier(sol::table data);
  void alert(const std::string& message) override;
private:
  std::string d_user, d_apikey;
};


class NtfyNotifier : public Notifier
{
public:
  NtfyNotifier(sol::table data);
  void alert(const std::string& message) override;
private:
  std::string d_auth, d_url, d_topic;
};

class TelegramNotifier : public Notifier
{
public:
  TelegramNotifier(const std::string& user, const std::string& apikey);
  void alert(const std::string& message) override;
private:
  std::string d_user, d_apikey;
};

class EmailNotifier : public Notifier
{
public:
  EmailNotifier(sol::table data);
  void alert(const std::string& message) override;
private:
  std::string d_from, d_to;
  ComboAddress d_server;
};
