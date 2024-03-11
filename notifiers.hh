#pragma once
#include <string>
#include "sol/sol.hpp"
#include "sclasses.hh"

class Notifier
{
public:
  virtual void alert(const std::string& message) = 0;
};


class PushoverNotifier : public Notifier
{
public:
  PushoverNotifier(const std::string& user, const std::string& apikey);
  void alert(const std::string& message) override;
private:
  std::string d_user, d_apikey;
};


class NtfyNotifier : public Notifier
{
public:
  NtfyNotifier(const std::string& topic) : d_topic(topic) {}
  void alert(const std::string& message) override;
private:
  std::string d_topic;
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
