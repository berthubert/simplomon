#pragma once
#include <string>


class PushoverReporter
{
public:
  PushoverReporter(const std::string& user, const std::string& apikey);
  void alert(const std::string& message);
private:
  std::string d_user, d_apikey;
};
