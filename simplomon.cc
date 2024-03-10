#include "fmt/format.h"
#include "fmt/ranges.h"
#include <map>
#include <curl/curl.h>
#include "pushover.hh"
#include "nlohmann/json.hpp"
#include <unistd.h>
#include <time.h>
#include "minicurl.hh"
#include <thread>
#include <mutex>
#include "simplomon.hh"
#include "sol/sol.hpp"

using namespace std;
vector<std::unique_ptr<Checker>> g_checkers;
std::unique_ptr<PushoverReporter> g_reporter;

int main(int argc, char **argv)
{
  initLua();
  try {
    g_lua.safe_script_file("simplomon.conf");
  }
  catch(sol::error& e) {
    fmt::print("Error parsing configuration: {}\n", e.what());
    return EXIT_FAILURE;
  }

  if(!g_reporter) {
    fmt::print("Did not configure a notifier, can't run\n");
  }

  for(;;) {
    for(auto &c : g_checkers) {
      string reason;
      try {
        CheckResult cr = c->perform();
        reason = cr.d_reason;
      }
      catch(exception& e) {
        reason = "Exception caught: "+string(e.what());
      }
      catch(...) {
        reason = "Unknown exception caught";
      }

      if(!reason.empty())
        c->d_af.reportAlert();

      // we could still be in an alert, even though the check was ok now
      bool inAlert = c->d_af.shouldAlert(c->d_minalerts, c->d_alertwindow);
      if(!inAlert) {// muted
        if(!reason.empty())
          fmt::print("Muting an alert since it does not yet meet threshold. The alert: {}\n", reason);
        reason="";
      }
      else if(reason.empty()) {
        fmt::print("Continuing alert, despite test now saying it is ok\n");
        reason = c->d_alertedreason; // maintain alert
      }
      
      if(reason != c->d_alertedreason) { // change of state
        string msg;
        if(!reason.empty()) 
          msg=fmt::format("{}\n", reason);
        else
          msg=fmt::format("🥳 The following alert is resolved: {}\n", c->d_alertedreason);
        c->d_alertedreason = reason;

        g_reporter->alert(msg);
        fmt::print("Sent out notification: {}\n", msg);
      }
      else if(!reason.empty()) {
        fmt::print("Alert '{}' still active, but reported already\n", reason);
      }
    }
    sleep(60);
  }
}
