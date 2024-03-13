#include "fmt/format.h"
#include "fmt/ranges.h"
#include <map>
#include <curl/curl.h>
#include "notifiers.hh"
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
vector<std::shared_ptr<Notifier>> g_notifiers;

/* the idea
   Every checker can generate multiple alerts.
   However, some alerts should only be reported if they persist for a bit
   This means we should only pass on an alert if we've seen it for a while nown
   Alerts can't generate persistent identifiers (id) for the same alert 
   So we must use the text representation and the checker should keep that constant

   our throtle then consists of a set of strings and when they were reported per checker
   If a checker stops reporting that string, that is fine

   we ask the throttle: give me a list of active alerts
   We never talk to the checker directly
*/

set<pair<Checker*, std::string>> CheckResultFilter::getFilteredResults()
{

  set<pair<Checker*, std::string>> ret;
  time_t now = time(nullptr);

  //  map<Checker*, map<std::string, set<time_t> > > d_reports;
  for(const auto& r : d_reports) {
    Checker& ptr = *r.first;
    time_t lim = now - ptr.d_failurewin;
    for(const auto& sp : r.second) {
      int count = count_if(sp.second.begin(), sp.second.end(),
                           [&](const auto& r) { return r >= lim; });
      if(count >= ptr.d_minfailures)
        ret.emplace(&ptr, sp.first);
      else
        fmt::print("Alert '{}' not repeated enough in {} seconds, {} < {}\n",
                   sp.first, ptr.d_failurewin, count, ptr.d_minfailures);
    }
  }
  return ret;
}

int main(int argc, char **argv)
try
{
  initLua();
  try {
    if(auto ptr = getenv("SIMPLOMON_CONFIG_URL")) {
      MiniCurl mc;
      fmt::print("Getting config from the network '{}'\n", ptr);
      string script = mc.getURL(ptr);
      g_lua.safe_script(script);
    }
    else if(argc > 1) {
      string src = argv[1];
      if(src.find("https://")==0) {
        MiniCurl mc;
        fmt::print("Getting config from '{}'\n", src);
        string script = mc.getURL(src);
        g_lua.safe_script(script);
      }
      else
        g_lua.safe_script_file(src);
    }
    else {
      fmt::print("Getting config from '{}'\n", "simplomon.conf");
      g_lua.safe_script_file("simplomon.conf");
    }

  }
  catch(sol::error& e) {
    fmt::print("Error parsing configuration: {}\n", e.what());
    return EXIT_FAILURE;
  }

  if(g_notifiers.empty()) {
    fmt::print("Did not configure a notifier, can't notify anything\n");
  }

  startWebService();
  
  CheckResultFilter crf;
  auto prevFiltered = crf.getFilteredResults(); // should be none
  for(;;) {
    time_t startRun = time(nullptr);
    
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

      if(!reason.empty()) {
        crf.reportResult(c.get(), reason);
        fmt::print("\nreporting: '{}'", reason);
      }
      fmt::print("."); cout.flush();
    }
    fmt::print("\n");
    // these are the active filtered alerts
    auto filtered = crf.getFilteredResults();
    fmt::print("Got {} filtered results\n", filtered.size());
    
    decltype(filtered) diff;
    set_difference(filtered.begin(), filtered.end(),
                   prevFiltered.begin(), prevFiltered.end(),
                   inserter(diff, diff.begin()));
    
    fmt::print("Got {} NEW results\n", diff.size());
    auto sendOut=[&](bool newOld) {
      for(const auto& f : diff) {
        for(const auto & n : f.first->notifiers) {
          try {
            if(newOld) {
              n->alert(f.second);
            }
            else {
              n->alert(fmt::format("🎉 the following alert is over: {}", f.second));
            }
          }
          catch(exception& e) {
            fmt::print("Failed to send notification: {}\n", e.what());
          }
        }
        if(newOld) 
          fmt::print("Sent out notification: {}\n", f.second);
        else
          fmt::print("Sent out resolved: {}\n", f.second);
      }
    };

    sendOut(true);
      

    diff.clear();
    set_difference(prevFiltered.begin(), prevFiltered.end(),
                   filtered.begin(), filtered.end(),
                   inserter(diff, diff.begin()));
    fmt::print("{} alerts were resolved\n", diff.size());
    sendOut(false);
    prevFiltered = filtered;
    time_t passed = time(nullptr) - startRun;
    if(passed < 60) {
      int sleeptime = 60 - passed;
      fmt::print("Sleeping {} seconds\n", sleeptime);
      sleep(sleeptime);
    }
  }
}
catch(std::exception& e)
{
  fmt::print("Fatal error: {}\n", e.what());
}
catch(...)
{
  fmt::print("Fatal error\n");
}
