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
#include "sqlwriter.hh"
#include "sol/sol.hpp"

using namespace std;

vector<std::unique_ptr<Checker>> g_checkers;
vector<std::shared_ptr<Notifier>> g_notifiers;

std::unique_ptr<SQLiteWriter> g_sqlw;

/* the idea
   Every checker can generate multiple alerts.
   However, some alerts should only be reported if they persist for a bit
   This means we should only pass on an alert if we've seen it for a while now
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
      else if(count)
        fmt::print("Alert '{}' not repeated enough in {} seconds, {} < {}, oldest alert: {}\n",
                   sp.first, ptr.d_failurewin, count, ptr.d_minfailures,
                   sp.second.empty() ? 0 : *sp.second.begin()
                   );
    }
  }
  // and now the cleanup
  time_t lim = now - d_maxseconds;
  for(auto iter = d_reports.begin(); iter != d_reports.end(); ) {
    // per Checker, map<string, set<time_t>>
    for(auto iter2 = iter->second.begin() ; iter2 != iter->second.end();) {
      // pair<string, set<time_t>>
      // clean up old time_t's from the set
      //      fmt::print("Cleanup for '{}', before: {}", iter2->first, iter2->second.size());
      erase_if(iter2->second, [&lim](const auto& a) { return a < lim; });
      //fmt::print(", after: {}\n", iter2->second.size());
      
      // if nothing is left, erase ourselves (the pair within the checker)
      if(iter2->second.empty()) {
        //fmt::print("Cleaning up entire message '{}'\n", iter2->first);
        iter2 = iter->second.erase(iter2);
      }
      else
        ++iter2;
    }
    // if the map is empty, erase the checker too
    if(iter->second.empty())
      iter = d_reports.erase(iter);
    else
      ++iter;
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
  
  CheckResultFilter crf(300);
  auto prevFiltered = crf.getFilteredResults(); // should be none
  
  for(;;) {
    time_t startRun = time(nullptr);
    
    for(auto &c : g_checkers) {
      string reason;
      try {
        CheckResult cr = c->perform();
        reason = cr.d_reason;
        if(!c->d_results.empty()) {
          auto attr = c->d_attributes;
          for(const auto& r: c->d_results) {
            std::vector<std::pair<const char*, SQLiteWriter::var_t>> out;
            for(const auto& a : attr)
              out.push_back({a.first.c_str(), a.second});
            out.push_back({"subject", r.first});
            for(const auto& res : r.second)
              out.push_back({res.first.c_str(), res.second});
            out.push_back({"tstamp", time(nullptr)});
            if(g_sqlw)
              g_sqlw->addValue(out, c->getCheckerName());
          }
        }
      }
      catch(exception& e) {
        reason = "Exception caught: "+string(e.what());
      }
      catch(...) {
        reason = "Unknown exception caught";
      }

      if(!reason.empty()) {
        if(!c->d_mute)
          crf.reportResult(c.get(), reason);
        if(g_sqlw) {
          auto attr = c->d_attributes;
          std::vector<std::pair<const char*, SQLiteWriter::var_t>> out;
          for(const auto& a : attr)
            out.push_back({a.first.c_str(), a.second});
          out.push_back({"checker", c->getCheckerName()});
          out.push_back({"reason", reason});
          out.push_back({"tstamp", time(nullptr)});
          g_sqlw->addValue(out, "reports");
        }
      }
      fmt::print("."); cout.flush();
    }
    fmt::print("\n");
    // these are the active filtered alerts
    auto filtered = crf.getFilteredResults();
    fmt::print("Got {} filtered results, ", filtered.size());

    giveToWebService(filtered);

    decltype(filtered) diff;
    set_difference(filtered.begin(), filtered.end(),
                   prevFiltered.begin(), prevFiltered.end(),
                   inserter(diff, diff.begin()));
    
    fmt::print("got {} NEW results, ", diff.size());
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
    fmt::print("{} alerts were resolved", diff.size());
    
    sendOut(false);
    prevFiltered = filtered;
    time_t passed = time(nullptr) - startRun;
    int interval = 60;
    if(passed < interval) {
      int sleeptime = interval - passed;
      fmt::print(", sleeping {} seconds\n", sleeptime);
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
