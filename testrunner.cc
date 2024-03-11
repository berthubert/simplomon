#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <algorithm> // std::move() and friends
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h> //unlink(), usleep()
#include <unordered_map>
#include "doctest.h"
#include "httplib.h"
#include "nlohmann/json.hpp"

#include "simplomon.hh"

using namespace std;
vector<std::unique_ptr<Checker>> g_checkers;
std::vector<std::unique_ptr<Notifier>> g_notifiers;

TEST_CASE("alert filter test") {
  AlertFilter af1;
  time_t now = time(nullptr);
  
  af1.reportAlert(now-4000);
  af1.reportAlert(now-3000);
  af1.reportAlert(now-2000);
  af1.reportAlert(now-1000);
  af1.reportAlert(now);

  CHECK(af1.shouldAlert(2, 900) == false);
  CHECK(af1.shouldAlert(1, 1001) == true);
  CHECK(af1.shouldAlert(2, 1001) == true);
  CHECK(af1.shouldAlert(4, 3001) == true);
  CHECK(af1.shouldAlert(4, 5000) == true);

  CHECK(af1.shouldAlert(5, 5001) == false);

  AlertFilter af2;
  now=time(nullptr);
  af2.reportAlert(now);
  af2.reportAlert(now-60);
  CHECK(af2.shouldAlert(2, 60) == true);
}

