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
vector<std::shared_ptr<Notifier>> g_notifiers;
std::optional<bool> g_haveIPv6;
std::unique_ptr<SQLiteWriter> g_sqlw;

TEST_CASE("alert filter test") {
  CHECK(1 == 1);
}

TEST_CASE("Prometheus parser") {
  PrometheusParser parser;

  parser.parse("");
}