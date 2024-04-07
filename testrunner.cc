#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <algorithm> // std::move() and friends
#include <cmath>
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
  using prom_t = PrometheusParser::prom_t;

  SUBCASE("Empty input") {
    CHECK_NOTHROW(parser.parse(""));
  }

  // Reference: https://prometheus.io/docs/instrumenting/exposition_formats/

  SUBCASE("Empty lines are ignored") {
    CHECK_NOTHROW(parser.parse("\n"));
    CHECK_NOTHROW(parser.parse("\n\n"));
  }

  SUBCASE("Comment lines are ignored") {
    CHECK_NOTHROW(parser.parse("# This is nothing\n"));
    CHECK_EQ(parser.d_prom, prom_t {});

    CHECK_NOTHROW(parser.parse("  # This is also nothing  \n"));
    CHECK_EQ(parser.d_prom, prom_t {});
  }

  SUBCASE("Simple line") {
    CHECK_NOTHROW(parser.parse("\n# A comment:\nsome_metric 0.8\n"));
    CHECK_EQ(parser.d_prom, prom_t {{"some_metric", {{{}, 0.8}}}});
  }

  SUBCASE("Special floating-point values") {
    CHECK_NOTHROW(parser.parse("sandwich_bytes nan\n"));
    CHECK(isnan(parser.d_prom["sandwich_bytes"][{}]));

    CHECK_NOTHROW(parser.parse("sandwich_bytes -Inf\n"));
    CHECK(isinf(parser.d_prom["sandwich_bytes"][{}]));
  }

  SUBCASE("Timestamps") {
    CHECK_NOTHROW(parser.parse("temp_degrees 19.5 1712484057\n"));
    CHECK_EQ(parser.d_prom, prom_t {{"temp_degrees", {{{}, 19.5}}}});
  }

  SUBCASE("Labels") {
    CHECK_NOTHROW(parser.parse("backflips_total{method=\"normal\"} 12\n"));
    CHECK_EQ(parser.d_prom, prom_t {{"backflips_total", {{{{"method", "normal"}}, 12}}}});

    CHECK_NOTHROW(parser.parse("barrel_rolls_total{star=\"fox\",toad=\"slippy\"} 0\n"));
    CHECK_EQ(parser.d_prom, prom_t {{"barrel_rolls_total", {{{{"star", "fox"}, {"toad", "slippy"}}, 0}}}});

    CHECK_NOTHROW(parser.parse("trailing_commas_total{where=\"here\",} 1\n"));
    CHECK_EQ(parser.d_prom, prom_t {{"trailing_commas_total", {{{{"where", "here"}}, 1}}}});

    CHECK_NOTHROW(parser.parse("   space_info { size = \" space is big \" } 23   \n"));
    CHECK_EQ(parser.d_prom, prom_t {{"space_info", {{{{"size", " space is big "}}, 23}}}});

    // We accept, but do not unescape, escaped characters like backslashes and double quotes
    CHECK_NOTHROW(parser.parse("escaped_labels_total{bs=\"\\\\\",q=\"\\\"\"} 1.0\n"));
    CHECK_EQ(parser.d_prom, prom_t {{"escaped_labels_total", {{{{"bs", "\\\\"}, {"q", "\\\""}}, 1}}}});
  }

  SUBCASE("Example") {
    const char *example = R"(
      # HELP apt_upgrades_pending Apt packages pending updates by origin.
      # TYPE apt_upgrades_pending gauge
      apt_upgrades_pending{arch="all",origin="Debian:bookworm-security/stable-security"} 2
      apt_upgrades_pending{arch="all",origin="Debian:bookworm/stable"} 4
      apt_upgrades_pending{arch="amd64",origin="Debian:bookworm-security/stable-security"} 8
      apt_upgrades_pending{arch="amd64",origin="Debian:bookworm/stable"} 24
    )";

    prom_t expected = {{"apt_upgrades_pending", {
      {{{"arch", "all"}, {"origin", "Debian:bookworm-security/stable-security"}}, 2},
      {{{"arch", "all"}, {"origin", "Debian:bookworm/stable"}}, 4},
      {{{"arch", "amd64"}, {"origin", "Debian:bookworm-security/stable-security"}}, 8},
      {{{"arch", "amd64"}, {"origin", "Debian:bookworm/stable"}}, 24}}}};

    CHECK_NOTHROW(parser.parse(example));
    CHECK_EQ(parser.d_prom, expected);
  }

  SUBCASE("Parse errors") {
    CHECK_THROWS(parser.parse("line_without_terminator"));
    CHECK_THROWS(parser.parse("value_is_garbage garbage\n"));
    CHECK_THROWS(parser.parse("ok_value_bad_timestamp 382 bogus\n"));
    CHECK_THROWS(parser.parse("bad!character!in!metric 48\n"));
    CHECK_THROWS(parser.parse("bad_character{in!label=\"\"} 62\n"));
    CHECK_THROWS(parser.parse("labels_empty{} 31\n"));
    CHECK_THROWS(parser.parse("labels_lots_commas{,,,,,,,} 31\n"));
    CHECK_THROWS(parser.parse("labels_missing_brace{foo=\"bar\" 51\n"));
  }
}