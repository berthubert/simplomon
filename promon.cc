#include "simplomon.hh"
#include "minicurl.hh"

using namespace std;

/*
# HELP apt_upgrades_pending Apt packages pending updates by origin.
# TYPE apt_upgrades_pending gauge
apt_upgrades_pending{arch="all",origin="Debian:bookworm-security/stable-security"} 2
apt_upgrades_pending{arch="all",origin="Debian:bookworm/stable"} 4
apt_upgrades_pending{arch="amd64",origin="Debian:bookworm-security/stable-security"} 8
apt_upgrades_pending{arch="amd64",origin="Debian:bookworm/stable"} 24

  ...
  node_filesystem_avail_bytes{device="/dev/nvme0n1p2",fstype="ext4",mountpoint="/"} 8.650682368e+10
*/

namespace {
struct PromLine
{
  std::string metric;
  map<string,string> sels;
  double value;
};
}

PrometheusParser::PrometheusParser()
{
  d_parser.set_logger([](size_t line, size_t col, const string& msg, const string &rule) {
    fmt::print("line {}, col {}: {}\n", line, col,msg, rule);
  });

  //   node_filesystem_avail_bytes{device="/dev/nvme0n1p2",fstype="ext4",mountpoint="/"} 8.650682368e+10
  //   xyz 3.14
  auto ok = d_parser.load_grammar(R"(
ROOT          <- ( ( ~COMMENTLINE / VLINE ) '\n')*
COMMENTLINE   <- '#' (!'\n' .)* 
VLINE         <- KWORD SELS? ' ' VALUE 
KWORD         <- [a-zA-Z0-9_]+ 
SELS          <- '{' KVPAIR (',' KVPAIR)* '}' 
KVPAIR        <-  KWORD '=' '"' KVAL '"' 
KVAL          <-  (!'"' .)*  
VALUE         <-  [0-9.+e-]+ 
)" );
  
  if(!ok)
    throw runtime_error("Failed to configure prometheus parser");

  d_parser["VALUE"] = [](const peg::SemanticValues &vs) {
    return atof(&vs.token()[0]);
  };

  d_parser["KVPAIR"] = [](const peg::SemanticValues &vs) {
    return std::make_pair(any_cast<string>(vs[0]), any_cast<string>(vs[1]));
  };

  d_parser["KWORD"] = [](const peg::SemanticValues &vs) {
    return vs.token_to_string();
  };

  d_parser["KVAL"] = [](const peg::SemanticValues &vs) {
    return vs.token_to_string();
  };

  d_parser["VLINE"] = [](const peg::SemanticValues &vs) {
    PromLine ret;
    ret.metric = any_cast<string>(vs[0]);
    if(vs.size() == 2) // no sels
      ret.value = any_cast<double>(vs[1]);
    else {
      ret.sels = any_cast<map<string,string>>(vs[1]);
      ret.value = any_cast<double>(vs[2]);
    }
    return ret;
  };

  d_parser["SELS"] = [](const peg::SemanticValues &vs) {
    map<string,string> sels;
    for(const auto& a : vs) {
      sels.insert(any_cast<pair<string,string>>(a));
    }
    return sels;
  };
  
  d_parser["ROOT"] = [](const peg::SemanticValues &vs) {
    vector<PromLine> ret;
    for(const auto& v : vs) {
      ret.push_back(any_cast<PromLine>(v));
    }
    return ret;
  };
  /*
  d_parser.set_logger([](size_t line, size_t col, const string& msg) {
    fmt::print("Error parsing col {}: {}\n", col, msg);
  });
  */
}

void PrometheusParser::parse(const std::string& cont)
{
  d_prom.clear();
  vector<PromLine> ret;
  if(!d_parser.parse(cont, ret))
    throw runtime_error("Unable to parse prometheus result");

  for(const auto& pl : ret) {
    d_prom[pl.metric][pl.sels] = pl.value;
  }
}

struct PromDiskFreeCheck : PromCheck
{
  PromDiskFreeCheck(sol::table data) 
  {
    checkLuaTable(data, {"kind"}, {"mountpoint", "gbMin"});
    d_mp = data.get_or("mountpoint", string("/"));
    d_gbMin = data.get_or("gbMin", 1);
  }

  void doCheck(CheckResult& cr, const PrometheusParser::prom_t& prom, const std::string& url, std::map<std::string, std::map<std::string, SQLiteWriter::var_t>>& results) override
  {
    auto iter = prom.find("node_filesystem_avail_bytes");
    if(iter == prom.end())
      return;
    
    // node_filesystem_avail_bytes
    for(const auto& ent : iter->second) {
      map<string, string> cop = ent.first;
      if(cop["mountpoint"] == d_mp) {
        double gbFree = ent.second/1000000000 ;
        results["gbDiskFree"][d_mp] = ent.second/1000000000.0;
        if(gbFree < d_gbMin)
          cr.d_reasons[d_mp].push_back(fmt::format("on {}, mountpoint had less than {} gb free: {:.0f} gb",
                                                   url, d_gbMin, gbFree));
      }
    }
  }
  
  string d_mp;
  int d_gbMin;
};

struct PromAptPendingCheck : PromCheck
{
  PromAptPendingCheck(sol::table data) 
  {
    checkLuaTable(data, {"kind"}, {"maxSec", "maxTot"});
    d_maxSec = data.get_or("maxSec", 0);
    d_maxTot = data.get_or("maxTot", -1);
  }

  void doCheck(CheckResult& cr, const PrometheusParser::prom_t& prom, const std::string& url, std::map<std::string, std::map<std::string, SQLiteWriter::var_t>>& results) override
  {
    auto iter = prom.find("apt_upgrades_pending");
    if(iter == prom.end())
      return;
    
    int totsecpend=0;
    int totpend=0;
    for(const auto& ent : iter->second) {
      map<string, string> cop = ent.first;
      
      if(cop["origin"].find("security") != string::npos) {
        totsecpend += ent.second;
      }
      totpend += ent.second;
    }
    results["aptPending"]["total"] = totpend;
    results["aptPending"]["security"] = totsecpend;

    if((d_maxSec>= 0 && totsecpend > d_maxSec) ||
       (d_maxTot>= 0 && totpend > d_maxTot))
      cr.d_reasons[""].push_back(fmt::format("There are {} pending security updates, out of {} total pending updates ({})",
                                             totsecpend, totpend, url));    
  }
  
  int d_maxSec, d_maxTot;
};

/*
node_network_receive_bytes_total{device="eno1"} 1.66779768142e+11
*/

struct PromBandwidthCheck : PromCheck
{
  PromBandwidthCheck(sol::table data) 
  {
    checkLuaTable(data, {"kind"}, {"maxMbit", "minMbit", "device", "direction"}  );
    d_maxMbit = data.get_or("maxMbit", -1.0);
    d_minMbit = data.get_or("minMbit", -1.0);
    d_device = data.get_or("device", string());
    d_direction = data.get_or("direction", string("both"));
    if(d_direction!= "in" && d_direction != "out" && d_direction != "both")
      throw std::runtime_error("Valid values for Bandwidth direction: in, out, both");
    if(d_minMbit < 0 && d_maxMbit < 0)
      throw std::runtime_error("Need to set a minum or a maximum bandwidth");
  }

  void doCheck(CheckResult& cr, const PrometheusParser::prom_t& prom, const std::string& url, std::map<std::string, std::map<std::string, SQLiteWriter::var_t>>& results) override
  {

    double bytes=0;
    vector<string> metrics;
    if(d_direction =="both" || d_direction=="out")
      metrics.push_back("node_network_transmit_bytes_total");
    if(d_direction =="both" || d_direction=="in")
      metrics.push_back("node_network_receive_bytes_total");
    
    for(const auto& m : metrics) {
      auto iter = prom.find(m);
      if(iter == prom.end())
        return;
            
      for(const auto& ent : iter->second) {
        map<string, string> cop = ent.first;
        if(d_device.empty() || cop["device"]==d_device)
          bytes += ent.second;
      }
    }
    string devstring = d_device.empty() ? string("") : fmt::format(" on dev {}", d_device);
    time_t now = time(nullptr);
    if(d_prevTime > 0) {

      double mbit = ((bytes - d_prevBytes)*8.0 / (now - d_prevTime))/1000000.0;
      results["Bandwidth "+d_direction+devstring]["Mbit"] = mbit;
      if(d_maxMbit > 0 && mbit > d_maxMbit)
        cr.d_reasons[""].push_back(fmt::format("From {}, bandwidth{} exceeded limit of {} Mbit/s (direction '{}')",
                                               url, devstring, d_maxMbit, d_direction));
      if(d_minMbit > 0 && mbit < d_minMbit)
        cr.d_reasons[""].push_back(fmt::format("From {}, bandwidth{} lower than limit of {} Mbit/s (direction '{}')",
                                               url, devstring, d_minMbit, d_direction));


    }
    d_prevBytes = bytes;
    d_prevTime = now;
  }
  
  int d_maxMbit=-1;
  int d_minMbit = -1;
  string d_device;
  time_t d_prevTime=-1;
  double d_prevBytes;
  string d_direction;
};


PrometheusChecker::PrometheusChecker(sol::table data) : Checker(data)
{
  checkLuaTable(data, {"url"}, {"checks"});
  d_url = data["url"];
  d_attributes["url"] = d_url;

  sol::optional<sol::table> checks = data["checks"];
  if(checks != sol::nullopt) {

    for(unsigned int n=0 ; n < checks->size(); ++n) {
      sol::table check = (*checks)[n+1];
      sol::optional<string> kind = check["kind"];
      if(kind == sol::nullopt) 
        throw std::runtime_error(fmt::format("A prometheus check needs a 'kind' field"));

      if(kind =="DiskFree")
        d_checkers.emplace_back(std::make_unique<PromDiskFreeCheck>(check));
      else if(kind =="AptPending")
        d_checkers.emplace_back(std::make_unique<PromAptPendingCheck>(check));
      else if(kind =="Bandwidth")
        d_checkers.emplace_back(std::make_unique<PromBandwidthCheck>(check));
      else
        throw std::runtime_error(fmt::format("Unknown prometheus check {}", *kind));         
    }
  }
}

CheckResult PrometheusChecker::perform()
{
  MiniCurl mc;
  string res = mc.getURL(d_url);

  d_parser.parse(res);
  d_results.clear();
  
  CheckResult cr;
  for(auto& c : d_checkers)
    c->doCheck(cr, d_parser.d_prom, d_url, d_results);
  
  return cr;
}
