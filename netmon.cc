#include "sclasses.hh"
#include <thread>
#include <signal.h>
#include "fmt/format.h"
#include "fmt/ranges.h"
#include "simplomon.hh"
#include "minicurl.hh"
#include "httplib.h"

using namespace std;


TCPPortClosedChecker::TCPPortClosedChecker(sol::table data) : Checker(data)
{
  checkLuaTable(data, {"servers", "ports"});
  for(const auto& s: data.get<vector<string>>("servers")) {
    d_servers.insert(ComboAddress(s));
  }
  for(int s: data.get<vector<int>>("ports")) {
    d_ports.insert(s);
  }
}


CheckResult TCPPortClosedChecker::perform()
{
  for(const auto& s : d_servers) {
    for(const auto& p : d_ports) {
      int ret=-1;
      ComboAddress rem=s;
      rem.setPort(p);

      try {
        Socket sock(s.sin4.sin_family, SOCK_STREAM);
        SetNonBlocking(sock);
        //fmt::print("Going to connect to {}\n", rem.toStringWithPort());
        ret = SConnectWithTimeout(sock, rem, 1);
      }
      catch(exception& e) {
        //        fmt::print("Could not connnect to TCP {}: {}\n",
        //           rem.toStringWithPort(), e.what());
        continue;
      }
      catch(...) {
        //fmt::print("Could not connnect to TCP {}\n",
        //         rem.toStringWithPort());

        continue;
      }
      if(ret >= 0) {
        return fmt::format("Was able to connect to TCP {} which should be closed", rem.toStringWithPort());
      }
    }
  }
  return "";
}

HTTPSChecker::HTTPSChecker(sol::table data) : Checker(data)
{
  checkLuaTable(data, {"url"}, {"maxAgeMinutes", "minBytes", "minCertDays", "serverIP", "method"});
  d_url = data.get<string>("url");
  d_maxAgeMinutes =data.get_or("maxAgeMinutes", 0);
  d_minCertDays =  data.get_or("minCertDays", 14);
  string serverip= data.get_or("serverIP", string(""));
  d_minBytes =     data.get_or("minBytes", 0);
  d_method =       data.get_or("method", string("GET"));

  if(!serverip.empty())
    d_serverIP = ComboAddress(serverip, 443);
  if (d_method != "GET" && d_method != "HEAD")
    throw runtime_error(fmt::format("only support HTTP HEAD & GET methods, not '{}'", d_method));
}

CheckResult HTTPSChecker::perform()

{
  string serverIP;
  if(d_serverIP.has_value())
    serverIP = fmt::format(" (server IP {})", d_serverIP->toString());
  
  try {
    MiniCurl mc;
    MiniCurl::certinfo_t certinfo;
    // XXX also do POST
    string body = mc.getURL(d_url, d_method == "HEAD", &certinfo,
                            d_serverIP.has_value() ? &*d_serverIP : 0);
    if(mc.d_http_code >= 400)
      return fmt::format("Content {} generated a {} status code{}", d_url, mc.d_http_code, serverIP);
    
    time_t now = time(nullptr);
    if(d_maxAgeMinutes > 0 && mc.d_filetime > 0)
      if(now - mc.d_filetime > d_maxAgeMinutes * 60)
        return fmt::format("Content {} older than the {} minutes limit{}", d_url, d_maxAgeMinutes, serverIP);
    
    if(certinfo.empty())  {
      return fmt::format("No certificates for '{}'{}", d_url,
                         serverIP);
    }
    
    if(body.size() < d_minBytes) {
      return fmt::format("URL {} was available{}, but did not deliver at least {} bytes of data", d_url, serverIP, d_minBytes);
    }
    
    //  fmt::print("{}\n", certinfo);
    
    time_t minexptime = std::numeric_limits<time_t>::max();
    
    for(auto& cert: certinfo) {
      /*    fmt::print("Cert {}, subject: {}, alternate: {}, start date: {}, expire date: {}, ", cert.first, cert.second["Subject"],
            cert.second["X509v3 Subject Alternative Name"],
            cert.second["Start date"], cert.second["Expire date"]);
      */
      struct tm tm={};
      // Jul 29 00:00:00 2023 GMT
      
      strptime(cert.second["Expire date"].c_str(), "%b %d %H:%M:%S %Y", &tm);
      time_t expire = mktime(&tm);
      strptime(cert.second["Start date"].c_str(), "%b %d %H:%M:%S %Y", &tm);
      time_t start = mktime(&tm);
      
      if(now < start) {
        return fmt::format("certificate for {} not yet valid{}",
                           d_url, serverIP);
      }
      //    fmt::print("days left: {:.1f}\n", (expire - now)/86400.0);
      minexptime = min(expire, minexptime);
    }
    double days = (minexptime - now)/86400.0;
    //  fmt::print("{}: first cert expires in {:.1f} days (lim {})\n", d_url, days,
    //             d_minCertDays);
    if(days < d_minCertDays) {
      return fmt::format("A certificate for '{}' expires in {:d} days{}",
                         d_url, (int)round(days), serverIP);
    }
    return "";
  }
  catch(exception& e) {
    return e.what() + serverIP;
  }
  return "";
}

HTTPRedirChecker::HTTPRedirChecker(sol::table data) : Checker(data)
{
  checkLuaTable(data, {"fromUrl", "toUrl"});
  
  string fromurl = data.get<string>("fromUrl");
  auto pos = fromurl.find("://");
  if(pos == string::npos)
    throw runtime_error(fmt::format("Need a protocol prefix, didn't find it in '{}'",
                                    fromurl));
  pos+=3;

  pos = fromurl.find("/", pos);
  d_frompath="/";
  if(pos == string::npos)
    d_fromhostpart = fromurl;
  else {
    d_fromhostpart = fromurl.substr(0, pos);
    d_frompath = fromurl.substr(pos+1);
  }
  
  d_tourl = data.get<string>("toUrl");
}

CheckResult HTTPRedirChecker::perform()
{
  httplib::Client cli(d_fromhostpart);
  auto res = cli.Get(d_frompath);
  if(!res)
    return fmt::format("Could not access path '{}' on server '{}' for redir check",
                       d_frompath, d_fromhostpart);
  if(res->status / 100 != 3)
    return fmt::format("Wrong status for redirect check of path '{}' on server '{}'",
                       d_frompath, d_fromhostpart);
  string dest = res->get_header_value("Location");
  if(dest != d_tourl)
    return fmt::format("HTTP redirection check from '{}{}' to '{}' failed, got '{}'",
                       d_fromhostpart, d_frompath, d_tourl, dest);

  //  fmt::print("Was all cool, HTTP redirection check from '{}{}' to '{}' got '{}'\n",
  //         d_fromhostpart, d_frompath, d_tourl, dest);
  return "";
}
