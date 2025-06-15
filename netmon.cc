#include "sclasses.hh"
#include <thread>
#include <signal.h>
#include "fmt/format.h"
#include "fmt/ranges.h"
#include "simplomon.hh"
#include "minicurl.hh"
#include "httplib.h"
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "support.hh"

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
  CheckResult cr;
  
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
        cr.d_reasons[rem.toStringWithPort()].push_back(fmt::format("Was able to connect to TCP {} which should be closed", rem.toStringWithPort()));
      }
    }
  }
  return cr;
}

TCPPortOpenChecker::TCPPortOpenChecker(sol::table data) : Checker(data)
{
  checkLuaTable(data, {"servers", "ports"});
  for(const auto& s: data.get<vector<string>>("servers")) {
    d_servers.insert(ComboAddress(s));
  }
  for(int s: data.get<vector<int>>("ports")) {
    d_ports.insert(s);
  }
}


CheckResult TCPPortOpenChecker::perform()
{
  CheckResult cr;
  
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
	cr.d_reasons[rem.toStringWithPort()].push_back(fmt::format("Unable to connect to TCP {}: {}",
								   rem.toStringWithPort(), e.what()));

        continue;
      }
      catch(...) {
	cr.d_reasons[rem.toStringWithPort()].push_back(fmt::format("Unable to connect to TCP {}",
								   rem.toStringWithPort()));

        continue;
      }
      if(ret < 0) {
        cr.d_reasons[rem.toStringWithPort()].push_back(fmt::format("Unable ot connect to TCP {}: ", rem.toStringWithPort(),
								   strerror(errno)));
      }
    }
  }
  return cr;
}


// XXX needs switch to select IPv4 or IPv6 or happy eyeballs?
HTTPSChecker::HTTPSChecker(sol::table data) : Checker(data)
{
  checkLuaTable(data, {"url"}, {"maxAgeMinutes", "minBytes", "minCertDays", "serverIP", "method", "localIP4", "localIP6", "dns", "regex"});
  d_url = data.get<string>("url");
  d_maxAgeMinutes =data.get_or("maxAgeMinutes", 0);
  d_minCertDays =  data.get_or("minCertDays", 14);
  string serverip= data.get_or("serverIP", string(""));
  string localip4= data.get_or("localIP4", string(""));
  string localip6= data.get_or("localIP6", string(""));
  
  d_minBytes =     data.get_or("minBytes", 0);
  d_method =       data.get_or("method", string("GET"));
  vector<string> dns = data.get_or("dns", vector<string>());
  d_regexStr =     data.get_or("regex", string(""));

  d_attributes["url"] = d_url;
  d_attributes["method"] = d_method;

  if(!serverip.empty()) {
    d_serverIP = ComboAddress(serverip, 443);
    d_attributes["serverIP"] = d_serverIP->toStringWithPort();
  }
  
  if(!localip4.empty()) {
    d_localIP4 = ComboAddress(localip4);
    d_attributes["localIP4"] = d_localIP4->toString();
  }

  if(!localip6.empty()) {
    d_localIP6 = ComboAddress(localip6);
    d_attributes["localIP6"] = d_localIP6->toString();
  }

  
  if(!dns.empty()) {
    for(const auto& d : dns)
      d_dns.push_back(ComboAddress(d, 53));
    d_attributes["dns"] = fmt::format("{}", dns);
  }
  
  if (d_method != "GET" && d_method != "HEAD")
    throw runtime_error(fmt::format("only support HTTP HEAD & GET methods, not '{}'", d_method));
  if(!d_regexStr.empty())
    d_attributes["regex"] = d_regexStr;
  d_regex = std::regex(d_regexStr);
}

double roundDec(double val, int dec)
{
  double fact = pow(10, dec);
  return ((int)(fact*val))/fact;
}

/*
An issue here is what certificates we actually check for expiry, we need the *whole* chain,
from http://blah to https://www.blah/ 
*/
CheckResult HTTPSChecker::perform()
{
  d_results.clear();
  string serverIP;
  ComboAddress activeServerIP4, activeServerIP6;
  activeServerIP4.sin4.sin_family = 0; // "unset"
  activeServerIP6.sin4.sin_family = 0; // "unset"
  double dnsMsec4 = 0, dnsMsec6 = 0;

  DNSName qname = makeDNSName(extractHostFromURL(d_url));
  
  vector<ComboAddress> aaaas;
  if(*g_haveIPv6) {
    aaaas=DNSResolveAt(qname, DNSType::AAAA, getResolvers());
    if(!aaaas.empty()) {
      vector<string> as;
      for(const auto& a : aaaas)
        as.push_back(a.toString());
      //      fmt::print("{} host has AAAA records {}\n", d_url, as);
    }
    else
      ; // fmt::print("{} host does NOT have AAAA records\n", d_url);
  }
  
  if(d_serverIP.has_value()) {
    serverIP = fmt::format(" (server IP {})", d_serverIP->toString());
    activeServerIP4 = *d_serverIP;
    activeServerIP6 = *d_serverIP;
  }
  else if(!d_dns.empty()) {
    vector<string> tofmt;
    for(const auto& d : d_dns)
      tofmt.push_back(d.toString());

    //    fmt::print("Going to do DNS lookup for {} over at {} using source {}\n",
    //               qname.toString(), tofmt, d_localIP.has_value() ? d_localIP->toString() : "default");
    DTime dt;
    std::vector<ComboAddress> r= DNSResolveAt(qname, DNSType::A, d_dns, d_localIP4, d_localIP6); 
    activeServerIP4 = r.at(0);
    d_results["ipv4"]["server-ip"] = activeServerIP4.toString();
    dnsMsec4 = dt.lapUsec() / 1000.0;
    d_results["ipv4"]["dns-msec"] = roundDec(dnsMsec4, 1);

    serverIP = fmt::format(" (server IPv4 {} from DNS {})", activeServerIP4.toString(), tofmt);

    r= DNSResolveAt(qname, DNSType::AAAA, d_dns, d_localIP4, d_localIP6); 
    activeServerIP6 = r.at(0);
    d_results["ipv6"]["server-ip"] = activeServerIP6.toString();
    dnsMsec6 = dt.lapUsec() / 1000.0;
    d_results["ipv6"]["dns-msec"] = roundDec(dnsMsec6, 1);

    serverIP += fmt::format(" (server IPv6 {} from DNS {})", activeServerIP6.toString(), tofmt);
    
    //    fmt::print("Got: {}\n", serverIP);
  }
  
  if(d_localIP4.has_value()) {
    serverIP += fmt::format(" (local IPv4 {})", d_localIP4->toString());
  }
  if(d_localIP6.has_value()) {
    serverIP += fmt::format(" (local IPv6 {})", d_localIP6->toString());
  }

  CheckResult cr;
  auto doCheck = [&](bool ipv6) {
    DTime dt;
    dt.start();
    MiniCurl mc(d_agent); 
    MiniCurl::certinfo_t certinfo;
    // XXX also do POST
    ComboAddress activeServerIP = ipv6 ? activeServerIP6 : activeServerIP4;

    // if you hand picked an activeServerIP, we're only going to test the right family
    if(!ipv6 && activeServerIP.sin4.sin_family && activeServerIP.sin4.sin_family != AF_INET)
      return;
    if(ipv6 && activeServerIP.sin4.sin_family && activeServerIP.sin4.sin_family != AF_INET6)
      return;
    
    
    string subject = ipv6 ? "ipv6" : "ipv4";
    try {
      ComboAddress li;
      if(!ipv6) {
        if(d_localIP4) li = *d_localIP4;
        else li = ComboAddress("0.0.0.0",0);
      }
      else { // ipv6
        if(d_localIP6) li = *d_localIP6;
        else li = ComboAddress("::",0);
      }
      
      string body = mc.getURL(d_url, d_method == "HEAD", &certinfo,
                              activeServerIP.sin4.sin_family ? &activeServerIP : 0,
                              &li);
      
      
      double httpMsec = dt.lapUsec()/1000.0;
      d_results[subject]["http-msec"]= roundDec(httpMsec, 1);
      d_results[subject]["msec"] = roundDec((ipv6 ? dnsMsec6 : dnsMsec4) + httpMsec, 1);
      d_results[subject]["http-code"] = (int32_t)mc.d_http_code;
      
      if(mc.d_http_code >= 400) {
        cr.d_reasons[subject].push_back(fmt::format("Content {} generated a {} status code{}", d_url, mc.d_http_code, serverIP));
        return;
      }
      
      time_t now = time(nullptr);
      if(d_maxAgeMinutes > 0 && mc.d_filetime > 0) {
        if(now - mc.d_filetime > d_maxAgeMinutes * 60) {
          cr.d_reasons[subject].push_back(fmt::format("Content {} older than the {} minutes limit{}", d_url, d_maxAgeMinutes, serverIP));
          return;
        }
      }
      
      if(certinfo.empty())  {
        cr.d_reasons[subject].push_back(fmt::format("No certificates for '{}'{}", d_url, serverIP));
        return;
      }
      d_results[subject]["bodySize"] = (int64_t)body.size();
      if(body.size() < d_minBytes) {
        cr.d_reasons[subject].push_back(fmt::format("URL {} was available{}, but did not deliver at least {} bytes of data", d_url, serverIP, d_minBytes));
        return;
      }
      
      if(!d_regexStr.empty() && !std::regex_search(body, d_regex)) {
        cr.d_reasons[subject].push_back(fmt::format("URL {} was available{}, but the response did not contain a match for the regular expression '{}'", d_url, serverIP, d_regexStr));
        return;
      }
      
      time_t minexptime = std::numeric_limits<time_t>::max();
      
      for(auto& cert: certinfo) {
        struct tm tm={};
        // Jul 29 00:00:00 2023 GMT
        
        strptime(cert.second["Expire date"].c_str(), "%b %d %H:%M:%S %Y", &tm);
        time_t expire = mktime(&tm);
        strptime(cert.second["Start date"].c_str(), "%b %d %H:%M:%S %Y", &tm);
        time_t start = mktime(&tm);
        
        if(now < start) {
          cr.d_reasons[subject].push_back(fmt::format("certificate for {} not yet valid{}",
                                                      d_url, serverIP));
          return;
        }
        //    fmt::print("days left: {:.1f}\n", (expire - now)/86400.0);
        minexptime = min(expire, minexptime);
      }
      double days = (minexptime - now)/86400.0;
      d_results[subject]["tlsMinExpDays"] = roundDec(days, 1);
      //  fmt::print("'{}': first cert expires in {:.1f} days (lim {})\n", d_url, days,
      //             d_minCertDays);
      if(days < d_minCertDays) {
        cr.d_reasons[subject].push_back(fmt::format("A certificate for '{}' expires in {:d} days{}",
                                                    d_url, (int)round(days), serverIP));
        return;
      }
    }
    catch(exception& e) {
      cr.d_reasons[subject].push_back(e.what() + serverIP);
    }
    
  };

  doCheck(false);
  if(!aaaas.empty())
    doCheck(true);
  return cr;
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
  cli.set_connection_timeout(10);
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


namespace {
struct icmppacket
{
	struct icmphdr hdr;
	char msg[];
};
}
/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
static unsigned short internetchecksum(void *b, int len)
{	unsigned short *buf = (unsigned short*)b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

static std::string makeICMPQuery(int family, uint16_t id, uint16_t seq, size_t psize)
{
  if(family==AF_INET) {
    size_t full_size = sizeof(icmphdr) + psize;
    vector<char> store(full_size, 0);
    icmppacket *p = (icmppacket *)store.data();

    p->hdr.type = ICMP_ECHO;
    p->hdr.un.echo.id = id;
    p->hdr.un.echo.sequence = seq;
    unsigned int i;
    for(i = 0; i < psize; i++) {
      p->msg[i] = (char)i;
    }

    p->hdr.checksum = 0;
    p->hdr.checksum = internetchecksum(p, full_size);
    return std::string((const char*)p, full_size);
  }
  else {
    /* compose ICMPv6 packet */
    size_t full_size = sizeof(struct icmp6_hdr) + psize;
    vector<char> store(full_size, 0);
    void *packet = store.data();
    struct icmp6_hdr *hdr = (struct icmp6_hdr *)packet;

    hdr->icmp6_type                      = ICMP6_ECHO_REQUEST;
    hdr->icmp6_code                      = 0;
    hdr->icmp6_dataun.icmp6_un_data16[0] = id; /* identifier */
    hdr->icmp6_dataun.icmp6_un_data16[1] = seq; /* sequence no */

    /* fill the rest of the packet */
    unsigned char *data = (unsigned char *)(hdr + 1);
    for (size_t i = 0; i < psize; i++)
      data[i] = i;

    return std::string((const char*)hdr, full_size);
  }
}


static void fillMSGHdr(struct msghdr* msgh, struct iovec* iov, char* cbuf, int buflen, char* data, size_t datalen, ComboAddress* addr)
{
  iov->iov_base = data;
  iov->iov_len  = datalen;

  memset(msgh, 0, sizeof(struct msghdr));
  
  msgh->msg_control = cbuf;
  msgh->msg_controllen = buflen;
  msgh->msg_name = addr;
  msgh->msg_namelen = addr->getSocklen();
  msgh->msg_iov  = iov;
  msgh->msg_iovlen = 1;
  msgh->msg_flags = 0;
}


/*
recvmsg(3, 
{msg_name={sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("1.1.1.1")}, msg_namelen=128 => 16, msg_iov=[{iov_base="\0\0\345\\\1\t\0\1J\31\366e\0\0\0\0\26G\4\0\0\0\0\0\20\21\22\23\24\25\26\27"..., iov_len=192}], msg_iovlen=1, 
msg_control=[
{cmsg_len=32, cmsg_level=SOL_SOCKET, cmsg_type=SO_TIMESTAMP_OLD, cmsg_data={tv_sec=1710627146, tv_usec=285083}}, 
{cmsg_len=20, cmsg_level=SOL_IP, cmsg_type=IP_TTL, cmsg_data=[59]}], 
msg_controllen=56, msg_flags=0}, 0) = 64
*/

bool HarvestTTL(struct msghdr* msgh, int* ttl) 
{
  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(msgh); cmsg != NULL; cmsg = CMSG_NXTHDR(msgh,cmsg)) {
    if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == IP_TTL) && 
        CMSG_LEN(sizeof(*ttl)) == cmsg->cmsg_len) {
      memcpy(ttl, CMSG_DATA(cmsg), sizeof(*ttl));
      return true;
    }
  }
  return false;
}


PINGChecker::PINGChecker(sol::table data) : Checker(data, 2)
{
  checkLuaTable(data, {"servers"}, {"localIP", "timeout", "size", "df"});
  for(const auto& s: data.get<vector<string>>("servers")) {
    d_servers.insert(ComboAddress(s));
  }
  string localip= data.get_or("localIP", string(""));
  if(!localip.empty()) {
    d_localIP = ComboAddress(localip);
    d_attributes["localIP"] = d_localIP->toString();
  }

  d_timeout = data.get_or("timeout", 1.0);
  if (d_timeout <= 0 || d_timeout > 10)
    throw runtime_error("ping timeout must be reasonable, between 0 and 10 seconds");

  /* Size of payload, except IP/ICMP header, 1016 to imitate previous default */
  d_size = data.get_or("size", 1016);
  if(d_size < 0 || d_size > 65500)
    throw runtime_error("ping size must be between 0 and 65500");

  /* Based on observation, old default was DF is set */
  d_dontFragment = data.get_or("df", true);

  try {
    Socket sock(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  }
  catch(...) {
    throw std::runtime_error("Not allowed to send ping packets, you may need to do: sysctl net.ipv4.ping_group_range='0 2147483647'");
  }
}

CheckResult PINGChecker::perform()
{
  d_results.clear();
  CheckResult ret;
  for(const auto& s : d_servers) {
    Socket sock(s.sin4.sin_family, SOCK_DGRAM, (s.sin4.sin_family == AF_INET) ? (int)IPPROTO_ICMP : (int)IPPROTO_ICMPV6);
    if(d_localIP) {
      SBind(sock, *d_localIP);
    }

    SConnect(sock, s);
    SSetsockopt(sock, SOL_IP, IP_RECVTTL, 1);

    if (s.sin4.sin_family == AF_INET) {
      if (d_dontFragment) {
        SSetsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO);
      } else {
        SSetsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT);
      }
    }

    string packet = makeICMPQuery(s.sin4.sin_family, 1, 1, d_size);
    DTime dt;
    dt.start();
    SWrite(sock, packet);

    double timeo = d_timeout;
    if(!waitForData(sock, &timeo)) {
      ret.d_reasons[s.toStringWithPort()].push_back(fmt::format("Timeout waiting for ping response from {}",
                                        s.toString()));
      continue;
    }
    string payload;
    ComboAddress server=s;

    struct msghdr msgh;
    struct iovec iov;
    char cbuf[256];
    
    char respbuf[1500];
    fillMSGHdr(&msgh, &iov, cbuf, sizeof(cbuf), respbuf, sizeof(respbuf), &server);
    
    int len = recvmsg(sock, &msgh, 0);
    if(len < 0) {
      ret.d_reasons[s.toStringWithPort()].push_back("Receiving ping response from "+s.toString()+": " + string(strerror(errno)));
      continue;
    }
    int ttl = -1;
    HarvestTTL(&msgh, &ttl);

    d_results[s.toString()]["msec"] = roundDec(dt.lapUsec()/1000.0, 1 );
    d_results[s.toString()]["ttl"] = ttl;
    //    fmt::print("Got ping response from {} with id {} and seq {}: {} msec\n",
    //               s.toString(), id, seq, dt.lapUsec()/1000.0);
  }
  return ret;
}


// Based on: https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
std::pair<int, std::string> exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    int rc;
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return std::pair<int, std::string> (255, "");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    rc = pclose(pipe) / 256;
    std::pair<int, std::string> ret(rc, result);
    return ret;
}

ExternalChecker::ExternalChecker(sol::table data) : Checker(data)
{
  checkLuaTable(data, {"cmd"}, {"regex", "rc"});
  
  d_cmd = data.get<string>("cmd");
  d_exp = data.get_or<string>("regex", "");
  d_rc = data.get_or("rc", -1);
}

CheckResult ExternalChecker::perform()
{
  std::pair<int, std::string> output = exec(d_cmd.c_str());

  d_results.clear();
  d_results[d_cmd]["rc"] = output.first;
  d_results[d_cmd]["output"] = output.second;

  if (d_exp != "") {
    if (!std::regex_search(output.second, std::regex(d_exp))) {
      return fmt::format("External check \"{}\" against \"{}\" failed, actual output: \"{}\"", d_cmd, d_exp, output.second);
    }
  }
  if (d_rc != -1) {
    if (output.first != d_rc) {
      return fmt::format("External check \"{}\" expected rc \"{}\", received: \"{}\"", d_cmd, d_rc, output.first);
    }
  }
  return "";
}
