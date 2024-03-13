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


#define PACKETSIZE	1024
namespace {
struct icmppacket
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
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

static std::string makeICMPQuery(int family, uint16_t id, uint16_t seq)
{
  if(family==AF_INET) {
    icmppacket p;
    memset(&p, 0, sizeof(p));
    p.hdr.type = ICMP_ECHO;
    p.hdr.un.echo.id = id;
    p.hdr.un.echo.sequence = seq;
    unsigned int i;
    for(i = 0; i < sizeof(p.msg)-1; i++ )
      p.msg[i] = i+'0';
    p.msg[i] = 0;
    
    
    p.hdr.checksum = 0;
    p.hdr.checksum = internetchecksum(&p, sizeof(p));
    return std::string((const char*)&p, sizeof(p));
  }
  else {
    /* compose ICMPv6 packet */
    struct icmp6_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.icmp6_type                      = ICMP6_ECHO_REQUEST;
    hdr.icmp6_code                      = 0;
    hdr.icmp6_dataun.icmp6_un_data16[0] = id; /* identifier */
    hdr.icmp6_dataun.icmp6_un_data16[1] = seq; /* sequence no */

    return std::string((const char*)&hdr, sizeof(hdr));
  }
}

static void parseICMPResponse(int family, const std::string& packet, uint16_t& id, uint16_t& seq, std::string& payload)
{
  if(family == AF_INET) {
    struct iphdr *ip = (iphdr*)packet.c_str();
    struct icmphdr* icmp = (struct icmphdr*) ((char*)packet.c_str() + ip->ihl*4);
    
    id = icmp->un.echo.id;
    seq = icmp->un.echo.sequence;

    payload = packet.substr(ip->ihl*4 + sizeof(icmp));
  }
  else {
    struct icmp6_hdr* hdr = (struct icmp6_hdr*) packet.c_str();
    id = hdr->icmp6_dataun.icmp6_un_data16[0];
    seq = hdr->icmp6_dataun.icmp6_un_data16[1];
  }
}

PINGChecker::PINGChecker(sol::table data) : Checker(data, 2)
{
  checkLuaTable(data, {"servers"});
  for(const auto& s: data.get<vector<string>>("servers")) {
    d_servers.insert(ComboAddress(s));
  }
}

CheckResult PINGChecker::perform()
{
  for(const auto& s : d_servers) {
    Socket sock(s.sin4.sin_family, SOCK_DGRAM, IPPROTO_ICMP);
    SConnect(sock, s);
    string packet = makeICMPQuery(s.sin4.sin_family, 1, 1);
    DTime dt;
    dt.start();
    SWrite(sock, packet);
    double timeo=1.0;
    if(!waitForData(sock, &timeo)) { // timeout
      return fmt::format("Timeout waiting for ping response from {}",
                         s.toString());
    }
    uint16_t id, seq;
    string payload;
    ComboAddress server=s;
    string resp = SRecvfrom(sock, 65535, server);
    parseICMPResponse(s.sin4.sin_family, resp, id, seq, payload);
    //    fmt::print("Got ping response from {} with id {} and seq {}: {} msec\n",
    //               s.toString(), id, seq, dt.lapUsec()/1000.0);
  }
  return "";
}
