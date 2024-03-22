#include "record-types.hh"
#include "sclasses.hh"
#include <thread>
#include <signal.h>
#include "fmt/format.h"
#include "fmt/ranges.h"
#include "fmt/chrono.h"
#include "simplomon.hh"
#include "support.hh"
#include <fstream>

using namespace std;

static DNSMessageReader sendQuery(const vector<ComboAddress>& resolvers, DNSName dn, DNSType dt, std::optional<ComboAddress> local = std::optional<ComboAddress>())
{
  DNSMessageWriter dmw(dn, dt);
  
  dmw.dh.rd = true;
  dmw.randomizeID();
  dmw.setEDNS(4000, false);
  for(int n=0; n < 3; ++n) {
    for(const auto& server: resolvers) {
      try {
	Socket sock(server.sin4.sin_family, SOCK_DGRAM);
        if(local) {
          local->setPort(0);
          SBind(sock, *local);
        }
	SetNonBlocking(sock, true);
	SConnect(sock, server);
	SWrite(sock, dmw.serialize());
	double timeout=1.5;
	if(!waitForData(sock, &timeout)) {
	  cout<<"Timeout asking "<<server.toString()<<" for "<<dn<<" "<<dt<<", trying again"<<endl;
	  continue;
	}
	
	ComboAddress rem=server;
	string resp = SRecvfrom(sock, 65535, rem);
	// these will be identical because of the connect above
	DNSMessageReader dmr(resp);
	if((RCode)dmr.dh.rcode != RCode::Noerror && (RCode)dmr.dh.rcode != RCode::Nxdomain ) {
          //	  cout<<"Server gave us an inconclusive RCode ("<<(RCode)dmr.dh.rcode<<"), ignoring this response"<<endl;
	  continue;
	}
	
	if(dmr.dh.tc) {
          throw std::runtime_error(fmt::format("Needed to do TCP DNS for {}|{} which we can't",
                                               dn.toString(), toString(dt))
                                   );
	  // shit
	}
	else
	  return dmr;
      }
      catch(...){} 
    }
  }
  throw std::runtime_error(fmt::format("No DNS server could be reached or responded trying to resolve '{}|{}'",
                                       dn.toString(), toString(dt))
                                       );
}

vector<ComboAddress> getResolvers()
{
  ifstream ifs("/etc/resolv.conf");
  
  if(!ifs) 
    return {ComboAddress("127.0.0.1", 53)};
            
  string line;
  vector<ComboAddress> ret;
  while(std::getline(ifs, line)) {
    auto pos = line.find_last_not_of(" \r\n\x1a");
    if(pos != string::npos)
      line.resize(pos+1);
    pos = line.find_first_not_of(" \t");
    if(pos != string::npos)
      line = line.substr(pos);
    
    pos = line.find_first_of(";#");
    if(pos != string::npos)
      line.resize(pos);
    
    if(line.rfind("nameserver ", 0)==0 || line.rfind("nameserver\t", 0) == 0) {
      pos = line.find_first_not_of(" ", 11);
      if(pos != string::npos) {
        try {
          ret.push_back(ComboAddress(line.substr(pos), 53));
        }
        catch(...)
          {}
      }
    }
  }
  return ret;
}


std::vector<ComboAddress> DNSResolveAt(const DNSName& name, const DNSType& type,
                                       const std::vector<ComboAddress>& servers,
                                       std::optional<ComboAddress> local)
{
  DNSMessageReader dmr = sendQuery(servers, name, type, local);
  DNSName dn;
  DNSType dt;
  dmr.getQuestion(dn, dt);
  vector<ComboAddress> ret;  
  std::unique_ptr<RRGen> rr;
  DNSSection rrsection;
  uint32_t ttl;
  while(dmr.getRR(rrsection, dn, dt, ttl, rr)) {
    if(rrsection == DNSSection::Answer && dt == type) {
      if(type == DNSType::A)
        ret.push_back(dynamic_cast<AGen*>(rr.get())->getIP());
      else if(type == DNSType::AAAA)
        ret.push_back(dynamic_cast<AAAAGen*>(rr.get())->getIP());
    }
  }
  return ret;
}

bool checkForWorkingIPv6()
try
{
  DNSMessageWriter dmw(makeDNSName("."), DNSType::SOA);
  
  dmw.dh.rd = true;
  dmw.randomizeID();
  dmw.setEDNS(4000, false);

  Socket sock(AF_INET6, SOCK_DGRAM);
  SetNonBlocking(sock, true);
  vector<ComboAddress> roots;
  for(const auto& str : {"2001:503:ba3e::2:30", "2801:1b8:10::b", "2001:500:2::c", "2001:500:2d::d", "2001:500:a8::e",
                         "2001:500:2f::f", "2001:500:12::d0d"})
    roots.emplace_back(str, 53);


  for(auto& r : roots) {
    SSendto(sock, dmw.serialize(), r);
  }
  double timeout=1.5;
  if(!waitForData(sock, &timeout)) {
    return false;
  }
  ComboAddress rem=*roots.begin();
  string resp = SRecvfrom(sock, 65535, rem);

  // these will be identical because of the connect above
  DNSMessageReader dmr(resp);
  std::unique_ptr<RRGen> rr;
  DNSName dn;
  DNSType dt;
  DNSSection rrsection;
  uint32_t ttl;
  while(dmr.getRR(rrsection, dn, dt, ttl, rr)) {
    if(rrsection == DNSSection::Answer && dt == DNSType::SOA) {
      fmt::print("Got answer from {}, SOA serial for root: {}\n",
                 rem.toString(),
                 dynamic_cast<SOAGen*>(rr.get())->d_serial);
    }
  }

  // apparently we got a response
  return true;
}
catch(...) {
  return false;
}


DNSChecker::DNSChecker(sol::table data) : Checker(data, 2)
{
  checkLuaTable(data, {"server", "name", "type"}, {"rd", "acceptable", "localIP"});
  d_nsip = ComboAddress(data.get<string>("server"), 53);
  d_qname = makeDNSName(data.get<string>("name"));
  d_qtype = makeDNSType(data.get<string>("type").c_str());
  for(const auto& a : data.get_or("acceptable", vector<string>()))
    d_acceptable.insert(a);
  d_rd = data.get_or("rd", true);
  string localip= data.get_or("localIP", string(""));
  if(!localip.empty()) {
    d_localIP = ComboAddress(localip, 0);
    d_attributes["localIP"] = d_localIP->toString();
  }

  d_attributes["server"] = d_nsip.toStringWithPort();
  d_attributes["name"] = d_qname.toString();
  d_attributes["type"] = toString(d_qtype);
  d_attributes["rd"] = d_rd;
}

CheckResult DNSChecker::perform()
{
  DNSMessageWriter dmw(d_qname, d_qtype);
          
  dmw.dh.rd = true;
  dmw.randomizeID();
  dmw.setEDNS(4000, false);
  
  Socket sock(d_nsip.sin4.sin_family, SOCK_DGRAM);
  if(d_localIP) {
    SBind(sock, *d_localIP);
  }

  SConnect(sock, d_nsip);

  d_results.clear();
  DTime dti; 
  SWrite(sock, dmw.serialize());

  ComboAddress server;

  double timeo=0.5;
  if(!waitForData(sock, &timeo)) { // timeout
    return fmt::format("Timeout asking DNS question for {}|{} to {}",
                          d_qname.toString(), toString(d_qtype), d_nsip.toStringWithPort());
  }
    
  
  string resp = SRecvfrom(sock, 65535, server);
  d_results[""]["msec"] = dti.lapUsec() / 1000.0;
  DNSMessageReader dmr(resp);
  
  DNSSection rrsection;
  uint32_t ttl;

  DNSName dn;
  DNSType dt;
  dmr.getQuestion(dn, dt);
  
  //  cout<<"Received "<<resp.size()<<" byte response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<dn<<", qtype "<<dt<<endl;

  if((RCode)dmr.dh.rcode != RCode::Noerror) {
    return fmt::format("Got DNS response with RCode {} from {} for question {}|{}",
                       toString((RCode)dmr.dh.rcode), d_qname.toString(), d_nsip.toStringWithPort(), toString(d_qtype));
  }
  
  std::unique_ptr<RRGen> rr;

  int matches = 0;
  vector<string> finals;
  while(dmr.getRR(rrsection, dn, dt, ttl, rr)) {
    if(rrsection == DNSSection::Answer && dt == d_qtype) {
      //  cout << rrsection<<" "<<dn<< " IN " << dt << " " << ttl << " " <<rr->toString()<<endl;
      finals.push_back(dn.toString()+" "+rr->toString());
      if(d_acceptable.empty())
        matches++;
      else {
        if(dt == DNSType::NS) {
          set<DNSName> acc;
          for(const auto& a : d_acceptable)
            acc.insert(makeDNSName(a));
          if(!acc.count(dynamic_cast<NSGen*>(rr.get())->d_name)) {
            return fmt::format("Unacceptable DNS answer {} for question {} from {}. Acceptable: {}", rr->toString(), d_qname.toString(), d_nsip.toStringWithPort(), d_acceptable);
          }
          else matches++;
        }
        else if(!d_acceptable.count(rr->toString())) {
          return fmt::format("Unacceptable DNS answer {} for question {} from {}. Acceptable: {}", rr->toString(), d_qname.toString(), d_nsip.toStringWithPort(), d_acceptable);
        }
        else matches++;
      }
    }
  }

  d_results[""]["finals"] = fmt::format("{}", finals);
  
  if(matches) {
    return "";
  }
  else {
    return fmt::format("No matching answer to question {}|{} to {} was received", d_qname.toString(), toString(d_qtype), d_nsip.toStringWithPort());
  }
  
}


DNSSOAChecker::DNSSOAChecker(sol::table data) : Checker(data, 2)
{
  checkLuaTable(data, {"domain", "servers"});
  d_domain = makeDNSName(data.get<string>("domain"));
  auto serv = data.get<vector<string>>("servers");
  for(const auto& s: serv)
    d_servers.insert(ComboAddress(s, 53));
}



CheckResult DNSSOAChecker::perform()
{
  set<string> harvest;
  for(const auto& s: d_servers) {
    DNSMessageWriter dmw(d_domain, DNSType::SOA);
    
    dmw.dh.rd = false;
    dmw.randomizeID();
    dmw.setEDNS(4000, false);
    
    Socket sock(s.sin4.sin_family, SOCK_DGRAM);
    SConnect(sock, s);
    
    SWrite(sock, dmw.serialize());

    ComboAddress server;

    double timeo=0.5;
    if(!waitForData(sock, &timeo)) { // timeout
      return fmt::format("Timeout asking DNS question for {}|{} to {}",
                            d_domain.toString(), toString(DNSType::SOA), s.toStringWithPort());
    }
    string resp = SRecvfrom(sock, 65535, server);
    
    DNSMessageReader dmr(resp);
    
    DNSSection rrsection;
    uint32_t ttl;
    
    DNSName dn;
    DNSType dt;
    dmr.getQuestion(dn, dt);
    
    //    cout<<"Received "<<resp.size()<<" byte response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<dn<<", qtype "<<dt<<endl;
    
    if((RCode)dmr.dh.rcode != RCode::Noerror) {
      return fmt::format("Got DNS response with RCode {} for question {}|{}",
                            toString((RCode)dmr.dh.rcode), d_domain.toString(), toString(DNSType::SOA));
    }
  
    std::unique_ptr<RRGen> rr;

    int matches = 0;
    while(dmr.getRR(rrsection, dn, dt, ttl, rr)) {
      if(dn == d_domain && rrsection == DNSSection::Answer && dt == DNSType::SOA) {
        harvest.insert(rr->toString());
        matches++;
      }
    }
    if(!matches) {
      return fmt::format("DNS server {} did not return a SOA for {}",
                            s.toStringWithPort(), d_domain.toString());
    }
  }
  if(harvest.size() != 1) {
    return fmt::format("Had different SOA records for {}: {}",
                       d_domain.toString(), harvest);
  }
  else {
    return "";
  }  
}

// minimum of 2 failures
RRSIGChecker::RRSIGChecker(sol::table data) : Checker(data, 2)
{
  checkLuaTable(data, {"server", "name"}, {"minDays", "type"});
  d_nsip = ComboAddress(data.get<string>("server"), 53);
  d_qname = makeDNSName(data.get<string>("name"));
  d_qtype = makeDNSType(data.get_or("type", string("SOA")).c_str());
  d_minDays = data.get_or("minDays", 7);

  d_attributes["server"] = d_nsip.toStringWithPort();
  d_attributes["name"] = d_qname.toString();
  d_attributes["type"] = toString(d_qtype);

}

CheckResult RRSIGChecker::perform()
{
  DNSMessageWriter dmw(d_qname, d_qtype);
          
  dmw.dh.rd = false;
  dmw.randomizeID();
  dmw.setEDNS(4000, true);
  
  Socket sock(d_nsip.sin4.sin_family, SOCK_DGRAM);
  SConnect(sock, d_nsip);

  SWrite(sock, dmw.serialize());

  ComboAddress server;

  double timeo=1.0;
  if(!waitForData(sock, &timeo)) { // timeout
    return fmt::format("Timeout asking DNS question for {}|{} to {}",
                       d_qname.toString(), toString(d_qtype), d_nsip.toStringWithPort());
  }
    
  
  string resp = SRecvfrom(sock, 65535, server);
  
  DNSMessageReader dmr(resp);
  DNSSection rrsection;
  uint32_t ttl;

  DNSName dn;
  DNSType dt;
  dmr.getQuestion(dn, dt);
  
  if((RCode)dmr.dh.rcode != RCode::Noerror) {
    return fmt::format("Got DNS response with RCode {} from {} for question {}|{}",
                       toString((RCode)dmr.dh.rcode), d_qname.toString(), d_nsip.toStringWithPort(), toString(d_qtype));
  }
  
  std::unique_ptr<RRGen> rr;
  bool valid=false;
  while(dmr.getRR(rrsection, dn, dt, ttl, rr)) {
    if(rrsection == DNSSection::Answer && dt == DNSType::RRSIG && dn == d_qname) {
      auto rrsig = dynamic_cast<RRSIGGen*>(rr.get());
      if(rrsig->d_type != d_qtype) {
        fmt::print("Skipping wrong type {}\n", toString(rrsig->d_type));
        continue;
      }
      struct tm tmstart={}, tmend={};
      time_t inception = rrsig->d_inception;
      time_t expire = rrsig->d_expire;
      gmtime_r(&inception, &tmstart);
      gmtime_r(&expire, &tmend);

      //      fmt::print("Got active RRSIG for {}|{} from {:%Y-%m-%d %H:%M} to {:%Y-%m-%d %H:%M} UTC\n", d_qname.toString(), toString(d_qtype), tmstart, tmend);

      time_t now = time(nullptr);
      if(now + d_minDays * 86400 > expire)
        return fmt::format("Got RRSIG that expires in {:.0f} days for {}|{} from {}, valid from {:%Y-%m-%d %H:%M} to {:%Y-%m-%d %H:%M} UTC",
                           (expire - now)/86400.0,
                           d_qname.toString(), toString(d_qtype), d_nsip.toStringWithPort(), tmstart, tmend);
      else if(now < inception) {
        fmt::print("Got RRSIG that is not yet active for {}|{} from {}, valid from {:%Y-%m-%d %H:%M} to {:%Y-%m-%d %H:%M} UTC\n",
                   d_qname.toString(), toString(d_qtype), d_nsip.toStringWithPort(), tmstart, tmend);

      }
      else
        valid=true;
    }
  }
  if(!valid)
    return fmt::format("Did not find an active RRSIG for {}|{} over at server {}", d_qname.toString(), toString(d_qtype), d_nsip.toStringWithPort());
  
  return "";
}
