#include "record-types.hh"
#include "sclasses.hh"
#include <thread>
#include <signal.h>
#include "fmt/format.h"
#include "fmt/ranges.h"
#include "fmt/chrono.h"
#include "simplomon.hh"

using namespace std;

DNSChecker::DNSChecker(sol::table data) : Checker(data, 2)
{
  checkLuaTable(data, {"server", "name", "type", "acceptable"}, {"rd"});
  d_nsip = ComboAddress(data.get<string>("server"), 53);
  d_qname = makeDNSName(data.get<string>("name"));
  d_qtype = makeDNSType(data.get<string>("type").c_str());
  for(const auto& a : data.get<vector<string>>("acceptable"))
    d_acceptable.insert(a);
  d_rd = data.get_or("rd", true);
}

CheckResult DNSChecker::perform()
{
  DNSMessageWriter dmw(d_qname, d_qtype);
          
  dmw.dh.rd = true;
  dmw.randomizeID();
  dmw.setEDNS(4000, false);
  
  Socket sock(d_nsip.sin4.sin_family, SOCK_DGRAM);
  SConnect(sock, d_nsip);

  SWrite(sock, dmw.serialize());

  ComboAddress server;

  double timeo=0.5;
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
  
  //  cout<<"Received "<<resp.size()<<" byte response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<dn<<", qtype "<<dt<<endl;

  if((RCode)dmr.dh.rcode != RCode::Noerror) {
    return fmt::format("Got DNS response with RCode {} from {} for question {}|{}",
                       toString((RCode)dmr.dh.rcode), d_qname.toString(), d_nsip.toStringWithPort(), toString(d_qtype));
  }
  
  std::unique_ptr<RRGen> rr;

  int matches = 0;
  while(dmr.getRR(rrsection, dn, dt, ttl, rr)) {
    if(rrsection == DNSSection::Answer && dt == d_qtype) {
      //  cout << rrsection<<" "<<dn<< " IN " << dt << " " << ttl << " " <<rr->toString()<<endl;
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
