#include "simplomon.hh"
#include <fstream>

using namespace std;

static DNSMessageReader sendQuery(const vector<ComboAddress>& resolvers, DNSName dn, DNSType dt, std::optional<ComboAddress> local4 = std::optional<ComboAddress>(), std::optional<ComboAddress> local6 = std::optional<ComboAddress>())
{
  DNSMessageWriter dmw(dn, dt);
  
  dmw.dh.rd = true;
  dmw.randomizeID();
  dmw.setEDNS(4000, false);
  for(int n=0; n < 3; ++n) {
    for(const auto& server: resolvers) {
      try {
	Socket sock(server.sin4.sin_family, SOCK_DGRAM);
        
        if(server.sin4.sin_family == AF_INET && local4) {
          local4->setPort(0);
          SBind(sock, *local4);
        }
        if(server.sin4.sin_family == AF_INET6 && local6) {
          local6->setPort(0);
          SBind(sock, *local6);
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
          throw std::runtime_error(fmt::format("Needed to do TCP DNS for {}|{} which we can't", dn, dt));
	  // shit
	}
	else
	  return dmr;
      }
      catch(...){} 
    }
  }
  throw std::runtime_error(fmt::format("No DNS server could be reached or responded trying to resolve '{}|{}'", dn, dt));
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
                                       std::optional<ComboAddress> local4,
                                       std::optional<ComboAddress> local6
                                       )
{
  DNSMessageReader dmr = sendQuery(servers, name, type, local4, local6);
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


std::string getAgeDesc(time_t then)
{
  int diff = (time(nullptr) - then);
  if(diff < 60)
    return fmt::format("{} seconds", diff);
  else if(diff < 3600) 
    return fmt::format("{} minutes", diff/60);
  else if(diff < 2*86400) 
    return fmt::format("{:.1f} hours", diff/3600.0);

  return fmt::format("{:.1f} days", diff/86400.0);  
}
