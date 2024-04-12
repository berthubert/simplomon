#include <thread>
#include <unistd.h>
#include <fmt/core.h>
#include "fmt/chrono.h"
#include "support.hh"
#include <iostream>
#include "nonblocker.hh"
#include "simplomon.hh"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

using namespace std;

//! false on EOF, but if we did receive come data, that is not EOF yet
bool NonBlocker::drainFromSock(int fd, std::string& dest)
{
  char buf[4096];
  for(;;) {
    int rc = read(fd, buf, sizeof(buf));
    if(rc < 0) {
      if(errno == EAGAIN)
        return true;
      throw runtime_error(fmt::format("Error reading from socket: {}", strerror(errno)));
    }
    if(!rc) { // eof
      if(dest.empty())
        return false;
      return true;
    }
    dest.append(buf, rc);
  }
}

// Returns false on *any* EOF, even if we did manage to write a bit
bool NonBlocker::drainToSock(std::string& src, int fd)
{
  while(!src.empty()) {
    int rc = write(fd, src.c_str(), src.size());
    if(rc < 0) {
      if(errno == EAGAIN)
        return true;
      throw runtime_error(fmt::format("Error writing to socket: {}", strerror(errno)));
    }
    if(!rc) { // eof
      return false;
    }
    src = src.substr(rc); // not very efficient, but quite often we'll be sending the whole ghing
  }
  return true;
}


void NonBlocker::worker()
try
{
  time_t endTime = time(nullptr) + d_seconds;

  if(!d_dest.sin4.sin_family) {
    DNSType dt = d_wantIPv6 ? DNSType::AAAA : DNSType::A;
    auto as = DNSResolveAt(d_dnsname, dt, getResolvers());
    if(as.empty()) {
      d_error = fmt::format("Could not resolve {} for {}", toString(dt), d_dnsname.toString());
      close(d_proxysock);
      return;
    }
    d_dest = *as.begin();
    d_dest.setPort(d_port);
  }
  
  Socket s(d_dest.sin4.sin_family, SOCK_STREAM);

  // perhaps run some stored function here for customization
  
  SetNonBlocking(s);
  SConnectWithTimeout(s, d_dest, d_seconds);

  SetNonBlocking(d_proxysock);

  string toServer, toClient;
  for(;;) {
    if(time(nullptr) > endTime) // this is the main check, the timeout on poll is not clever
      break;
    // Do we need to read something? As long as we have data in our buffers to send, no
    vector<int> toread;
    if(toServer.empty())
      toread.push_back(d_proxysock);
    if(toClient.empty())
      toread.push_back(s);
    
    if(!toread.empty()) {
      auto res = SPoll(toread, {}, 0.25);
      if(res.count(d_proxysock)) { // from our client
        if(!drainFromSock(d_proxysock, toServer))
          break;
      }
      if(res.count(s)) { // from our server
        if(!drainFromSock(s, toClient))
          break;
      }
    }
    if(0)
      fmt::print("Got {} bytes from client to be sent to server, {} from server to be sent to client\n",
               toServer.size(), toClient.size());
    
    // do we need to write something?
    vector<int> towrite;
    if(!toServer.empty())
      towrite.push_back(s);
    if(!toClient.empty())
      towrite.push_back(d_proxysock);
    
    if(!towrite.empty()) {
      auto res = SPoll({},towrite, 0.25);
      if(res.count(d_proxysock)) { // to our client
        if(!drainToSock(toClient, d_proxysock)) {
          d_error = "You (the client) closed the socket";
          break;
        }
      }
      if(res.count(s)) { // to our server
        if(!drainToSock(toServer, s)) {
          d_error = "Server closed the socket";
          break;
        }
      }
    }
  }
  close(d_proxysock);
}
catch(std::exception& e)
{
  fmt::print("Exception: {}\n", e.what());
  d_error = e.what();
}

void NonBlocker::init()
{
  int sv[2];
  if(socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) < 0)
    throw std::runtime_error(fmt::format("Making socketpair: {}\n", strerror(errno)));
  d_usersock=sv[0];  // arbitrary
  d_proxysock=sv[1]; // fd's are identical

  d_thread = std::move(std::thread(&NonBlocker::worker, this));
}

NonBlocker::NonBlocker(const ComboAddress& dest, int seconds) : d_dest(dest), d_seconds(seconds)
{
  init();
}


NonBlocker::NonBlocker(const std::string& dest, int port, bool wantIPv6, int seconds) : d_dnsname(makeDNSName(dest)), d_seconds(seconds), d_wantIPv6(wantIPv6), d_port(port)
{
  d_dest.sin4.sin_family = 0; // this means worker must resolve name
  init();
}


