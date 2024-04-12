#pragma once

#include "swrappers.hh"
#include "sclasses.hh"
#include <string>
#include "record-types.hh"

class NonBlocker
{
public:
  NonBlocker(const ComboAddress& dest, int seconds);
  NonBlocker(const std::string& dest, int port, bool wantIPv6, int seconds);
  ~NonBlocker()
  {
    close(d_usersock); 
    d_thread.join();
  }
  void worker();

  operator int()
  {
    return d_usersock;
  }
  std::string d_error;

private:
  bool drainFromSock(int fd, std::string& dest);
  bool drainToSock(std::string& dest, int fd);
  void init();
  ComboAddress d_dest={};
  DNSName d_dnsname;

  int d_seconds;
  bool d_wantIPv6;
  std::thread d_thread;
  int d_usersock;
  int d_proxysock;
  int d_port;
};
