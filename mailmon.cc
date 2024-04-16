#include "simplomon.hh"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "peglib.h"
#include "nonblocker.hh"
#include <mutex>

using namespace std;

bool getLine(FILE* fp, std::string& line)
{
  char buf[256]={};
  if(fgets(buf, sizeof(buf)-1, fp) == nullptr)
    return false;
  line = buf;
  return true;
}

// empty string == EOF
string sslGetLine(SSL* ssl)
{
  string resp;
  for(;;) {
    char c;
    int rc = SSL_read(ssl, &c, 1);
    if(rc == 1) {
      resp.append(1,c);
      if(c=='\n')
        break;
    }
    if(rc <= 0)
      break;
  }
  return resp;
}

struct SSLHelper
{
  SSLHelper()
  {
    // Initialize OpenSSL - can you do this all the time?
    std::lock_guard<std::mutex> l(d_lock);

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    // Initialize SSL
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL) {
      throw std::runtime_error("Error: SSL context creation failed");
    }

    // Load trusted CA certificates
    if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
      SSL_CTX_free(ssl_ctx);
      throw std::runtime_error("Error loading CA certificates\n");
    }
    
    // Create SSL connection
    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
      SSL_CTX_free(ssl_ctx);
      throw std::runtime_error("Creating SSL struct");
    }
  }

  ~SSLHelper()
  {
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
  }
  
  
  void attachFD(int fd)
  {
    if (SSL_set_fd(ssl, fd) != 1) 
      throw std::runtime_error("Error: Failed to attach socket descriptor to SSL");
  }

  void initTLS()
  {
    if (SSL_connect(ssl) != 1) {
      throw std::runtime_error("Error: SSL handshake failed\n");
    }
  }
  void checkConnection(const std::string& host, int days = -1);
  void printDetails();
  SSL_CTX *ssl_ctx;
  SSL *ssl;

  static std::mutex d_lock;
};

std::mutex SSLHelper::d_lock;

void SSLHelper::printDetails()
{
  shared_ptr<X509> cert(SSL_get_peer_certificate(ssl), X509_free);
  
  X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert.get()), 0,XN_FLAG_RFC2253);
  fmt::print("\n");
  
  X509_NAME_print_ex_fp(stdout, X509_get_issuer_name(cert.get()), 0,XN_FLAG_RFC2253);
  fmt::print("\n");
  
  
  ASN1_INTEGER *serial = X509_get_serialNumber(cert.get());
  if (serial != NULL) {
    BIGNUM *bn_serial = ASN1_INTEGER_to_BN(serial, NULL);
    char *serial_string = BN_bn2hex(bn_serial);
    if (serial_string != NULL) {
      fmt::print("Serial Number: {}\n", serial_string);
      OPENSSL_free(serial_string);
    }
    BN_free(bn_serial);
  }
  
  auto t=X509_get_notAfter(cert.get());
  struct tm notafter, notbefore;
  ASN1_TIME_to_tm(t, &notafter);

  t=X509_get_notBefore(cert.get());
  ASN1_TIME_to_tm(t, &notbefore);
  fmt::print("{:%Y-%m-%d %H:%M} - {:%Y-%m-%d %H:%M}\n", notbefore, notafter);
}

void SSLHelper::checkConnection(const std::string& host, int minCertDays)
{
  long verify_result = SSL_get_verify_result(ssl);
  if (verify_result != X509_V_OK) {
    throw std::runtime_error(fmt::format("Certificate verification error: {}\n", X509_verify_cert_error_string(verify_result)));
  }
  
  shared_ptr<X509> cert(SSL_get_peer_certificate(ssl), X509_free);
  // this is sensitive to trailing dots
  if (X509_check_host(cert.get(), host.c_str(), host.size(), 0, NULL) != 1) {
    throw std::runtime_error(fmt::format("Cert does not match host {}", host));
  }

  if(minCertDays > 0) {
    auto t=X509_get_notAfter(cert.get());
    struct tm notafter;
    ASN1_TIME_to_tm(t, &notafter);
    time_t expire = mktime(&notafter);
    double days = (expire - time(nullptr))/86400.0;
    if(days < minCertDays)
      throw std::runtime_error(
                               fmt::format("Certificate for {} set to expire in {:.0f} days",
                                           host, days));
  }
}

SMTPChecker::SMTPChecker(sol::table data) : Checker(data)
{
  checkLuaTable(data, {"server"}, {"servername", "from", "to", "minCertDays"});
  d_server = ComboAddress(data.get<std::string>("server"), 25);
  d_attributes["server"] = d_server.toStringWithPort();
  d_minCertDays =  data.get_or("minCertDays", 14);
  d_from = data.get_or("from", string());
  d_to = data.get_or("to", string());
  
  sol::optional<string> servername = data["servername"];
  if(servername != sol::nullopt)
    d_servername = makeDNSName(*servername);
}


CheckResult SMTPChecker::perform()
{
  NonBlocker nb(d_server, 10);
  shared_ptr<FILE> fp(fdopen(dup(nb), "r+"), fclose);

  string line;
  auto sponge= [&](int expected) {
    while(getLine(fp.get(), line)) {
      if(line.size() < 4)
        throw std::runtime_error("Invalid response from SMTP server: '"+line+"'");
      if(stoi(line.substr(0,3)) != expected)
        throw std::runtime_error("Unexpected response from SMTP server: '"+line+"'");
      if(line.at(3) == ' ')
        break;
    }
  };
  
  sponge(220);

  if(line.empty()) {
    fmt::print("EOF, possibly error: {}\n", nb.d_error);
    return "EOF early";
  }
  
  fprintf(fp.get(), "EHLO simplomon\r\n");
  sponge(250);

  if(line.empty()) {
    fmt::print("EOF, possibly error: {}\n", nb.d_error);
    return "EOF after EHLO";
  }
  
  fprintf(fp.get(), "STARTTLS\r\n");
  sponge(220);

  SSLHelper sh;
  sh.attachFD(nb);

  sh.initTLS();
  //  sh.printDetails();
  string checkname = d_servername.empty() ? "" : d_servername.toString();
  if(!checkname.empty())
    checkname.resize(checkname.size()-1); // trailing dot upsets openssl
  sh.checkConnection(checkname, d_minCertDays);

  auto spongeSSL = [&](int expected) {
    string line;
    for(;;) {
      line = sslGetLine(sh.ssl);
      if(line.size() < 4)
        throw std::runtime_error("Invalid response from SMTP server: '"+line+"'");
      if(stoi(line.substr(0,3)) != expected)
        throw std::runtime_error("Unexpected response from SMTP server: '"+line+"'");
      if(line.at(3) == ' ')
        break;
    }
  };

  if(!d_from.empty() && !d_to.empty()) {
    line="MAIL From:<"+d_from+">\r\n";
    SSL_write(sh.ssl, line.c_str(), line.size());
    spongeSSL(250);
    
    line="RCPT To:<"+d_to+">\r\n";
    SSL_write(sh.ssl, line.c_str(), line.size());
    spongeSSL(250);
    
    line="DATA\r\n";
    SSL_write(sh.ssl, line.c_str(), line.size());
    
    spongeSSL(354);
    string subject="A simplomon test message";
    
    string msg="From: "+d_from+"\r\n";
    msg+="To: "+d_to+"\r\n";
    msg+="Subject: "+subject+"\r\n";
    
    msg+=fmt::format("Message-Id: <{}@simplomon.hostname>\r\n", time(nullptr));
    
    //Date: Thu, 28 Dec 2023 14:31:37 +0100 (CET)
    msg += fmt::format("Date: {:%a, %d %b %Y %H:%M:%S %z (%Z)}\r\n", fmt::localtime(time(0)));
    msg+="\r\n";
    
    msg+=to_string(time(nullptr))+"\r\n";
    msg+="A simplomon test message!\r\n";
    msg+= "\r\n.\r\n";
    SSL_write(sh.ssl, msg.c_str(), msg.size());
    
    spongeSSL(250);
  }

  line = "quit\r\n";
  SSL_write(sh.ssl, line.c_str(), line.size());

  spongeSSL(221);
  return "";
}


IMAPChecker::IMAPChecker(sol::table data) : Checker(data)
{
  checkLuaTable(data, {"server"}, {"user", "password", "servername", "minCertDays"});
  d_server = ComboAddress(data.get<std::string>("server"), 993);
  d_attributes["server"] = d_server.toStringWithPort();
  d_minCertDays =  data.get_or("minCertDays", 14);
  d_user = data.get_or("user", string());
  d_attributes["user"] = d_user;
  d_password = data.get_or("password", string());
  
  sol::optional<string> servername = data["servername"];
  if(servername != sol::nullopt)
    d_servername = makeDNSName(*servername);
}

// https://www.atmail.com/blog/imap-101-manual-imap-sessions/
// https://nickb.dev/blog/introduction-to-imap/

CheckResult IMAPChecker::perform()
{
  NonBlocker nb(d_server, 10);

  SSLHelper sh;
  sh.attachFD(nb);

  sh.initTLS();
  //  sh.printDetails();
  string checkname = d_servername.empty() ? "" : d_servername.toString();
  if(!checkname.empty())
    checkname.resize(checkname.size()-1);
  if(!checkname.empty())
    sh.checkConnection(checkname, d_minCertDays);

  string resp = sslGetLine(sh.ssl);

  int counter=0;
  vector<string> lines;
  auto scommand = [&](const std::string& cmd) {

    string line="A"+to_string(counter++)+" " + cmd+"\r\n";
    //    fmt::print("Sending {}", line);
    SSL_write(sh.ssl, line.c_str(), line.size());
    lines.clear();
    do {
      resp = sslGetLine(sh.ssl);
      //fmt::print("Response is {}", resp);
      if(lines.empty()) {
        auto pos = resp.rfind('{');
        if(pos != string::npos) {
          int bytes = atoi(&resp.at(pos+1));
          vector<char> c(bytes);
          SSL_read(sh.ssl, &c.at(0), bytes);
          lines.push_back(string(&c.at(0), bytes));
          SSL_read(sh.ssl, &c.at(0), 3); // ")\r\n"
          continue;
        }
      }
      lines.push_back(resp);
    }while(!resp.empty() && resp[0]=='*');
  };

  
  scommand("login "+d_user+" "+d_password);
  scommand("namespace");
  scommand(R"(select "INBOX")");
  scommand(R"(uid search subject "Simplomon test message")");
  /*
  * SEARCH 171430 171431 171432 171433 171434 171435
a9 OK Search completed (0.045 + 0.000 + 0.044 secs).
  */

  peg::parser p(R"(
LINE <- '* SEARCH' (' ' UID)*'\r\n'?
UID <- (![ \r\n] .)+
)");

  if(!(bool)p)
    throw runtime_error("Error in grammar");
  
  p["UID"] = [](const peg::SemanticValues& vs) {
    return vs.token_to_string();
  };

  p["LINE"] = [](const peg::SemanticValues& vs) {
    return vs.transform<string>();
  };
  vector<string> uids;
  p.parse(lines[0], uids);

  fmt::print("Got {} uids: {}\n", uids.size(), uids);

  /*
n uid fetch 171446 BODY[TEXT]
* 13508 FETCH (UID 171446 FLAGS (\Seen) BODY[TEXT] {58}
hallo
)
en gaat het nu door dan?
zou wel leuk zijn
)
)
n OK Fetch completed (0.026 + 0.000 + 0.025 secs).
  */
  vector<string> todel;
  time_t freshest = 0;
  for(const auto& uid : uids) {
    scommand("uid fetch "+uid+" BODY.PEEK[TEXT]");
    //    fmt::print("lines: {}\n", lines);
    if(!lines.empty()) {
      time_t then = atoi(lines[0].c_str());
      if(freshest < then)
        freshest = then;
      time_t age = time(nullptr) - then;
      //      fmt::print("Age is {} seconds\n", age);
      if(age > 300)
        todel.push_back(uid);
    }
  }

  for(const auto& del : todel) {
    scommand("uid store "+del+" +FLAGS (\\Deleted)");
  }
  if(!todel.empty())
    scommand("expunge");
  
  if(time(nullptr) - freshest > 300) {
    return "No recent sentinel message found";
  }
  return "";
}
