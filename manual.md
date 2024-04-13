# What simplomon does

> This file is not yet complete! However, everything you read here should be
> correct.

Simplomon is a self-contained program that runs *checkers* on your infrastructure.
Checkers can signal one or more alert conditions. Such an alert might be configured to
need a few repeats before it leads to a *notification*. 

Simplomon supports several notifiers, which can also be configured to only send
out alert conditions that persist for x minutes or more. Suitable for
management people. 

# Configuration
Configuration is read from a file that is actually interpreted as Lua code. 

A useful but minimal configuration file is:

```Lua
addEmailNotifier{from="bert@hubertnet.nl", to="bert@hubertnet.nl", server="10.0.0.2"}

-- at 10 AM UTC receive confirmation that things are working
dailyChime{utcHour=10}

-- check certificates, content, warn on certificates close expirey
https{url="https://berthub.eu/", regex="Europe"}

-- check if all nameservers have the same SOA record
dnssoa{domain="berthub.eu", 
	servers={"100.25.31.6", "86.82.68.237", "217.100.190.174"}
}
```

Simplomon will read its configuration file from "./simplomon.conf", or from
the first command line argument, or from the URL specified in the SIMPLOMON_CONFIG_URL
environment variable (for use in containers).

Because the configuration file is Lua, it is possible to store variables for
reuse, or to have loops that populate many checks from a loop etc.

# What simplomon does
The configuration file is read once, and it defines:

 * Checkers: what do we check
 * Notifiers: how do we notify alerts
 * Settings: how often do we check, using how many parallel checks etc
 * Logger: if alert, notifications, statistics get logged
 * Webserver: if we should launch the webserver, if there should be a
 dashboard

Simplomon by default tries to perform all checks once every minute. To do
so, it will by default perform at most 4 checks in parallel. After all
checks are done, simplomon determines how long this took. If it took longer
than the configured check interval, the number of allowed parallel checks is
raised by 1 for the next round. By default at most 16 checks will happen in
parallel.

# When does a notification go out?
This is a multi-step process, and it might currently be a bit too confusing.

A *checker* delivers a list of alerts. Simplomon then counts if there have
been more than `minFailures` alerts within `failureWindow` seconds. And if
so, the alert is passed on to the nofitier(s). The default values for most
checkers are 1 alert within 120 seconds. 

The upshot of this is that a single alert will persist for 2 minutes.
However, the Ping checker defaults to `minFailures=2`. This means that only
two subsequent failed pings will be reported to the notifiers.

By default the notifiers will just forward whatever they get. However, as an
additional feature, a notifier can introduce an additional delay. If a
notifier gets passed a `minMinutes` parameter, an actual notification will
only go out if a notification persists for that many minutes.

# All checkers
## dns
Check if DNS is serving what it should be. TBC. Example:

```lua
dns{server="100.25.31.6", name="berthub.eu", type="A",
	acceptable={"86.82.68.237", "217.100.190.174"}}
dns{server="100.25.31.6", name="berthub.eu", type="AAAA",
	acceptable={"2001:41f0:782d::2"}}
```

## dnssoa
Check if SOA records are identical. TBC. Example:

```lua
nameservers={"100.25.31.6", "86.82.68.237", "217.100.190.174"}
dnssoa{domain="berthub.eu", servers= nameservers}
dnssoa{domain="hubertnet.nl", servers= nameservers}
```

## httpredir

Does the http redirect work? TBC. Example:

```lua
httpredir{fromUrl="http://berthub.eu", toUrl="https://berthub.eu/"}
```

## https
The https checker supports many things, but with sensible defaults you can
often just use `https{url="https://berthub.eu/"}` and be done. Of specific
note, if you have an AAAA IPv6 address for your domain name, and if your
Simplomon has working IPv6, this check will check both IPv4 and IPv6
automatically. 

Here are the parameters, of which only `url` is mandatory:

 * url: needs to include https. Simplomon will follow any redirects.
 * maxAgeMinutes: alert if the webserver says content is older than this
 * minCertDays: alert if a certificate in the chain expires within this many
   days (defaults to 14)
 * serverIP: perform the check for `url` on this IPv4/IPv6 address. Useful
   for if you know you have multiple backends, and want to force the test to
   happen on all of them.
 * localIPv4/localIPv6: bind to these addresses when connecting to IPv4 or
   IPv6. Can be useful to perform tests from systems with multiple internet
   connections.
 * minBytes: if the web server returns fewer bytes than this, it is an alert
 * regex: search for this regex in the returned content, and if it isn't
   found, this is an alert
 * method: GET or HEAD. Be aware that some sites effectively do not support
   HEAD, possibly because of "web firewalls"
 * dns: get the IP address from these nameservers. Useful when testing
   against DNS-based CDNs (like Akamai). 

## imap
The imap checker assumes it connects to a TLS endpoint. There it will check the certificate for freshness. 

If a username and password are configured, the checker will check the main Mailbox for messages called 'Simplomon test message'. If no recent message is found, this lead to an alert. Such test messages can be delivered by the smtp checker described below.

Parameters:
 * server: IP(v6) address of the server to be checked
 * servername: what name to check the certificate against
 * minCertDays: optional, expected remaining lifeftime of the certificate
 * user, password: optional, if set, check if a recent 'Simplomon test message' is present in the main Mailbox
 
The checker will actually delete messages called 'Simplomon test message' to prevent the smtp checker from filling up your mailbox.

## ping
Send out IPv4, IPv6 ping messages. Supports %-style link selection for fe80 usage.

```lua
ping{servers={"9.9.9.9", "8.8.8.8"}} -- does our network even work
```
TBC

## prometheusExp
Query a Prometheus Node Exporter. TBC.
Example:
```lua
prometheusExp{url="http://10.0.0.1:9100/metrics", 
checks={{kind="DiskFree", mountpoint="/", gbMin=10},
        {kind="AptPending"},  -- pending security updates
        {kind="Bandwidth", device="enp2s0.9", minMbit=0.1, maxMbit=50},
        {kind="Bandwidth", device="ppp0", minMbit=0.4}
}}
```

## rrsig
Check for DNSSEC signature expiry. TBC.

```lua
rrsig{server="45.55.10.200", name="powerdns.com"}
```

## smtp
The smtp checker assumes it connects to a plaintext SMTP server, where it can send STARTTLS to move to a TLS protected session. There it will check the certificate for freshness. 

If the 'from', and 'to' parameters are configured, the checker will attempt to deliver a message with the subject 'Simplomon test message'.

Parameters:
 * server: IP(v6) address of the server to be checked
 * servername: what name to check the certificate against
 * minCertDays: optional, expected remaining lifeftime of the certificate
 * from, to: optional, if set, deliver a 'Simplomon test message'

This simplomon test message is meant to be checked by the imap checker (see above).

## tcpportclosed
Check if certain ports are closed on multiple servers:

```lua
-- Check if the following ports are closed
scaryports={25, 80, 110, 443, 3000, 3306, 5000, 5432, 8000, 8080, 8888}
tcpportclosed{servers={"100.25.31.6"}, ports=scaryports}
```
TBC

# All notifiers
Notifiers are *added* using the `addXNotifier` commands. If you want nothing special, define a notifier at the very top of your configuration file. 

Checkers defined after an `addXNotifier` command will notify through all previously added notifiers. This means that you can for example define another notifier that only gets used by the checkers defined beyond that point.

You can also explicitly set notifiers per checker using the following syntax:

```lua
testers = {createEmailNotifier{from="bert@example.com", to="bert@example.com",
server="10.0.0.2}}

https{url="https://staging.example.com", notifiers=testers}
```

## Email
Example:

```lua
addEmailNotifier{from="bert@example.com", to="bert@example.com",
server="10.0.0.2", minMinutes = 60}
```

## Ntfy.sy
Example:

```lua
addNtfyNotifier{topic="your_secret_topic"}
```
You can also specify an authorization through `auth`, and a notification URL through `url`.

## Pushover
Example:
```lua
addPushoverNotifier{user="copy this in from pushover config",
        apikey="copy this in from pushover config"}
```

## Telegram
Example:

```lua
addTelegramNotifier{bot_id="your bot id",
                       apikey="your api key",
                       chat_id="the chat id"}
```

# Webserver
If you run `Webserver{address="127.0.0.1:8080"}`, simplomon will launch a
webserver. If you run Simplomon inside a container, you'll probably have to
use `0.0.0.0:8080` for things to work.

You can also add `user="something", password=...` (password in quotes). 

This server supports the following three endpoints. The first, '/health' is
always enabled. The dashboard and other JSON endpoints only function if you
supplied a user name and a password, which will be checked using basic auth.

 * /health: generates {"health":"ok"} which appears to make some Docker
   environments happy
 * /state: creates a JSON object of all active alerts
 * /checker-states: a largish JSON object describing the settings of all checkers & the
 results of the measurements they are doing

If you load / in a webserver you get a somewhat nice dashboard with metrics.

# Logger
Enabled like this:

```lua
Logger{filename="db.sqlite"}`
```
This fills db.sqlite with a _lot_ of statistics. In the database, you'll find the following generic tables:

 * reports: everytime a checker raises an alert, it is logged in this table. There are four columns that are always present:
   * checker: name of checker that generated this row
   * subject: within the checker, which subject created the alert condition
   * reason: human readable description of the problem
   * tstamp: UNIX timestamp when the report was generated
 * notifications: a copy of everything that was submitted to the notifiers. Columns:
   * tstamp: UNIX timestamp when the notification was submitted
   * message: the message that got sent out
   
The reports table also includes additional columns that describe the exact configuration of the checker that caused the report.

In addition, each checker fills its own table with fun statistics on what it checked. This happens even when there are no problems. This table can be used to create graphs, for example, or to perform forensics on alerts.

