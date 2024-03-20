# simplomon
Very simple availability monitoring system with a single configuration file and a single binary. Also comes as a Docker image.

Key differences compared to existing systems:

 * Setup in 5 minutes, no need to ever think about it anymore
 * Also check what should not work (ports that should be closed)
 * Pin certain things to how they _should_ be (like NS records)
 * Advanced features by default
   * certificate expiry checking
   * DNS synchronization
   * DNSSEC signature freshness checks
   * HTTP redirect checking ('www' -> '', 'http' -> 'https')

You'd use this if you think "I need to slap some monitoring on this pronto
and I can't be bothered to setup something difficult that will require
maintenance or get hacked". Another usecase if you want to monitor from a
vantage point where you can't install large-scale software.

You'd also use this if you appreciate some of the 'smarter' checks described
above.

If you want a full featured complicated monitoring system, there is lots of
choice already, and this isn't it. Also, as it stands simplomon won't scale to thousands of checks.

If you miss features that just make sense, do let me know!  Open an
issue please.

## Sample configuration (without Docker)
Note that the configuration below is completely functional, you need nothing
else, except a working [Pushover](https://pushover.net/) or [ntfy](https://ntfy.sh/)
account, or a mailbox. If you need another notifier, do let me know.

```lua
pushoverNotifier{user="copy this in from pushover config",
        apikey="copy this in from pushover config"}

-- or ntfy.sh:
-- ntfyNotifier{topic="your_secret_topic"}
-- or point to your own instance, or set the Authorization header through 'auth'
-- ntfyNotifier{topic="your_topic", url="https://ntfy.example.net", auth="Basic dGVzdHVzZXI6ZmFrZXBhc3N3b3Jk"}

-- or email
--emailNotifier{from="bert@example.com", to="bert@example.com", server="10.0.0.2"}
```
Pushover appears to work really well, and I'd prefer it to ntfy. Email meanwhile is a bit scary, since it might need the very infrastructure it monitors to send out notifications. You might never get that email.

Here are some sample checkers:

```lua
dailyChime{utcHour=10} -- 10AM UTC chime confirms monitoring works

ping{servers={"9.9.9.9", "8.8.8.8"}} -- does our network even work

-- the following checks certificates, and whines if any expire within
-- two weeks
https{url="https://berthub.eu"}

-- save bandwidth, don't fetch the body
https{url="https://galmon.eu/", method="HEAD"}

-- This complains if that URL is older than 20 minutes
https{url="https://berthub.eu/nlelec/dutch-stack.svg", maxAgeMinutes=20}

-- check if a specific server IP is serving correctly
https{url="https://berthub.eu", serverIP="86.82.68.237"}
https{url="https://berthub.eu", serverIP="2001:41f0:782d::2"}

-- check if a URL works correctly if resolved via specific nameserver
https{url="https://berthub.eu", dns={"8.8.8.8"}}
-- or from a specific source IP
https{url="https://berthub.eu", dns={"9.9.9.9"], localIP="10.0.0.9"}

-- Check if SOA records are identical
nameservers={"100.25.31.6", "86.82.68.237", "217.100.190.174"}
dnssoa{domain="berthub.eu", servers= nameservers}
dnssoa{domain="hubertnet.nl", servers= nameservers}

-- DNSSEC, check if signatures are fresh enough
rrsig{server="45.55.10.200", name="powerdns.com"}
rrsig{server="188.166.104.87", name="powerdns.com"}
rrsig{server="149.20.2.26", name="isc.org", minDays=10}
rrsig{server="100.25.31.6", name="berthub.eu"}

-- Check if the following ports are closed
scaryports={25, 80, 110, 443, 3000, 3306, 5000, 5432, 8000, 8080, 8888}
tcpportclosed{servers={"100.25.31.6"}, ports=scaryports}

-- Check if DNS is serving what it should be
dns{server="100.25.31.6", name="berthub.eu", type="A",
	acceptable={"86.82.68.237", "217.100.190.174"}}
dns{server="100.25.31.6", name="berthub.eu", type="AAAA",
	acceptable={"2001:41f0:782d::2"}}

-- Does the http redirect work?
httpredir{fromUrl="http://berthub.eu", toUrl="https://berthub.eu/"}

-- And the www redirects?
httpredir{fromUrl="http://www.berthub.eu", toUrl="https://berthub.eu/"}
httpredir{fromUrl="https://www.berthub.eu", toUrl="https://berthub.eu/"}
```

Save this as 'simplomon.conf' and start './simplomon' and you should be in
business.

## Webserver
If you run `Webserver{address="127.0.0.1:8080"}`, simplomon will launch a
webserver. If you run Simplomon inside a container, you'll probably have to
use `0.0.0.0:8080` for things to work.

This server supports the following three endpoints:

 * /health: generates {"health":"ok"} which appears to make some Docker
   environments happy
 * /state: creates a JSON object of all active alerts
 * /checker-states: a largish JSON object describing the settings of all checkers & the
 results of the measurements they are doing

## Datalogger
If you add `Logger("stats.sqlite3")`, simplomon will populate a SQLite
database (in the file './stats.sqlite3') with lots of interesting metadata,
one table per checker kind.

In addition, all alert reports will be logged in the 'reports' table, even
if they did not lead to notifications.

## Todo

 * SMTP checker
 * IMAP checker
   * Both with actual certificate checks, including STARTTLS to get to them
 * Generic port *open* test
 * HTTP *POST* support
 * HTTP JSON check
 * Build simple status page based on our JSON output
 * Performance tests ("average response time past hour > 100ms")
 * Enable Check config statements to create multiple kinds of alerts

## Docker
There is [an image on the Docker hub](https://hub.docker.com/repository/docker/berthubert/simplomon/general) which you can pull (berthubert/simplomon).

The image will read its configuration file from the HTTPS URL supplied in the SIMPLOMON_CONFIG_URL environment variable. 

Do make sure to set `Webserver{address="0.0.0.0:8080"}` in that
configuration file, as otherwise your Docker environment may not recognize
that simplomon is running.

To build the image yourself, do:

```bash
sudo docker build -f Dockerfile.full-build .
```

This implements a two-stage builder to create an image.

You can host the image for example on Scaleway's [container
service](https://www.scaleway.com/en/containers/). It makes perfect sense to
host your monitoring somewhere outside of your own network. Note that
Scaleway sadly has no support for outgoing IPv6.

## Running Docker on a server
To run the simplomon service on a Linux server it is easy to wrap a little systemd service definition around it.
* A systemd-based Linux server is needed with root access
* install docker
* create the config file as `/etc/simplomon.conf`
* create a systemd service definition file `/etc/systemd/system/simplomon.service` with these contents:
```
[Unit]
Description=Simplomon Monitoring Service
After=docker.service
Requires=docker.service

[Service]
TimeoutStartSec=0
Restart=always
ExecStartPre=-/usr/bin/docker exec %n stop
ExecStartPre=-/usr/bin/docker rm %n
ExecStartPre=/usr/bin/docker pull berthubert/simplomon
ExecStart=docker run  \
    -v /etc/simplomon.conf:/simplomon.conf  \
    --name %n \
    berthubert/simplomon

[Install]
WantedBy=default.target
```
* let systemd reload config with `systemctl daemon-reload`
* enable the service with `systemctl enable simplomon.service`
* start the service with `systemctl start simplomon.service`

checking if it has started correctly:
```# systemctl status simplomon.service
● simplomon.service - Simplomon Monitoring Service
     Loaded: loaded (/etc/systemd/system/simplomon.service; enabled; vendor preset: enabled)
     Active: failed (Result: timeout) since Wed 2024-03-13 21:07:11 UTC; 10min ago
    Process: 368586 ExecStartPre=/usr/bin/docker exec simplomon.service stop (code=exited, status=1/FAILURE)
    Process: 368595 ExecStartPre=/usr/bin/docker rm simplomon.service (code=exited, status=0/SUCCESS)
    Process: 368624 ExecStartPre=/usr/bin/docker pull berthubert/simplomon (code=exited, status=0/SUCCESS)
    Process: 368647 ExecStart=/usr/bin/docker run -v /etc/simplomon.conf:/simplomon.conf --name simplomon.service berthubert/simplomon (code=killed, signal=KILL)
   Main PID: 368647 (code=killed, signal=KILL)
```

check the log with `journalctl -u simplomon.service`

### notes
- it is normal that the `docker exec stop` or the `docker rm` commands might fail in the status output; they are there to make sure previous instances have been stopped
- Stopping the service might take up to a minute, since the simplomon service can sleep for some time

## Compiling natively
On Debian derived systems the following works:

```
apt install python3-pip pkg-config libnghttp2-dev libssl-dev liblua5.3-dev
```
In addition, the project requires a recent version of meson, which you can
get with 'pip3 install meson ninja' or perhaps 'pip install
meson ninja' and only if that doesn't work 'apt install meson'.

> The meson in Debian bullseye is very old, and will give you a confusing
> error message about 'git' if you try it. If you [enable
> bullseye-backports](https://backports.debian.org/Instructions/) you can do
> `apt install -t bullseye-backports meson` and get a working one. Or use
> the pip version, which is also great.

Then run:

```
meson setup build
meson compile -C build
```

# Distributing binaries, docker etc
To make a more portable binary, try:

```bash
LDFLAGS="-static-libstdc++ -static-libgcc" meson setup build --prefer-static
meson compile -C build/
```

Or even a fully static one:
```bash
LDFLAGS=-static meson setup build --prefer-static -Dbuildtype=release -Dcpp-httplib:cpp-httplib_openssl=disabled -Dcpp-httplib:cpp-httplib_brotli=disabled

meson compile -C build/
```

# Inspiration

 * [Uptime Kuma](https://github.com/louislam/uptime-kuma) - single Docker
   image.
