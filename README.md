# simplomon
Very simple monitoring system with a single configuration file and a single binary. Also comes a a Docker image.

Key differences compared to existing systems:

 * Setup in 5 minutes, no need to ever think about it anymore
 * Also check what should not work (ports that should be closed)
 * Pin certain things how they _should_ be (like NS records)
 * Advanced features by default
   * certificate expiry checking
   * DNS synchronization
   * DNSSEC signature freshness checks
   * HTTP redirect checking ('www' -> '', 'http' -> 'https')

You'd use this if you think "I need to slap some monitoring on this pronto
and I can't be bothered to setup something difficult that will require
maintenance or get hacked".

You'd also use this if you just want to do stuff like this out of the box:

 * Check if all DNS servers are updating
 * If you want to get timely notifications of TLS certificates expiring

If you want a full featured complicated monitoring system, there is lots of
choice already, and this isn't it.

But if you miss features that just make sense, do let me know!  Open an
issue please.

## Sample configuration (without Docker)
Note that this configuration is completely functional, you need nothing
else, except a working [Pushover](https://pushover.net/) or [ntfy](https://ntfy.sh/)
account. If you need something else, do let me know.

```lua
pushoverNotifier{user="copy this in from pushover config",
        apikey="copy this in from pushover config"}

-- or ntfy.sh:
-- ntfyNotifier{topic="your_secret_topic"}

-- or email
--emailNotifier{from="bert@example.com", to="bert@example.com", server="10.0.0.2"}

dailyChime{utcHour=10} -- 10AM UTC chime confirms monitoring works

-- the following checks certificates, and whines if any expire within
-- two weeks
https{url="https://berthub.eu"}
https{url="https://galmon.eu/"}

-- This complains if that URL is older than 20 minutes
https{url="https://berthub.eu/nlelec/dutch-stack.svg", maxAgeMinutes=20}

-- check if a specific server IP is serving correctly
https{url="https://berthub.eu", serverIP="86.82.68.237"}
https{url="https://berthub.eu", serverIP="2001:41f0:782d::2"}

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

## Docker
There is [an image on the Docker hub](https://hub.docker.com/repository/docker/berthubert/simplomon/general) which you can pull (berthubert/simplomon).

The image will read its configuration file from the HTTPS URL supplied in the SIMPLOMON_CONFIG_URL environment variable.

## Compiling
On Debian derived systems the following works:

```
apt install python3-pip pkg-config libnghttp2-dev
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

