# simplomon
Very simple monitoring system with a single configuration file

Key differences:
 * Also setup what should not work
 * Pin certain things how the _should_ be (like NS records)


## different destinations for alerts
so you can monitor for friends easily

## Monitors
Each Monitor does its thing and publishes some helpful stats. One of these
stats is called alert. 

Some samples:

`checkTCPUnreachable("192.0.2.0/24", [22, 25, 3306], except: [["192.0.2.1", 25]])`

Will check this entire range that the named ports are not reachable. 
Each individual IP/port combination is a possible alert state. 

`ensureNSRecords("berthub.eu", {"server.berthub.eu", "ns-us1.berthub.eu"})`

`checkURLReachable("https://berthub.eu", ips: {"1.2.3.4", "5.4.3.2", "DNS"})`
This will also check if the certificate is fresh

`checkDNSSOASync("berthub.eu")` - checks if all the SOA records are the same

`checkDNSResponds("www.berthub.eu", ips: {"1.2.3.4", "5.4.3.2"})`
`checkNoSMTPRelay("smtp.server.example.com")`





 * Port open
   * Open: 0 or 1
   * Alert: 1 or 0
 * https request
   * Succeeded: 0 or 1
   * Reponse time: 200ms
   * Certificate remaining days: 34



It also knows when it is in an alert condition based on those stats.  There
could also be multiple alert conditions, and these are also published.

The monitor performs periodic checks, and these set or reset the alert
conditions.

These conditions get polled, and can lead to alerts.

# Filter
Many tests might be a bit flaky and we only want to alert if the alert stays
up for a while.

