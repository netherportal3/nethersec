# Flood detector (`flood-report.sh`)

A CDN or an edge firewall only sees traffic that goes through it. Anyone who learns a box's IP
can reach it directly with an HTTP flood, an SMTP connection flood or a SYN flood. This
detector reads what the box itself can see about that traffic and reports through the same
transport as the host detector. It runs every minute, because a live flood cannot wait for the
30-minute detector, and it shares the detector's rules: raise once, resolve once, a per-run cap
(`HOSTSEC_FLOOD_MAX_POSTS`, 6), one `monitor-unreadable-flood` card for whatever it cannot
read, only a 2xx counts as sent (anything else goes again on the next run), and always exit 0.

**Detection is on; blocking ships off.** With `HOSTSEC_FLOOD_MITIGATE=0` (the default) it only
logs the address it would drop and names it on the card. Only the exact value `1` arms it: any
other value (`true`, `yes`, a typo) leaves blocking off and says so in the journal.

It is tested by offline harnesses (`host/test/flood-report.test.sh` for the decisions and the
mitigation choices, against a mock `nft`; `host/test/flood-http-aggregate.test.sh` for the log
parsing), not yet on a live server under a real flood.

## Checks

| Check | Event | Signal | Default |
|---|---|---|---|
| Connection flood | `conn-flood` | conntrack `count/max` at 85% or more, at least 500 half-open SYN-RECV sockets, or one source outside the CDN ranges holding 60% of at least 3000 established connections | quiet card, naming that source when one dominates |
| Network volume | `net-flood` | inbound packets and bits a second from `/proc/net/dev` (120000 pps or 800 Mbit/s) | quiet card. No single source, so never blocked |
| HTTP request flood | `http-flood` | requests per client in the Caddy JSON access log (`docker logs`): at least 6000 in the window and one client with 55% of them, or at least 18000 a minute from all clients together | quiet card. Inert without a Caddy container |
| SMTP connect burst | `smtp-flood` | postfix `connect from` lines in the mail server container's logs (at least 1500 in the window); the top source is named when it has 60% of them | quiet card. Inert without a mail container |

Each takes `HOSTSEC_FLOOD_*_SEVERITY=critical` to page instead. A check whose signal does not
exist on the box (no Caddy, no mail container) posts nothing; a signal that exists but cannot
be read folds into `monitor-unreadable-flood`, never a false all-clear. A `docker ps` or
`docker logs` that fails counts as cannot read, since it cannot tell "no container" from "could
not look". The rate checks count
what came in since the previous run, and the first run only records a starting point, so a new
install never alerts on old log lines. After a pause, the first window covers the whole pause.

The thresholds ship high so a busy box never cries wolf. Watch a normal day, then lower them
in `/etc/nethersec/flood.env` (mode 600). Keep your tuned values private: they tell an attacker
how far under the radar to stay.

**The HTTP check** needs Caddy to write its access log as JSON to stdout (`output stdout` and
`format json` in its `log` block): the check reads only the container's stdout. It finds a
container whose name has `caddy` in it, or takes `HOSTSEC_FLOOD_HTTP_CONTAINER`. [`flood-http-aggregate.py`](../../host/flood-http-aggregate.py)
works out each request's real client: the `Cf-Connecting-Ip` header counts only when the
request came from a Cloudflare address (any client can send that header, so honoring it
otherwise would let an attacker point the drop at someone else), then Caddy's `client_ip`,
then the peer address. Every request counts, whatever its user agent: a client sets its own
user agent, so a flood could claim to be Googlebot. A top client in Cloudflare's ranges or
part of Fastly's, one found through a header rather than its own connection, or one whose
requests mostly carry a good-bot user agent (search engines, link unfurlers such as Discordbot
and Slackbot, uptime monitors), is named on the card but never blocked, since blocking Discordbot would break every link preview of your site. When no
single client holds 55% but all of them together send at least 18000 requests a minute
(`HOSTSEC_FLOOD_HTTP_TOTAL_PER_MIN`), the check raises too, naming the busiest client, and
blocks nothing.

**The SMTP check** finds a container whose name has `mail` in it, or takes
`HOSTSEC_FLOOD_SMTP_CONTAINER`.

## Blocking (off by default)

When a check finds one dominant IPv4 source (a `conn-flood` established flood or an
`http-flood`) and `HOSTSEC_FLOOD_MITIGATE=1`, the detector adds a drop for that address that
expires by itself (`HOSTSEC_FLOOD_MITIGATE_MINUTES`, 60). It uses its own nftables table,
`inet nethersec_flood`, with a `prerouting` chain at priority -300 so it runs before Docker's
rules, and a `flood_drop` set with a timeout per element.

The drop matches the packet's source address: every IPv4 packet that address sends to the box,
on any port and to any container, is dropped. A client the HTTP check found through Cloudflare's
header (or through Caddy's `client_ip` behind another proxy) reaches the box through that proxy,
so the drop could not stop it, and a client can write that header itself. So the HTTP check
blocks only a client that connected to the box directly; one found through a header is named
on the card and never blocked.

Every decline falls through to the alert (worst case: alerted, not blocked):

- loopback, private and carrier-grade NAT ranges, link-local and reserved addresses, the box's
  own addresses and its default gateway are never dropped (a proxy, tunnel or local app shows
  up as one of these, and dropping it would cut the box off from itself);
- the Cloudflare ranges and the part of Fastly's built into the script are never dropped;
- nor any address on `HOSTSEC_FLOOD_ALLOW_IPS` (exact addresses, not ranges: your own app
  servers, uptime monitors, your admin address);
- and at most `HOSTSEC_FLOOD_MITIGATE_MAX_PER_HOUR` (6) drops in each clock hour; past that it
  stops blocking and only alerts.

Arm it per box only after watching the detector fire correctly. To undo:

```sh
sudo sh /opt/nethersec/flood-report.sh --unmitigate              # remove every drop (the whole table)
sudo sh /opt/nethersec/flood-report.sh --unmitigate-ip 203.0.113.9
```

Never arm it on a box running docker-mailserver: that runs its own fail2ban with nftables
inside the container, and a host rule would collide. The detector still alerts there.

## Install and operate

```sh
sudo bash host/install.sh --with-flood --run-now
journalctl -u nethersec-flood-report.service -n 40 --no-pager
sudo touch /etc/nethersec/flood-disabled          # pause just this
```

It reuses the transport and the source name in `report.env` and keeps its own knobs in
`/etc/nethersec/flood.env`, made from [flood.env.example](../../host/flood.env.example), which
lists every threshold, severity and mitigation setting. It needs `python3` for the HTTP check.
The connection check reads the conntrack counters in `/proc` and `ss`: with one of them it
checks what that one shows, and with neither it reads as unreadable. An `ss` that is installed
but fails reads as unreadable too, unless the conntrack counters already show a flood, so a
card it raised is never cleared on the counters alone. `install.sh --uninstall` removes its
table along with the rest.
