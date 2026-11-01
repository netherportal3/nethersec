#!/usr/bin/env python3
"""flood-http-aggregate.py: reduce a Caddy JSON access log to one flood decision line.

Reads Caddy access-log JSON lines on STDIN (the output of `docker logs <caddy>` when
the Caddyfile uses `log { format json }`) and prints ONE line to STDOUT:

    <total> <topcount> <topip> <sharepct> <lines_seen> <topexempt>

- total       every request in the window with a client IP that parses
- topcount    requests from the single busiest client IP
- topip       that client IP ('-' when there were none)
- sharepct    topcount / total as an integer percent (0 when total is 0)
- lines_seen  raw log lines read (so the caller can tell "quiet" from "not JSON":
              many lines seen but zero parsed ⇒ the log is console format, not JSON)
- topexempt   1 when topip must never be blocked: it is in a protected CDN range, most
              of its requests carry a good-bot User-Agent, or most of them did not
              come from it directly (its address came from a header through a proxy,
              which a client can write, and a drop at the box would not stop it). Else 0.

Client IP is resolved to the REAL client, but the
spoofable CF-Connecting-IP header is honored ONLY when the request actually reached
us from a Cloudflare edge (request.remote_ip in the Cloudflare ranges); otherwise a
direct CDN-bypass client could forge it to steer the drop at a third party. Order from
a CF edge: CF-Connecting-IP → request.client_ip (Caddy trusted-proxy-resolved) →
request.remote_ip; every IP is validated with ipaddress and emitted canonically, and a
line whose resolved IP does not parse is skipped. Every request counts, whatever its
User-Agent or address: a User-Agent is set by the client, so skipping "good bots" would
let a flood that claims to be Googlebot go unseen. The good-bot User-Agents and the
protected CDN ranges only set topexempt, which keeps the detector from blocking that
source (a blocked Discordbot kills every link preview of the site). The sh detector
applies its thresholds to the numbers printed here.

Pure stdin→stdout, stdlib only, no network. Any malformed line (bad JSON, bytes that are
not UTF-8) is counted as seen and skipped, never fatal. If the script itself fails, it
prints NOTHING and exits 1, so the caller reads the check as unreadable. It never prints
a made-up "0 0 - 0 0 0", which would read as a quiet window and could close an open card.
"""

import sys
import json
import ipaddress

# Cloudflare's own edge ranges (https://www.cloudflare.com/ips-v4 + ips-v6). The
# CF-Connecting-IP header is attacker-spoofable and is trusted ONLY when the request
# actually reached us FROM one of these ranges (see _client_ip / _is_cloudflare).
_CLOUDFLARE_CIDRS = [
    # Cloudflare IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Cloudflare IPv6
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# Fastly ranges (the subset that fronts crawlers/mirrors). Protected from being
# picked as the attacker, but Fastly does NOT set CF-Connecting-IP, so being on this
# list never grants trust to that header.
_FASTLY_CIDRS = [
    # Fastly IPv4 (subset that fronts crawlers/mirrors)
    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
    "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
    "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
    "185.31.16.0/22", "199.27.72.0/21",
    # Fastly IPv6
    "2a04:4e40::/32", "2a04:4e42::/32",
]

# Protected CDN / good-bot IP ranges; kept in lock-step with flood-report.sh's
# PROTECTED_CIDRS (Cloudflare's published ranges + a Fastly subset, and the IPv6
# prefixes). A dominant source inside one of these is a CDN that fronts good bots and
# perhaps your own site. Its requests still count, but it is marked exempt so it is
# never blocked. Over-refusing a block here is the safe failure.
_PROTECTED_CIDRS = _CLOUDFLARE_CIDRS + _FASTLY_CIDRS


def _build_nets(cidrs):
    nets = []
    for _c in cidrs:
        try:
            nets.append(ipaddress.ip_network(_c))
        except ValueError:
            pass
    return nets


_CLOUDFLARE_NETS = _build_nets(_CLOUDFLARE_CIDRS)
_PROTECTED_NETS = _build_nets(_PROTECTED_CIDRS)

# Good-bot User-Agent substrings (case-insensitive): crawlers, link unfurlers and
# uptime monitors. A blocked Discordbot or Slackbot silently kills every link preview
# of the site in those apps.
_GOOD_BOT_UA = (
    "discordbot", "googlebot", "bingbot", "applebot", "slackbot",
    "twitterbot", "facebookexternalhit", "telegrambot", "whatsapp",
    "linkedinbot", "redditbot", "embedly", "pinterest", "vkshare",
    "skypeuripreview", "bingpreview", "mastodon", "iframely", "opengraph",
    "snapchat", "yandexbot", "duckduckbot", "baiduspider", "uptime",
    "site24x7", "pingdom", "statuscake", "ahrefsbot", "semrushbot",
)


def _is_protected(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in _PROTECTED_NETS:
        if ip.version == net.version and ip in net:
            return True
    return False


def _is_cloudflare(ip_str):
    """True only when ip_str is a valid address inside a Cloudflare edge range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in _CLOUDFLARE_NETS:
        if ip.version == net.version and ip in net:
            return True
    return False


def _first_header(headers, name):
    """Caddy logs request headers as {"Name": ["value", ...]} (case as sent)."""
    if not isinstance(headers, dict):
        return ""
    lname = name.lower()
    for k, v in headers.items():
        if k.lower() == lname:
            if isinstance(v, list) and v:
                return str(v[0])
            if isinstance(v, str):
                return v
    return ""


def _bare_ip(value):
    """Strip a host:port / [v6]:port wrapper, returning the bare host string."""
    ip = str(value or "").strip()
    if ip.startswith("["):
        ip = ip[1:].split("]", 1)[0]
    elif ip.count(":") == 1:  # host:port (a lone colon ⇒ not bare IPv6)
        ip = ip.rsplit(":", 1)[0]
    return ip


def _client_ip(req):
    """Resolve the real client IP the way the edge does, but SAFELY.

    CF-Connecting-IP is attacker-controlled: any client can send it. Honor it ONLY
    when the request actually reached us from a Cloudflare edge (remote_ip inside the
    Cloudflare ranges); otherwise a direct CDN-bypass flooder could forge the header
    to steer the drop at an innocent third party. Falls back to Caddy's trusted-proxy-
    resolved client_ip, then remote_ip. Returns the canonical str(ip), or "" when the
    resolved value does not parse (the caller then skips the line).
    """
    if not isinstance(req, dict):
        return ""
    remote = _bare_ip(req.get("remote_ip"))
    candidate = _bare_ip(req.get("client_ip")) or remote
    if remote and _is_cloudflare(remote):
        cf = _bare_ip(_first_header(req.get("headers"), "Cf-Connecting-Ip"))
        if cf:
            candidate = cf
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def main():
    counts = {}
    bot_counts = {}  # requests per client IP that carry a good-bot User-Agent
    direct_counts = {}  # requests per client IP where it was the TCP peer itself
    total = 0
    lines_seen = 0
    # Read bytes and decode each line on its own, so a byte that is not UTF-8 spoils only
    # its own line (an attacker can put raw bytes in a log) and never stops the count.
    for braw in sys.stdin.buffer:
        raw = braw.decode("utf-8", "replace").strip()
        if not raw:
            continue
        lines_seen += 1
        # Caddy may prefix a container-runtime timestamp; find the JSON object.
        brace = raw.find("{")
        if brace < 0:
            continue
        try:
            rec = json.loads(raw[brace:])
        except (ValueError, TypeError):
            continue
        if not isinstance(rec, dict):
            continue
        # Only access-log entries ("handled request"); skip Caddy's own info lines.
        if rec.get("msg") != "handled request" and "access" not in str(rec.get("logger", "")):
            continue
        req = rec.get("request")
        if not isinstance(req, dict):
            continue
        ip = _client_ip(req)
        if not ip:
            continue
        counts[ip] = counts.get(ip, 0) + 1
        total += 1
        # Did this client connect to us itself? Only then can a drop at the box stop it.
        # An address taken from a header (CF-Connecting-IP, or X-Forwarded-For through a
        # trusted proxy) may be one the client wrote, and its packets come from the proxy.
        try:
            peer = str(ipaddress.ip_address(_bare_ip(req.get("remote_ip"))))
        except ValueError:
            peer = ""
        if peer == ip:
            direct_counts[ip] = direct_counts.get(ip, 0) + 1
        ua = _first_header(req.get("headers"), "User-Agent").lower()
        if ua and any(b in ua for b in _GOOD_BOT_UA):
            bot_counts[ip] = bot_counts.get(ip, 0) + 1

    top_ip = "-"
    top_count = 0
    for ip, c in counts.items():
        if c > top_count:
            top_count = c
            top_ip = ip
    share = (top_count * 100 // total) if total > 0 else 0
    exempt = 0
    if top_count and (
        _is_protected(top_ip)
        or bot_counts.get(top_ip, 0) * 2 > top_count
        or direct_counts.get(top_ip, 0) * 2 <= top_count
    ):
        exempt = 1
    print("%d %d %s %d %d %d" % (total, top_count, top_ip, share, lines_seen, exempt))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # nothing on stdout: the caller reads it as unreadable
        try:
            sys.stderr.write("flood-http-aggregate: %s\n" % exc)
        except Exception:
            pass
        sys.exit(1)
    sys.exit(0)
