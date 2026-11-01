# Mitigations

Four scripts you run by hand, as root, from `/opt/nethersec` once `install.sh` has put them
there. Each of the first three changes one thing, is safe to run again, and has a `--check`
that changes nothing; the snapshot script only prints. `install.sh` runs only the first one,
and only with `--with-applier`.

The first three are tested by offline harnesses in `host/test/` that mock Docker, nft,
systemctl and `/proc/modules`; the snapshot script has none. None has been run on a live server
as packaged here, so try each on one box and look before you roll it out.

## Docker live-restore

Without live-restore, a restart of dockerd or containerd stops every container, so a Docker
package upgrade (the applier's, or your own) is an outage.
[`docker-live-restore.sh`](../../host/docker-live-restore.sh) turns it on: it merges
`"live-restore": true` into `/etc/docker/daemon.json` (other keys kept, the old file backed up
beside it), checks the result with `dockerd --validate` before it replaces anything, and reloads
dockerd with SIGHUP, which restarts no container. It refuses on a swarm node, where live-restore
does not apply.

```sh
sudo bash /opt/nethersec/docker-live-restore.sh            # turn it on
sudo bash /opt/nethersec/docker-live-restore.sh --check    # 0 on, 1 off or no answer, 2 no Docker
```

Two limits. Docker documents live-restore for patch upgrades; it often holds across minor
versions too, but compare `docker ps` uptimes after a big jump. And while dockerd restarts,
Docker's embedded DNS (served by dockerd) does not answer, so a container opening a new
connection by service name can fail for those seconds. On a box where that could lose a write,
such as a database its clients reach by service name, upgrade Docker in a maintenance window and
hold its packages the rest of the time.

Check 8 of the detector cards a Docker box where live-restore is off.

## Drop IPv4 packets with IP options

CVE-2026-98432 (an IPv4 TCP use-after-free, CVSS 9.8, in every kernel since 4.4) is reached
only through a SYN carrying the Record Route or Timestamp IP option: the kernel keeps a copy of
the options with the half-open connection, and a race frees that copy while another CPU still
reads it. No normal client sends IP options, so
[`ipv4-options-drop.sh`](../../host/ipv4-options-drop.sh) drops every inbound IPv4 TCP packet
that carries them. That removes the trigger for every listener, plain TCP and Multipath TCP
alike, and restarts nothing. Keep it after the fixed kernel too: a server has no use for IP
options.

It writes its own nftables table (`ip nethersec_ipopt`, at the raw prerouting hook, before
Docker's rules) to `/etc/nethersec/ipv4-options-drop.nft`, checks it with `nft -c`, and installs
`nethersec-ipv4-options-drop.service`, which loads it now and at every boot before the network
comes up. Docker's, ufw's and fail2ban's tables are never touched. IPv6 is not affected by the
bug and is left alone.

```sh
sudo bash /opt/nethersec/ipv4-options-drop.sh            # turn it on
sudo bash /opt/nethersec/ipv4-options-drop.sh --check    # 0 on, 1 off; prints the drop count
sudo bash /opt/nethersec/ipv4-options-drop.sh --remove   # take it off
```

Check 10 of the detector runs `--check` every run on Ubuntu and cards a box where it is off,
including one where it was never turned on.

## Block network modules a server does not use

Any process, a container's included, that opens a socket of some family makes the kernel load
the module behind it, and from then on that module parses packets from the network. Many
critical kernel CVEs sit in modules a typical web server never uses: NFS and SunRPC, Ceph, SCTP,
SMB, the RDMA stack, NVMe and iSCSI over the network, Open vSwitch, IPVS, MPLS and a long tail of
old socket families. [`kernel-modules-block.sh`](../../host/kernel-modules-block.sh) writes
`/etc/modprobe.d/nethersec-blocked-modules.conf`, one `install <module> /bin/false` line per
module on its list, so the kernel refuses to load them, asked or on demand. That closes every
bug in those modules, fixed or not, with no reboot. Bugs in the core (TCP, UDP, fragments, the
bridge and veth) still need the fixed kernel.

A module loaded on the box when it runs is left out and named, so nothing running loses a
module. It unloads nothing and restarts nothing. The list leaves out hardware drivers, the
tunnels and IPsec that Docker, WireGuard or Tailscale may use, and the conntrack helpers other
than SIP's. It does list `macvlan`, `ipvlan` and `ovpn`: a box that uses one of them must take
it off the list.

**Check the list against your own boxes before you rely on it.** A module your box loads only
now and then (an NFS mount at backup time, say) would be blocked the next time it is wanted.
For each name in `BLOCKED` at the top of the script:

```sh
grep -c '^<name> ' /proc/modules     # 1 = loaded now
```

To let a module load again, take it off the list in your copy of the script and run it again.
When you test the block, note that a blocked module's dependencies still load (`modprobe sctp`
loads `udp_tunnel`), so prove it with `modprobe -n -v sctp`, which prints `install /bin/false`.

```sh
sudo bash /opt/nethersec/kernel-modules-block.sh            # turn it on
sudo bash /opt/nethersec/kernel-modules-block.sh --check    # 0 on, 1 off or out of date
sudo bash /opt/nethersec/kernel-modules-block.sh --remove   # take it off
```

## Firewall snapshots

[`firewall-snapshot.sh`](../../host/firewall-snapshot.sh) prints a box's whole firewall setup as
stable text: ufw, iptables and ip6tables (Docker's rules included), every other nftables table,
fail2ban's jails, the network sysctls and the non-loopback listeners. Counters and the
elements of every nftables set (fail2ban's banned addresses among them) are stripped, so an
unchanged box prints the same text twice. It changes nothing. Re-run it and diff after any
firewall change. The listeners come last, and the last line of the output is the box's
`HOSTSEC_LISTEN_ALLOW` line for check 12 (`tail -n 1` gives it).

```sh
sudo bash /opt/nethersec/firewall-snapshot.sh > "$(hostname).txt"
```

Keep the snapshots somewhere private, never in a public repo: they list open ports and
allow-lists.

## Removing them

`install.sh --uninstall` leaves these in place, since they protect the box on their own and need
nothing from `/opt/nethersec`; it prints how to take off the IP-options drop and the module
block. `install.sh --uninstall --purge` takes those two off before it removes `/etc/nethersec`.
Docker live-restore stays on either way. To turn it off, put back the backup the script printed
(`/etc/docker/daemon.json.bak.<time>-liverestore`; with no backup there was no file before, so
remove `daemon.json`) and run `sudo systemctl reload docker`.
