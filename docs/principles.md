# How nethersec decides what to tell you

Most security monitoring fails the same way: it sends so much that people stop reading it, and
then the one alert that mattered goes unread. nethersec is built around a few rules that keep the
alerts few and the silence trustworthy. Every part follows them, except where a rule below names
an exception, and a change that breaks one needs a very good reason.

## 1. Cannot read is never all-clear

A check that fails to read (apt is locked, the network is down, a feed returned garbage) sends
nothing about its own signal. It never reports a zero and never sends "fixed", because a false
"fixed" would close a real alert. Instead, on a server every detector check that could not read
folds into one `monitor-unreadable` alert, which clears once they can all read again. The flood
detector has its own (`monitor-unreadable-flood`), and the PC scanner raises its own once a
check has failed to read for more than 2 days. The reboot check is the exception: a lookup it
cannot finish marks the box "not checked" in the hub's weekly summary instead.

The same rule runs through the hub: a repo that cannot be read keeps what was open there (and
the status channel says so after two scans in a row), and an advisory source that is down marks
nothing fixed until it is back. A watch feed, or the container check, that has failed for a day
gets one "can't read" card.

## 2. Report changes, not states

A problem is reported when it starts and when it ends, not on every run. A problem that stays
open is raised again on a slow timer (every 6 hours for host and hub watch cards, hourly for a
flood, weekly on a PC), so one a person resolved before it was fixed comes back without becoming
noise. Repo advisory cards and advisory or KEV notices are not raised again: a repo card stays
open until the fix lands, and a notice until a person resolves it.

## 3. Page only when a person is needed now

Routine patching opens no card and pages nobody (at most a note in the status channel). A
pending security update that the system will install on its own tonight is not news. A page
means one of:

- auto-patching has stopped: a High or Critical fix stuck past its grace window, or the
  release-age applier failing or not finishing its runs,
- a vulnerability that is being exploited in the wild (CISA's list) and matches something you
  list or run,
- a new critical advisory in a repo's runtime dependencies or for a component in `watch.json`,
  or a malicious package release,
- a critical Linux kernel bug reachable over the network with no Ubuntu fix shipped yet,
- an attack in progress, from a check you set to critical (the SSH, error-log and flood checks
  are quiet cards by default),
- a service down, from an uptime report (critical unless it says otherwise).

Everything else is a quiet card or a note you can read today.

## 4. A box cannot close its own security alert

When a box says a security problem is fixed, the hub adds that to the card and waits for a
person (a server admin or someone with the watcher role) to press Resolve. A box that was taken
over can say anything about itself, so it must not be able to quietly clear the alert about it.
A container image card works the same way: once the boxes' package lists show the fix or another
image, or a box reports the container gone, the card says so, is not sent again, and waits for
Resolve. Uptime cards are not security alerts: the box's "resolved" closes them.

## 5. Anything that acts ships dark

The parts that change a system on their own (the package applier, the flood blocker) start in
dry-run. The flood blocker logs the drops it would make. The applier in dry-run still holds and
releases packages as usual, so the waiting already applies, and logs the set it would install.
You arm each one per box (`HOSTSEC_APPLY_DRYRUN=0`, `HOSTSEC_FLOOD_MITIGATE=1`) after watching
it decide correctly for a while. The mitigation scripts act only when a person runs them, and
`install.sh --with-applier` turns on Docker live-restore where Docker is installed.

## 6. Fail toward patched

The applier holds some updates back to let them age. If you turn it off (a kill switch file or
`HOSTSEC_APPLY_ENABLED=0`), its next run releases every hold it made; `install.sh --uninstall`
does the same. A hold with nobody managing it is worse than no hold.

## 7. Wait for new versions, but not for security fixes

A new release of a package can be hijacked or broken; most such releases are caught within days.
So with the applier armed, ordinary updates (Ubuntu's `-updates` and third-party repos) install
only once the box has seen that exact version for a few days (4 by default). Ubuntu's own
security updates do not wait (unless you set `HOSTSEC_APPLY_BLANKET=1`), and neither does a
short list of core packages from Ubuntu (OpenSSH, libc, OpenSSL, the kernel and the like),
because delaying a known fix only lengthens the exposure.

## 8. Move fast on obvious signals, only alert on ambiguous ones

A security response should not sit behind a long fixed timer. When a signal is unambiguous, act
at once: once armed, the flood blocker drops an IPv4 address in the same run (it runs every
minute) that sees it holding most of a flood (by default 60 percent of the established
connections or 55 percent of the HTTP requests). A signal that could be real users, such as a
flood with no single source, is not acted on: it only alerts. The safety rails: an allowlist
(yours, plus CDN and good-bot ranges), no drop of a local, private or the box's own address or
of an HTTP client known only from a header, a cap on drops per hour (6 by default), and drops
that expire on their own (after 60 minutes by default).

## 9. Scripts never crash a timer, and never leak a key

The scripts the timers run (the detector, the applier, the flood detector) always exit 0. Their
own errors go to the journal or a quiet "can't read" card, never a page. The exception is the
applier, because patching has stopped: an apply or its simulation that fails pages, and so does
the detector's backstop when the applier has not finished a run for 3 hours. Keys live in files
only their owner can read. On a server they reach `curl` on stdin (`curl -K -`), never on a
command line where other users can see them.
