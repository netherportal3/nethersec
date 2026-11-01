#!/usr/bin/env python3
# apt-introspect.py: authoritative enumeration of upgradable packages for
# apply-aged-upgrades.sh (the write-side release-age gate).
#
# Emits one TAB-separated row per UPGRADABLE, installed package:
#
#   name  candidate_version  arch  origin  site  archive  trusted  is_security  source
#
# `source` is the source-package name of the candidate. Binaries built from one source
# (e.g. krb5 -> libkrb5-3 + libk5crypto3 + libkrb5support0 + libgssapi-krb5-2) ship as a
# single upload with strict `(= exact-version)` interdeps, so the applier must treat them
# as one lockstep group; fast-pathing a crown-jewel member while a sibling is held makes
# `apt-get --only-upgrade` of the subset impossible ("held broken packages").
#
# Why a Python helper and not `apt-get -s dist-upgrade` parsing:
#   1. AUTHORITATIVE ORIGIN + TRUST. Gate/fast-path decisions hinge on whether the
#      candidate comes from a TRUSTED (GPG-signed) origin, and which one. Only
#      python3-apt exposes candidate.origins[].trusted / .origin / .site / .archive.
#      A hostile third-party repo can self-label its suite "noble-security"; the
#      `-s` suite token would trust it, the signed-origin check does not.
#   2. HOLD-INDEPENDENT ENUMERATION. "upgradable" here means candidate != installed,
#      computed from versions directly; so a package we have `apt-mark hold`ed
#      STILL appears. `apt-get -s dist-upgrade` hides held packages as "kept back",
#      which would make an aged-in-but-held package silently vanish and never apply.
#
# Read-only: opens the EXISTING apt cache (no `apt-get update`, no network). Trust
# is fail-closed at the caller: this prints nothing and exits 3 if python3-apt is
# missing or the cache can't open, so the applier treats "can't resolve" as
# untrusted rather than guessing.
import sys

try:
    import apt  # python3-apt (present by default on Ubuntu; apt itself uses it)
except Exception as exc:  # pragma: no cover - environment guard
    sys.stderr.write("apt-introspect: python3-apt unavailable: %s\n" % exc)
    sys.exit(3)


def main():
    try:
        cache = apt.Cache()
    except Exception as exc:
        sys.stderr.write("apt-introspect: cannot open apt cache: %s\n" % exc)
        sys.exit(3)

    rows = []
    for pkg in cache:
        if not pkg.is_installed:
            continue
        cand = pkg.candidate
        inst = pkg.installed
        if cand is None or inst is None:
            continue
        if cand.version == inst.version:
            continue  # candidate == installed -> not upgradable

        origins = list(cand.origins or [])
        # A version is TRUSTED if any origin providing it is signed/trusted.
        trusted = any(bool(o.trusted) for o in origins)
        # Label from a trusted origin when one exists, else the first origin.
        chosen = next((o for o in origins if o.trusted), origins[0] if origins else None)
        origin = (chosen.origin or "") if chosen else ""
        site = (chosen.site or "") if chosen else ""
        archive = (chosen.archive or "") if chosen else ""
        # Security if the candidate is available from ANY *-security pocket.
        is_security = 1 if any((o.archive or "").endswith("-security") for o in origins) else 0

        arch = pkg.architecture() or ""
        # Source-package name of the candidate (drives lockstep grouping in the applier).
        # `.source_name` is a property that can raise (not just AttributeError) when the
        # record can't be fetched; fall back to the binary name on ANY failure so the
        # whole helper never aborts over one package's metadata.
        try:
            source = cand.source_name or pkg.name
        except Exception:
            source = pkg.name
        # Sanitise: no field may contain a tab/newline (versions/names never do,
        # but be defensive so the TSV contract can't be broken by odd metadata).
        fields = [pkg.name, cand.version, arch, origin, site, archive,
                  "1" if trusted else "0", str(is_security), source]
        fields = [f.replace("\t", " ").replace("\n", " ") for f in fields]
        rows.append("\t".join(fields))

    if rows:
        sys.stdout.write("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
