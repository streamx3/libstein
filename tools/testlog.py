#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Maintains doc/testing/test-log.md: one row per test run per environment, with
the UTC time, the short commit id, the tag (if the commit carries one), the
platform, the build, what was exercised, the result and a link or note as
evidence. The table between the testlog markers is regenerated on every call,
newest first; rows outside the markers are left alone.

  tools/testlog.py ci [--runs N] [--branch B]   pull completed GitHub Actions CI runs (needs `gh`)
  tools/testlog.py add --platform P --build B --scope S --result pass|fail|partial [--evidence TEXT]
                                                record a run made by hand (local machine, real hardware)
  tools/testlog.py render                       rewrite the table from the rows already in the file
"""
import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "doc", "testing", "test-log.md")
BEGIN, END = "<!-- testlog:begin -->", "<!-- testlog:end -->"
COLUMNS = ["When (UTC)", "Commit", "Tag", "Platform", "Build", "Scope", "Result", "Evidence"]

# What the CI workflow exercises per runner (see .github/workflows/ci.yml).
CI_BUILD = {
    "ubuntu-24.04": "GCC 13, Debug, ASan+UBSan, -Werror",
    "macos-14": "AppleClang, Debug, -Werror",
    "windows-2022": "MSVC 2022, Debug, -Werror",
}
CI_PLATFORM = {
    "ubuntu-24.04": "Linux x86-64 (GitHub runner, images only)",
    "macos-14": "macOS 14 arm64 (GitHub runner, images only)",
    "windows-2022": "Windows Server 2022 x86-64 (GitHub runner, images only)",
}
CI_SCOPE = {
    "ubuntu-24.04": "all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair)",
    "macos-14": "all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair)",
    "windows-2022": "all 13 ctest suites against fixtures; WinFsp mount required",
}


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=False).stdout.strip()


def tag_of(sha):
    tags = git("tag", "--points-at", sha).split()
    return ", ".join(tags) if tags else "–"


def repo_slug():
    url = git("remote", "get-url", "origin")
    m = re.search(r"github\.com[:/]([^/]+)/([^/.]+)", url)
    return "%s/%s" % (m.group(1), m.group(2)) if m else None


def gh_api(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("gh api %s failed: %s" % (path, r.stderr.strip()))
    return json.loads(r.stdout)


def read_rows():
    text = open(LOG, encoding="utf-8").read()
    if BEGIN not in text or END not in text:
        sys.exit("markers %s / %s missing in %s" % (BEGIN, END, LOG))
    head, rest = text.split(BEGIN, 1)
    table, tail = rest.split(END, 1)
    rows = []
    for line in table.strip().splitlines():
        if not line.startswith("|") or set(line.replace("|", "").strip()) <= set("-: ") or line.startswith("| When"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == len(COLUMNS):
            rows.append(dict(zip(COLUMNS, cells)))
    return head, rows, tail


def write_rows(head, rows, tail):
    seen, unique = set(), []
    for r in rows:
        key = (r["When (UTC)"], r["Commit"], r["Platform"], r["Evidence"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)
    unique.sort(key=lambda r: r["When (UTC)"], reverse=True)
    lines = ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    for r in unique:
        lines.append("| " + " | ".join(r[c].replace("|", "\\|") for c in COLUMNS) + " |")
    open(LOG, "w", encoding="utf-8").write(head + BEGIN + "\n" + "\n".join(lines) + "\n" + END + tail)
    return len(unique)


def when_of(iso):
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M")


def cmd_ci(args):
    slug = repo_slug() or sys.exit("origin is not a GitHub remote")
    branch = args.branch or git("rev-parse", "--abbrev-ref", "HEAD")
    runs = gh_api("repos/%s/actions/workflows/ci.yml/runs?branch=%s&status=completed&per_page=%d" % (slug, branch, args.runs))["workflow_runs"]
    head, rows, tail = read_rows()
    added = 0
    for run in runs:
        for job in gh_api("repos/%s/actions/runs/%d/jobs" % (slug, run["id"]))["jobs"]:
            if job["conclusion"] in (None, "skipped", "cancelled") or not job.get("completed_at"):
                continue
            os_name = job["name"]
            evidence = "[CI #%d %s](%s)" % (run["run_number"], os_name, job["html_url"])
            if any(r["Evidence"] == evidence for r in rows):
                continue
            rows.append({
                "When (UTC)": when_of(job["completed_at"]),
                "Commit": run["head_sha"][:7],
                "Tag": tag_of(run["head_sha"]),
                "Platform": CI_PLATFORM.get(os_name, os_name),
                "Build": CI_BUILD.get(os_name, "see workflow"),
                "Scope": CI_SCOPE.get(os_name, "ctest"),
                "Result": "pass" if job["conclusion"] == "success" else job["conclusion"],
                "Evidence": evidence,
            })
            added += 1
    total = write_rows(head, rows, tail)
    print("added %d rows (%d total)" % (added, total))


def cmd_add(args):
    head, rows, tail = read_rows()
    sha = git("rev-parse", "HEAD")
    rows.append({
        "When (UTC)": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "Commit": sha[:7],
        "Tag": tag_of(sha),
        "Platform": args.platform,
        "Build": args.build,
        "Scope": args.scope,
        "Result": args.result,
        "Evidence": args.evidence or "operator record",
    })
    print("%d rows" % write_rows(head, rows, tail))


def cmd_render(_args):
    head, rows, tail = read_rows()
    print("%d rows" % write_rows(head, rows, tail))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    ci = sub.add_parser("ci")
    ci.add_argument("--runs", type=int, default=10)
    ci.add_argument("--branch")
    ci.set_defaults(fn=cmd_ci)
    add = sub.add_parser("add")
    for name in ("platform", "build", "scope"):
        add.add_argument("--" + name, required=True)
    add.add_argument("--result", required=True, choices=["pass", "fail", "partial"])
    add.add_argument("--evidence")
    add.set_defaults(fn=cmd_add)
    sub.add_parser("render").set_defaults(fn=cmd_render)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
