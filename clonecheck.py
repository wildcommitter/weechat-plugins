# -*- coding: utf-8 -*-
#
# clonecheck.py
#
# A lean clone detector for WeeChat.
#
# When someone JOINs a channel, their host is compared ONLY against the
# hosts of users already in that channel's nicklist. If a match is found
# the join is reported as a possible clone. This deliberately avoids the
# classic clone_scanner performance problem of re-walking the entire
# nicklist for *every* user on *every* join (O(joins x nicks)); here each
# join is a single pass that stops at the first match.
#
# Parsing uses WeeChat's own irc_message_parse (no manual string slicing),
# which is the robust approach -- hand-rolled splitting of IRC lines is a
# known source of subtle bugs.
#
# Commands:
#   /clonecheck scan [#channel]   -- manually scan a channel for clones
#   /clonecheck status            -- print version + config diagnostics
#
# License: 0BSD -- do whatever you want.

from __future__ import print_function

import fnmatch
import time

try:
    import weechat
except ImportError:
    print("This script must be run inside WeeChat. https://weechat.org/")
    raise SystemExit(1)

SCRIPT_NAME = "clonecheck"
SCRIPT_AUTHOR = "generated"
SCRIPT_VERSION = "1.2"
SCRIPT_LICENSE = "0BSD"
SCRIPT_DESC = "Lean clone detector (host match on join, no full rescans)"

SETTINGS = {
    # "host"  -> compare only the host portion (user@HOST)
    # "ident" -> compare ident@host (stricter; misclassifies less but
    #            also misses clones that vary their ident)
    "compare": (
        "host",
        "What to compare: host / ident",
    ),
    # Comma-separated servers to skip (host sharing is normal on some,
    # e.g. bouncers, twitch, bitlbee).
    "excluded_servers": (
        "",
        "Servers to skip (comma separated, empty = none)",
    ),
    # Comma-separated channels to skip (e.g. "#bigchannel,#twitchstream").
    "excluded_channels": (
        "",
        "Channels to skip (comma separated, empty = none)",
    ),
    # Where to print reports:
    #   "private" -> a dedicated clonecheck buffer (default; recommended)
    #   "core"    -> the core WeeChat buffer
    #   "buffer"  -> the channel buffer where the join happened
    "report_to": (
        "private",
        "Where to print clone reports: private / core / buffer",
    ),
    # --- Outbound NOTICE (OFF by default; messaging strangers based on a
    #     shared-host heuristic is spammy and false-positive prone) ---
    # "off"      -> never send any NOTICE (default; just log to you)
    # "joiner"   -> NOTICE the user who just joined
    # "existing" -> NOTICE the existing matching nick(s)
    # "both"     -> NOTICE joiner and existing matches
    "notice_target": (
        "off",
        "Who to NOTICE on a clone join: off / joiner / existing / both "
        "(off strongly recommended; see notice_caveat)",
    ),
    "notice_text": (
        "Heads up: a same-host connection just joined ${channel}.",
        "NOTICE text. ${nick} ${channel} ${others} ${server} expand.",
    ),
    # Only notify when the joining nick matches one of these (comma
    # separated, * wildcards ok). Empty = (with notice on) anyone --
    # discouraged. Strongly recommended to set a watch list.
    "notice_only_nicks": (
        "",
        "Restrict NOTICE to these joining nicks (csv, * ok). "
        "Empty = everyone (not recommended).",
    ),
    # Hard rate limit: minimum seconds between NOTICEs to the same nick.
    "notice_cooldown_seconds": (
        "300",
        "Minimum seconds between NOTICEs to the same target",
    ),
    # Safety acknowledgement. The script will REFUSE to send any NOTICE
    # until this is flipped to "on", so it can never message strangers
    # by accident just because notice_target was set.
    "notice_caveat": (
        "off",
        "You must set this to 'on' to confirm you understand NOTICEs "
        "may hit innocent users sharing a host (VPN/NAT/Tor/bouncer)",
    ),
    # Verbose debug to the core buffer.
    "debug": (
        "off",
        "Verbose debug to core buffer: on / off",
    ),
}

# last NOTICE time per "server.nick" for cooldown enforcement
_last_notice = {}
_cc_buffer = ""


def log(msg):
    weechat.prnt("", "%s\t%s" % (SCRIPT_NAME, msg))


def dbg(msg):
    if weechat.config_get_plugin("debug") == "on":
        log("[debug] %s" % msg)


def _cc_input_cb(data, buffer, input_data):
    return weechat.WEECHAT_RC_OK


def _cc_close_cb(data, buffer):
    global _cc_buffer
    _cc_buffer = ""
    return weechat.WEECHAT_RC_OK


def ensure_cc_buffer():
    """Dedicated read-only buffer for clone alerts (same pattern as the
    ignore_notify log buffer: quiet, no hotlist spam, survives reloads)."""
    global _cc_buffer
    if _cc_buffer:
        return _cc_buffer
    existing = weechat.buffer_search("python", "clonecheck")
    if existing:
        _cc_buffer = existing
        return _cc_buffer
    _cc_buffer = weechat.buffer_new(
        "clonecheck", "_cc_input_cb", "", "_cc_close_cb", ""
    )
    if _cc_buffer:
        weechat.buffer_set(_cc_buffer, "title",
                           "Clone detections (read-only)")
        weechat.buffer_set(_cc_buffer, "notify", "0")
    return _cc_buffer


def opt(key):
    return weechat.config_get_plugin(key)


def _csv(key):
    raw = (opt(key) or "").strip()
    return [x.strip() for x in raw.split(",") if x.strip()]


def host_key(host):
    """Reduce a 'user@host' (or full 'nick!user@host') to the comparison
    key according to the 'compare' setting.

    irc_message_parse's 'host' field is the 'user@host' portion. We never
    string-slice an IRC line by hand; we only normalise this already
    parsed value.
    """
    if not host:
        return ""

    # strip a leading 'nick!' if present (defensive; parse usually gives
    # just user@host for the 'host' key)
    if "!" in host:
        host = host.split("!", 1)[1]

    if opt("compare") == "ident":
        # ident@host as-is (case-insensitive)
        return host.lower()

    # host only: drop the ident before '@'
    if "@" in host:
        return host.split("@", 1)[1].lower()
    return host.lower()


def iter_channel_nicks(server, channel):
    """Yield (nick, host_key) for every user currently in the channel's
    nicklist. Host comes from the irc nicklist infolist, normalised via
    host_key(). Single pass; caller decides when to stop.
    """
    infolist = weechat.infolist_get(
        "irc_nick", "", "%s,%s" % (server, channel)
    )
    if not infolist:
        return

    try:
        while weechat.infolist_next(infolist):
            n = weechat.infolist_string(infolist, "name")
            h = weechat.infolist_string(infolist, "host")  # user@host
            yield n, host_key(h)
    finally:
        weechat.infolist_free(infolist)


def find_clones_of(server, channel, target_nick, target_hostkey):
    """Return list of existing nicks in channel sharing target_hostkey
    (excluding the target nick itself). Stops collecting nothing early --
    we want all matches for a useful report -- but this is still a single
    O(nicks) pass for THIS join only.
    """
    if not target_hostkey:
        return []
    matches = []
    for n, hk in iter_channel_nicks(server, channel):
        if n == target_nick:
            continue
        if hk and hk == target_hostkey:
            matches.append(n)
    return matches


def report(server, channel, joining_nick, host, clones):
    dest = opt("report_to")
    others = ", ".join(clones)
    msg = ("clone? %s (%s) on %s%s shares host with: %s"
           % (joining_nick, host, server,
              "/" + channel if channel else "", others))

    if dest == "buffer":
        buf = weechat.info_get("irc_buffer", "%s,%s" % (server, channel))
        if buf:
            weechat.prnt(buf, "%s%s"
                         % (weechat.prefix("network"), msg))
            return
        # fall through to private if channel buffer not found

    if dest == "core":
        log(msg)
        return

    # default: "private" -> dedicated read-only clonecheck buffer
    buf = ensure_cc_buffer()
    if buf:
        weechat.prnt_date_tags(
            buf, 0, "notify_message",
            "%s%s" % (weechat.prefix("network"), msg)
        )
    else:
        log(msg)  # last-resort fallback


def _cooldown_ok(server, target):
    try:
        cd = float(opt("notice_cooldown_seconds"))
    except (TypeError, ValueError):
        cd = 300.0
    key = "%s.%s" % (server, target)
    last = _last_notice.get(key)
    now = time.time()
    if last is not None and (now - last) < cd:
        return False
    _last_notice[key] = now
    return True


def _send_notice(server, target, text):
    weechat.command(
        "", "/quote -server %s NOTICE %s :%s" % (server, target, text)
    )
    dbg("NOTICE -> %s on %s" % (target, server))


def maybe_notice(server, channel, joining_nick, clones):
    """Send NOTICE(s) only if every safety gate passes. Defaults make
    this a no-op: notice_target=off and notice_caveat=off both block it.
    """
    target_mode = opt("notice_target")
    if target_mode == "off":
        return

    # hard safety interlock: refuse unless explicitly acknowledged
    if opt("notice_caveat") != "on":
        dbg("notice_target set but notice_caveat!=on -> refusing to send. "
            "Set plugins.var.python.clonecheck.notice_caveat on to enable.")
        return

    # optional watch list on the JOINING nick
    watch = _csv("notice_only_nicks")
    if watch:
        if not any(fnmatch.fnmatch(joining_nick.lower(), w.lower())
                   for w in watch):
            dbg("joiner %s not in notice_only_nicks -> skip notice"
                % joining_nick)
            return

    others = ", ".join(clones)
    text = (opt("notice_text")
            .replace("${nick}", joining_nick)
            .replace("${channel}", channel)
            .replace("${others}", others)
            .replace("${server}", server))

    targets = []
    if target_mode in ("joiner", "both"):
        targets.append(joining_nick)
    if target_mode in ("existing", "both"):
        targets.extend(clones)

    for t in targets:
        if _cooldown_ok(server, t):
            _send_notice(server, t, text)
        else:
            dbg("cooldown active for %s -> notice suppressed" % t)


def join_signal_cb(data, signal, signal_data):
    """Hooked on '*,irc_in2_join'. JOIN is purely informational, so a
    signal (observe-only, never modifies) is the correct hook here --
    unlike privmsg+ignore which needed a modifier to run before filtering.

    signal     -> 'server,irc_in2_join'
    signal_data-> raw IRC line, e.g.
                  ':nick!user@host JOIN #channel'
    """
    try:
        server = signal.split(",", 1)[0]

        if server in _csv("excluded_servers"):
            return weechat.WEECHAT_RC_OK

        parsed = weechat.info_get_hashtable(
            "irc_message_parse",
            {"message": signal_data, "server": server},
        )
        nick = parsed.get("nick", "")
        host = parsed.get("host", "")          # user@host
        channel = parsed.get("channel", "")
        if not channel:
            # some servers put the channel in 'arguments'
            channel = (parsed.get("arguments", "") or "").lstrip(":").strip()

        dbg("JOIN server=%s nick=%s host=%s chan=%s"
            % (server, nick, host, channel))

        if not nick or not channel:
            return weechat.WEECHAT_RC_OK

        if channel in _csv("excluded_channels"):
            return weechat.WEECHAT_RC_OK

        # ignore our own joins
        mynick = weechat.info_get("irc_nick", server)
        if mynick and nick.lower() == mynick.lower():
            return weechat.WEECHAT_RC_OK

        hk = host_key(host)
        if not hk:
            dbg("no host on join (no host-in-names cap?) -> skip")
            return weechat.WEECHAT_RC_OK

        clones = find_clones_of(server, channel, nick, hk)
        if clones:
            report(server, channel, nick, host, clones)
            maybe_notice(server, channel, nick, clones)
        else:
            dbg("no clones for %s (%s) in %s" % (nick, hk, channel))

    except Exception as exc:
        log("error in join callback: %s" % exc)

    return weechat.WEECHAT_RC_OK


def scan_channel(server, channel):
    """Manual scan: group all current nicks by host_key, report any
    host_key with >1 nick. One pass to build the map, then report.
    """
    by_host = {}
    for n, hk in iter_channel_nicks(server, channel):
        if not hk:
            continue
        by_host.setdefault(hk, []).append(n)

    found = False
    for hk, nicks in by_host.items():
        if len(nicks) > 1:
            found = True
            log("clones in %s/%s [%s]: %s"
                % (server, channel, hk, ", ".join(sorted(nicks))))
    if not found:
        log("no clones found in %s/%s" % (server, channel))


def clonecheck_cmd_cb(data, buffer, args):
    argv = (args or "").strip().split()
    sub = argv[0].lower() if argv else "status"

    if sub == "status":
        log("--- clonecheck status (v%s) ---" % SCRIPT_VERSION)
        log("compare=%s report_to=%s debug=%s"
            % (opt("compare"), opt("report_to"), opt("debug")))
        log("excluded_servers=%s excluded_channels=%s"
            % (opt("excluded_servers") or "(none)",
               opt("excluded_channels") or "(none)"))
        nt = opt("notice_target")
        ack = opt("notice_caveat")
        if nt == "off":
            log("NOTICE: disabled (notice_target=off) -- log only")
        elif ack != "on":
            log("NOTICE: BLOCKED -- notice_target=%s but "
                "notice_caveat=off (safety interlock). No NOTICEs sent."
                % nt)
        else:
            log("NOTICE: ACTIVE -> target=%s cooldown=%ss watch=%s"
                % (nt, opt("notice_cooldown_seconds"),
                   opt("notice_only_nicks") or "EVERYONE(!)"))
        log("--- end status ---")
        return weechat.WEECHAT_RC_OK

    if sub == "scan":
        # /clonecheck scan [#channel]   (defaults to current buffer)
        server = weechat.buffer_get_string(buffer, "localvar_server")
        if len(argv) > 1:
            channel = argv[1]
        else:
            channel = weechat.buffer_get_string(buffer, "localvar_channel")
        if not server or not channel:
            log("scan: run this from a channel buffer, or "
                "use /clonecheck scan #channel from that server.")
            return weechat.WEECHAT_RC_OK
        scan_channel(server, channel)
        return weechat.WEECHAT_RC_OK

    log("usage: /clonecheck scan [#channel] | /clonecheck status")
    return weechat.WEECHAT_RC_OK


if __name__ == "__main__":
    if weechat.register(
        SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION,
        SCRIPT_LICENSE, SCRIPT_DESC, "", "",
    ):
        for key, (default, desc) in SETTINGS.items():
            if not weechat.config_is_set_plugin(key):
                weechat.config_set_plugin(key, default)
            weechat.config_set_desc_plugin(
                key, "%s (default: \"%s\")" % (desc, default)
            )

        weechat.hook_signal("*,irc_in2_join", "join_signal_cb", "")

        if opt("report_to") == "private":
            ensure_cc_buffer()

        weechat.hook_command(
            "clonecheck",
            "Lean clone detector: scan a channel or show status",
            "scan [#channel] | status",
            "  scan: check a channel for users sharing a host\n"
            "status: print version and current settings\n\n"
            "Tip: clone detection only works when the server sends\n"
            "hosts in the nicklist (most do). It only catches users\n"
            "sharing the SAME host -- VPN/bouncer/IP changes evade it.",
            "scan || status",
            "clonecheck_cmd_cb",
            "",
        )

        log("loaded v%s. compare=%s. /clonecheck status for details."
            % (SCRIPT_VERSION, opt("compare")))
