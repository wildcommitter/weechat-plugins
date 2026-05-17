# -*- coding: utf-8 -*-
#
# ignore_notify.py
#
# When someone on your WeeChat /ignore list messages you (private message
# and/or mentions you in a channel), automatically send them a one-time
# notice that their messages are being filtered.
#
# WeeChat's /ignore is purely client-side: the ignored person normally has
# no idea. This script optionally tells them. Use responsibly -- announcing
# an ignore is often considered rude in IRC culture.
#
# Requires: WeeChat >= 1.0  (uses irc_ignore infolist + irc_in2_privmsg signal)
#
# License: public domain / 0BSD -- do whatever you want with it.

from __future__ import print_function

import re
import time

try:
    import weechat
except ImportError:
    print("This script must be run inside WeeChat.")
    print("Get WeeChat at: https://weechat.org/")
    raise SystemExit(1)

SCRIPT_NAME = "ignore_notify"
SCRIPT_AUTHOR = "generated"
SCRIPT_VERSION = "1.4"
SCRIPT_LICENSE = "0BSD"
SCRIPT_DESC = "Notify ignored users (once) that they are being ignored"

# ---------------------------------------------------------------------------
# Configuration (change with: /set plugins.var.python.ignore_notify.<key>)
# ---------------------------------------------------------------------------
SETTINGS = {
    # "pm", "mention", or "both"
    "notify_on": (
        "both",
        "When to notify an ignored user: pm / mention / both",
    ),
    # "session"  -> notify each nick once until WeeChat (or script) restarts
    # "cooldown" -> notify again only after cooldown_minutes have passed
    # "always"   -> notify on every message (noisy, not recommended)
    "frequency": (
        "session",
        "How often to notify each person: session / cooldown / always",
    ),
    # Minutes between repeat notifications when frequency = cooldown
    "cooldown_minutes": (
        "15",
        "Minutes before the same person can be notified again "
        "(only used when frequency = cooldown)",
    ),
    # Message sent to the ignored person. ${nick} and ${mynick} are expanded.
    "message": (
        "Heads up: your messages aren't reaching me -- you're on my filter list.",
        "Text sent to the ignored user (${nick}, ${mynick} supported)",
    ),
    # How to send it: "notice" (IRC NOTICE) or "privmsg" (regular message)
    "method": (
        "notice",
        "How to send the heads-up: notice / privmsg",
    ),
    # Comma-separated list of server names to act on; empty = all servers
    "servers": (
        "",
        "Restrict to these servers (comma separated, empty = all)",
    ),
    # Log every ignored PM/mention to a dedicated buffer
    "log_buffer": (
        "on",
        "Log ignored PMs/mentions to a dedicated buffer: on / off",
    ),
    # Also send the heads-up notice, or only log silently
    "send_notice": (
        "on",
        "Send the heads-up message to the ignored user: on / off "
        "(off = log only, never reply)",
    ),
    # Verbose debug logging to the core buffer
    "debug": (
        "off",
        "Verbose debug to core buffer (logs every privmsg seen): on / off",
    ),
}

# the dedicated log buffer pointer (filled in at register time)
_log_buffer = ""

# last time (epoch seconds) we notified a nick: { "server.nick": float }
_notified = {}


def log(msg):
    weechat.prnt("", "%s\t%s" % (SCRIPT_NAME, msg))


def buffer_input_cb(data, buffer, input_data):
    # read-only log buffer: ignore typed input
    return weechat.WEECHAT_RC_OK


def buffer_close_cb(data, buffer):
    global _log_buffer
    _log_buffer = ""
    return weechat.WEECHAT_RC_OK


def ensure_log_buffer():
    """Return the log buffer pointer, creating it if needed."""
    global _log_buffer
    if _log_buffer:
        return _log_buffer

    existing = weechat.buffer_search("python", "ignore_log")
    if existing:
        _log_buffer = existing
        return _log_buffer

    _log_buffer = weechat.buffer_new(
        "ignore_log",
        "buffer_input_cb",
        "",
        "buffer_close_cb",
        "",
    )
    if _log_buffer:
        weechat.buffer_set(_log_buffer, "title",
                           "Ignored PMs / mentions (read-only log)")
        weechat.buffer_set(_log_buffer, "localvar_set_no_log", "0")
        weechat.buffer_set(_log_buffer, "notify", "0")
    return _log_buffer


def log_to_buffer(server, nick, kind, target, body):
    """kind is 'PM' or 'MENTION'. target is the channel for mentions."""
    if get_opt("log_buffer") != "on":
        return
    buf = ensure_log_buffer()
    if not buf:
        return

    if kind == "PM":
        where = "%s (PM)" % server
    else:
        where = "%s %s" % (server, target)

    weechat.prnt_date_tags(
        buf, 0, "notify_message",
        "%s%s\t%s%s%s: %s" % (
            weechat.color("chat_prefix_network"),
            where,
            weechat.color("chat_nick"),
            nick,
            weechat.color("reset"),
            body,
        ),
    )


def get_opt(key):
    return weechat.config_get_plugin(key)


def server_allowed(server):
    raw = get_opt("servers").strip()
    if not raw:
        return True
    allowed = [s.strip() for s in raw.split(",") if s.strip()]
    return server in allowed


def _wc_match(mask, value):
    """Wildcard match (WeeChat * / ? semantics), case-insensitive."""
    if not value:
        return False
    if "*" not in mask and "?" not in mask:
        effective = "*%s*" % mask
    else:
        effective = mask
    return weechat.string_match(value, effective, 0) == 1


def _mask_match(mask, value):
    """Match a single WeeChat /ignore mask against a value.

    WeeChat's /ignore accepts EITHER a POSIX-ish regular expression OR a
    plain wildcard mask. So we mirror that: try the mask as a regex first
    (case-insensitive, like /ignore), and if it isn't a valid regex fall
    back to wildcard matching. This handles both 'bob*' style masks and
    '^bob$' / regex-style masks like the one the user actually has.
    """
    if not value:
        return False

    try:
        if re.search(mask, value, re.IGNORECASE):
            return True
        # valid regex but no match -> still allow a wildcard interpretation
        # only when the mask has no regex-only metacharacters, to avoid
        # double-counting. Bare names fall through to _wc_match below.
    except re.error:
        # not a valid regex: treat purely as a wildcard mask
        return _wc_match(mask, value)

    # regex compiled but didn't match; if the mask looks like a plain
    # name/wildcard (no anchors or regex metachars), also try wildcard.
    if not any(c in mask for c in "^$[]()\\|+"):
        return _wc_match(mask, value)
    return False


def is_ignored(server, nick, host):
    """Return True if (server, nick/host) matches a WeeChat /ignore entry.

    Mirrors WeeChat's own /ignore behaviour: each mask is matched as a
    regex first, then as a wildcard, against both the nick and the full
    nick!user@host form.
    """
    target_nick = nick or ""
    target_full = host or target_nick
    if host and "!" not in host and nick:
        target_full = "%s!%s" % (nick, host)

    infolist = weechat.infolist_get("irc_ignore", "", "")
    if not infolist:
        return False

    matched = False
    try:
        while weechat.infolist_next(infolist):
            ig_server = weechat.infolist_string(infolist, "server")
            mask = weechat.infolist_string(infolist, "mask")

            if ig_server and ig_server != "*" and ig_server != server:
                continue
            if not mask:
                continue

            if _mask_match(mask, target_nick) or _mask_match(mask, target_full):
                matched = True
                break
    finally:
        weechat.infolist_free(infolist)

    return matched


def already_notified(server, nick):
    freq = get_opt("frequency")
    if freq == "always":
        return False

    key = "%s.%s" % (server, nick)
    last = _notified.get(key)
    if last is None:
        return False

    if freq == "session":
        return True

    if freq == "cooldown":
        try:
            cooldown = float(get_opt("cooldown_minutes")) * 60.0
        except ValueError:
            cooldown = 15 * 60.0
        return (time.time() - last) < cooldown

    # unknown value -> behave like "session" (safest / least noisy)
    return True


def mark_notified(server, nick):
    _notified["%s.%s" % (server, nick)] = time.time()


def send_heads_up(server, nick, mynick):
    template = get_opt("message")
    text = template.replace("${nick}", nick).replace("${mynick}", mynick or "")

    method = get_opt("method")
    irc_cmd = "NOTICE" if method == "notice" else "PRIVMSG"

    weechat.command(
        "",
        "/quote -server %s %s %s :%s" % (server, irc_cmd, nick, text),
    )
    mark_notified(server, nick)
    log("Notified '%s' on %s that they're filtered." % (nick, server))


def privmsg_modifier_cb(data, modifier, modifier_data, string):
    """Hooked on the 'irc_in_privmsg' MODIFIER.

    The modifier runs BEFORE the IRC plugin applies /ignore filtering,
    which is essential here: messages from ignored users would otherwise
    be discarded upstream and this script would never see them. We never
    change the message -- we return it unmodified so /ignore still works
    normally afterwards.

    For the modifier, 'modifier_data' is the server name. 'string' is the
    raw IRC line.
    """
    try:
        server = modifier_data

        # Optional raw debug: log EVERY privmsg the script sees, ignored
        # or not, so you can verify messages actually reach this hook.
        if get_opt("debug") == "on":
            log("[debug] raw on %s: %s" % (server, string))

        if not server_allowed(server):
            return string

        parsed = weechat.info_get_hashtable(
            "irc_message_parse",
            {"message": string, "server": server},
        )
        nick = parsed.get("nick", "")
        host = parsed.get("host", "")
        target = parsed.get("channel", "")
        body = parsed.get("text", "")

        if not nick:
            return string

        mynick = weechat.info_get("irc_nick", server)
        if mynick and nick.lower() == mynick.lower():
            return string

        ignored = is_ignored(server, nick, host)

        if get_opt("debug") == "on":
            log("[debug] nick=%s target=%s ignored=%s" % (nick, target, ignored))

        if not ignored:
            return string

        is_private = bool(mynick) and target.lower() == mynick.lower()
        is_mention = bool(mynick) and (mynick.lower() in body.lower())

        notify_on = get_opt("notify_on")
        relevant = (
            (notify_on in ("pm", "both") and is_private)
            or (notify_on in ("mention", "both") and not is_private and is_mention)
        )

        if not relevant:
            if get_opt("debug") == "on":
                log("[debug] ignored user but not relevant "
                    "(private=%s mention=%s notify_on=%s)"
                    % (is_private, is_mention, notify_on))
            return string

        # Always log every relevant message (logging is never rate-limited).
        log_to_buffer(
            server, nick,
            "PM" if is_private else "MENTION",
            target, body,
        )

        # The heads-up notice IS rate-limited and optional.
        if get_opt("send_notice") == "on" and not already_notified(server, nick):
            send_heads_up(server, nick, mynick)

    except Exception as exc:  # never break message flow on error
        log("error in callback: %s" % exc)

    # CRITICAL: return the string UNCHANGED so /ignore still works.
    return string


def reset_cmd_cb(data, buffer, args):
    _notified.clear()
    log("Notification memory cleared -- everyone can be notified again.")
    return weechat.WEECHAT_RC_OK


def status_cmd_cb(data, buffer, args):
    """Print diagnostics so you can see whether the script is wired up."""
    log("--- ignore_notify status (v%s) ---" % SCRIPT_VERSION)

    # Live self-test of the matching engine, so we can SEE what the
    # running code actually does with a known input.
    import re as _re_check
    try:
        rx_ok = bool(_re_check.search("^PHILyGRANA$", "PHILyGRANA",
                                      _re_check.IGNORECASE))
    except Exception as e:
        rx_ok = "ERROR: %s" % e
    log("self-test: re.search('^PHILyGRANA$','PHILyGRANA') = %s" % rx_ok)
    log("self-test: _mask_match('^PHILyGRANA$','PHILyGRANA') = %s"
        % _mask_match("^PHILyGRANA$", "PHILyGRANA"))

    log("log_buffer=%s send_notice=%s notify_on=%s frequency=%s"
        % (get_opt("log_buffer"), get_opt("send_notice"),
           get_opt("notify_on"), get_opt("frequency")))
    buf = weechat.buffer_search("python", "ignore_log")
    log("log buffer exists: %s" % ("yes" if buf else "NO"))

    infolist = weechat.infolist_get("irc_ignore", "", "")
    count = 0
    if infolist:
        while weechat.infolist_next(infolist):
            count += 1
            log("  ignore #%d: server=%s mask=%s" % (
                count,
                weechat.infolist_string(infolist, "server"),
                weechat.infolist_string(infolist, "mask"),
            ))
        weechat.infolist_free(infolist)
    log("total /ignore entries: %d" % count)
    if count == 0:
        log("NOTE: no /ignore entries -> nothing will ever be logged.")

    # Optional: test whether a specific nick would be treated as ignored.
    # Usage:  /ignore_notify_status <nick> [server]
    arg = (args or "").strip()
    if arg:
        parts = arg.split()
        test_nick = parts[0]
        test_server = parts[1] if len(parts) > 1 else ""
        result = is_ignored(test_server, test_nick, "")
        log("match test: nick='%s' server='%s' -> %s"
            % (test_nick, test_server or "(any)",
               "WOULD be logged/notified" if result
               else "would NOT match any ignore"))

    log("Write a test line into the buffer now:")
    log_to_buffer("TEST", "tester", "PM", "you", "this is a test line")
    log("--- end status ---")
    return weechat.WEECHAT_RC_OK


if __name__ == "__main__":
    if weechat.register(
        SCRIPT_NAME,
        SCRIPT_AUTHOR,
        SCRIPT_VERSION,
        SCRIPT_LICENSE,
        SCRIPT_DESC,
        "",
        "",
    ):
        for key, (default, desc) in SETTINGS.items():
            if not weechat.config_is_set_plugin(key):
                weechat.config_set_plugin(key, default)
            weechat.config_set_desc_plugin(key, "%s (default: \"%s\")" % (desc, default))

        weechat.hook_modifier("irc_in_privmsg", "privmsg_modifier_cb", "")

        if get_opt("log_buffer") == "on":
            ensure_log_buffer()

        weechat.hook_command(
            "ignore_notify_reset",
            "Forget who has already been notified (lets everyone be re-notified)",
            "",
            "",
            "",
            "reset_cmd_cb",
            "",
        )

        weechat.hook_command(
            "ignore_notify_status",
            "Print diagnostics and write a test line to the log buffer",
            "",
            "",
            "",
            "status_cmd_cb",
            "",
        )

        log(
            "loaded. notify_on=%s frequency=%s method=%s"
            % (get_opt("notify_on"), get_opt("frequency"), get_opt("method"))
        )
