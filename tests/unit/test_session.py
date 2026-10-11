"""``session.check`` (logind and display halves) and its parsers.

Design Doc "Key Dialog Unit" (session check steps 1 to 6), IP-14, ADR-0005
D2, DD-19 and DD-20. Every test runs the real code over the Deck's
``loginctl`` captures through the fake runner:

- ``loginctl-user-deck-display.txt``: ``Display=5``;
- ``loginctl-seat-seat0-active.txt``: ``ActiveSession=5``;
- ``loginctl-session-5-properties.txt``: the asked-for properties, with an
  empty ``Display=`` line;
- ``loginctl-session-5.txt``: the full ``show-session 5``, where ``Display``
  is absent instead of empty (absent equals empty);
- ``loginctl-session-3-properties.txt``: the same properties from the Deck on
  systemd 261, asked with one ``-p`` per property (the comma form
  ``-p Name,Seat,...`` printed nothing there) and printed in loginctl's own
  order, not the asked one;
- ``loginctl-session-wayland.txt`` (synthetic): the same session as Wayland.

The display half (``need_display=True``) adds ``systemctl --user
show-environment`` through the fake runner and real ``/proc`` files under
``tmp_path`` (``tests/helpers/proc_tree.py``): the synthetic
``proc-net-unix-x0-listening.txt`` (X0 listener inode 2205399, abstract row
2205398, no ``X1`` listener), ``proc-cgroup-xorg.txt`` and
``proc-cgroup-other-scope.txt``.

Only the full allow-list match with a verified display is ``DESKTOP``; any
doubt is ``NOT_SURE`` and the values reach the journal (AC-076).
"""

import dataclasses
import logging

import pytest

from steamos_mounter import session, session_display
from steamos_mounter.session import SessionCheck, Verdict, check, parse_props
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture
from tests.helpers.proc_tree import (
    OTHER_SCOPE_CGROUP_FIXTURE,
    X0_INODE,
    XORG_AUTH,
    XORG_CMDLINE,
    XORG_PID,
    ProcTree,
    socket_link,
    unix_row,
    unix_table,
)

LOGINCTL = "/usr/bin/loginctl"
USER_CAPTURE = "loginctl-user-deck-display.txt"
SEAT_CAPTURE = "loginctl-seat-seat0-active.txt"
SESSION_CAPTURE = "loginctl-session-5-properties.txt"
FULL_SESSION_CAPTURE = "loginctl-session-5.txt"
WAYLAND_FIXTURE = "loginctl-session-wayland.txt"
SESSION_3_CAPTURE = "loginctl-session-3-properties.txt"
SESSION_PROPERTIES = (
    "Name",
    "Seat",
    "Active",
    "Remote",
    "Class",
    "Type",
    "State",
    "Desktop",
    "Scope",
    "Display",
    "Service",
    "VTNr",
)
# systemd 261's loginctl prints nothing for "-p A,B": one "-p" per property.
SESSION_PROPERTY_FLAGS = (
    "-p",
    "Name",
    "-p",
    "Seat",
    "-p",
    "Active",
    "-p",
    "Remote",
    "-p",
    "Class",
    "-p",
    "Type",
    "-p",
    "State",
    "-p",
    "Desktop",
    "-p",
    "Scope",
    "-p",
    "Display",
    "-p",
    "Service",
    "-p",
    "VTNr",
)
COMMA_PROPERTIES = (
    "Name,Seat,Active,Remote,Class,Type,State,Desktop,Scope,Display,Service,VTNr"
)
SHOW_USER = (LOGINCTL, "show-user", "deck", "-p", "Display")
SHOW_SEAT = (LOGINCTL, "show-seat", "seat0", "-p", "ActiveSession")
SHOW_SESSION = (LOGINCTL, "show-session", "5", *SESSION_PROPERTY_FLAGS)
LOGGER = "steamos_mounter.session"


def capture_text(name: str) -> str:
    return load_fixture(name).decode("utf-8")


def with_property(text: str, name: str, value: str | None) -> str:
    """``text`` with the ``name=`` line set to ``value``, or dropped for None."""
    lines = [line for line in text.splitlines() if not line.startswith(f"{name}=")]
    if value is not None:
        lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def answer(text: str) -> Answer:
    return Answer(stdout=text.encode("utf-8"))


def script_deck(
    fake_runner,
    *,
    user: Answer | str = USER_CAPTURE,
    seat: Answer | str = SEAT_CAPTURE,
    session_props: Answer | str = SESSION_CAPTURE,
) -> None:
    fake_runner.on(SHOW_USER, user)
    fake_runner.on(SHOW_SEAT, seat)
    fake_runner.on((LOGINCTL, "show-session"), session_props)


def wayland_answer() -> Answer:
    # A synthetic file has no capture-index row, so the exit status is given.
    return Answer.from_fixture(WAYLAND_FIXTURE, returncode=0)


def with_allow_list(ctx, **changes):
    allow_list = dataclasses.replace(ctx.platform.allow_list, **changes)
    platform = dataclasses.replace(ctx.platform, allow_list=allow_list)
    return dataclasses.replace(ctx, platform=platform)


# --- parse_props -------------------------------------------------------------------


def test_parse_props_reads_the_session_capture():
    props = parse_props(capture_text(SESSION_CAPTURE))

    assert dict(props) == {
        "Name": "deck",
        "VTNr": "1",
        "Seat": "seat0",
        "Display": "",
        "Remote": "no",
        "Service": "sddm-autologin",
        "Desktop": "KDE",
        "Scope": "session-5.scope",
        "Type": "x11",
        "Class": "user",
        "Active": "yes",
        "State": "active",
    }


def test_parse_props_absent_display_equals_the_empty_one():
    full = parse_props(capture_text(FULL_SESSION_CAPTURE))
    asked = parse_props(capture_text(SESSION_CAPTURE))

    assert "Display" not in full
    assert "Display" in asked
    assert full["Display"] == asked["Display"] == ""
    assert "Display" not in full  # reading an absent key adds nothing


def test_parse_props_full_and_asked_captures_agree_on_every_asked_property():
    full = parse_props(capture_text(FULL_SESSION_CAPTURE))
    asked = parse_props(capture_text(SESSION_CAPTURE))

    assert {name: full[name] for name in SESSION_PROPERTIES} == dict(asked)


def test_parse_props_reads_the_user_capture():
    props = parse_props(capture_text(USER_CAPTURE))

    assert dict(props) == {"Display": "5", "State": "active", "Linger": "yes"}


def test_parse_props_skips_lines_without_a_name():
    props = parse_props("\n=orphan\nnot a property\nActiveSession=5\n")

    assert dict(props) == {"ActiveSession": "5"}


def test_parse_props_unquotes_like_systemctl_show():
    props = parse_props('Desktop="K\\\\DE"\n')

    assert props["Desktop"] == "K\\DE"


# --- check: the Desktop Mode capture -----------------------------------------------


def test_deck_capture_is_desktop(ctx, fake_runner):
    script_deck(fake_runner)

    result = check(ctx, need_display=False)

    assert result.verdict is Verdict.DESKTOP
    assert result.session_id == "5"
    assert result.scope == "session-5.scope"
    assert result.display is None
    assert result.xorg_pid is None
    assert result.xauthority is None
    assert result.detail["Type"] == "x11"
    assert result.detail["Desktop"] == "KDE"


def test_show_session_asks_each_property_with_its_own_flag(ctx, fake_runner):
    script_deck(fake_runner)

    check(ctx, need_display=False)

    argv = fake_runner.argvs[2]
    assert argv == (
        LOGINCTL,
        "show-session",
        "5",
        "-p",
        "Name",
        "-p",
        "Seat",
        "-p",
        "Active",
        "-p",
        "Remote",
        "-p",
        "Class",
        "-p",
        "Type",
        "-p",
        "State",
        "-p",
        "Desktop",
        "-p",
        "Scope",
        "-p",
        "Display",
        "-p",
        "Service",
        "-p",
        "VTNr",
    )
    assert argv.count("-p") == 12
    assert not any("," in value for value in argv)


def test_check_runs_the_three_loginctl_queries_as_the_caller(ctx, fake_runner):
    script_deck(fake_runner)

    check(ctx, need_display=False)

    assert fake_runner.argvs == [SHOW_USER, SHOW_SEAT, SHOW_SESSION]
    assert all(call.user is None and call.group is None for call in fake_runner.calls)
    assert all(call.env_extra == {} for call in fake_runner.calls)
    assert all(0 < call.timeout <= 30 for call in fake_runner.calls)


def test_full_show_session_capture_without_display_is_desktop(ctx, fake_runner):
    # The full capture has no Display line at all; it reads as empty.
    script_deck(fake_runner, session_props=FULL_SESSION_CAPTURE)

    result = check(ctx, need_display=False)

    assert result.verdict is Verdict.DESKTOP
    assert result.display is None


def test_verdict_spellings():
    assert [str(verdict) for verdict in Verdict] == ["desktop", "none", "not-sure"]


def test_session_check_is_frozen(ctx, fake_runner):
    script_deck(fake_runner)
    result = check(ctx, need_display=False)

    assert isinstance(result, SessionCheck)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.verdict = Verdict.NONE  # type: ignore[misc]


# --- check: each allow-list property -----------------------------------------------


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("Name", "root"),
        ("Seat", "seat1"),
        ("Active", "no"),
        ("Remote", "yes"),
        ("Class", "greeter"),
        ("Class", "manager"),
        ("State", "online"),
        ("State", "closing"),
        ("Desktop", "gamescope"),
        ("Desktop", ""),
        ("Type", "wayland"),
        ("Type", "tty"),
        ("Type", ""),
    ],
)
def test_each_allow_list_mismatch_is_not_sure(ctx, fake_runner, caplog, name, value):
    text = with_property(capture_text(SESSION_CAPTURE), name, value)
    script_deck(fake_runner, session_props=answer(text))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check(ctx, need_display=False)

    assert result.verdict is Verdict.NOT_SURE
    assert result.session_id == "5"
    assert result.detail[name] == value
    journal = "\n".join(caplog.messages)
    assert f"{name}={value!r}" in journal
    assert "Name='" in journal and "Type='" in journal


@pytest.mark.parametrize(
    "name", ["Name", "Seat", "Active", "Remote", "Class", "State", "Desktop", "Type"]
)
def test_each_absent_allow_list_property_is_not_sure(ctx, fake_runner, name):
    text = with_property(capture_text(SESSION_CAPTURE), name, None)
    script_deck(fake_runner, session_props=answer(text))

    result = check(ctx, need_display=False)

    assert result.verdict is Verdict.NOT_SURE
    assert result.detail[name] == ""


def test_wayland_fixture_is_not_sure(ctx, fake_runner, caplog):
    script_deck(fake_runner, session_props=wayland_answer())

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check(ctx, need_display=False)

    assert result.verdict is Verdict.NOT_SURE
    assert "Type='wayland'" in "\n".join(caplog.messages)


def test_wayland_fixture_differs_from_the_capture_only_in_type():
    capture = parse_props(capture_text(SESSION_CAPTURE))
    wayland = parse_props(capture_text(WAYLAND_FIXTURE))

    assert {k: v for k, v in wayland.items() if capture[k] != v} == {"Type": "wayland"}


def test_not_sure_is_logged_once_at_notice(ctx, fake_runner, caplog):
    text = with_property(capture_text(SESSION_CAPTURE), "Remote", "yes")
    script_deck(fake_runner, session_props=answer(text))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        check(ctx, need_display=False)

    assert [record.levelname for record in caplog.records] == ["NOTICE"]
    assert "session not recognized" in caplog.messages[0]
    assert "Remote" in caplog.messages[0]


def test_desktop_logs_nothing_above_debug(ctx, fake_runner, caplog):
    script_deck(fake_runner)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        check(ctx, need_display=False)

    assert all(record.levelno <= logging.DEBUG for record in caplog.records)


# --- check: user and seat ----------------------------------------------------------


@pytest.mark.parametrize("user_text", ["Display=\n", "State=active\nLinger=yes\n"])
def test_no_primary_session_is_none(ctx, fake_runner, user_text):
    fake_runner.on(SHOW_USER, answer(user_text))

    result = check(ctx, need_display=False)

    assert result.verdict is Verdict.NONE
    assert result.session_id is None
    assert fake_runner.argvs == [SHOW_USER]


@pytest.mark.parametrize("active_session", ["1", "", "6"])
def test_seat_mismatch_is_not_sure(ctx, fake_runner, caplog, active_session):
    script_deck(fake_runner, seat=answer(f"ActiveSession={active_session}\n"))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check(ctx, need_display=False)

    assert result.verdict is Verdict.NOT_SURE
    assert result.session_id == "5"
    assert result.detail["ActiveSession"] == active_session
    assert fake_runner.argvs == [SHOW_USER, SHOW_SEAT]
    assert f"ActiveSession={active_session!r}" in "\n".join(caplog.messages)


@pytest.mark.parametrize("session_id", ["-5", "5 6", "../5", "5\x00"])
def test_unusable_session_id_is_not_sure_and_never_passed_on(
    ctx, fake_runner, session_id
):
    fake_runner.on(SHOW_USER, answer(f"Display={session_id}\n"))

    result = check(ctx, need_display=False)

    assert result.verdict is Verdict.NOT_SURE
    assert fake_runner.argvs == [SHOW_USER]


@pytest.mark.parametrize(
    "failure",
    [
        Answer(returncode=1, stderr=b"Failed to get user: User deck is not logged in"),
        Answer.timeout(),
        Answer.missing(),
    ],
)
@pytest.mark.parametrize("failing", ["user", "seat", "session_props"])
def test_failed_loginctl_query_is_not_sure(ctx, fake_runner, caplog, failure, failing):
    script_deck(fake_runner, **{failing: failure})

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check(ctx, need_display=False)

    assert result.verdict is Verdict.NOT_SURE
    assert any(record.levelname == "NOTICE" for record in caplog.records)


# --- check: the allow-list comes from the platform ---------------------------------


def test_platform_allow_list_decides_desktop(ctx, fake_runner):
    gnome_only = with_allow_list(ctx, desktop=frozenset({"GNOME"}))
    script_deck(fake_runner)

    result = check(gnome_only, need_display=False)

    assert result.verdict is Verdict.NOT_SURE


def test_platform_allow_list_can_admit_wayland(ctx, fake_runner):
    wayland_too = with_allow_list(ctx, session_type=frozenset({"x11", "wayland"}))
    script_deck(fake_runner, session_props=wayland_answer())

    result = check(wayland_too, need_display=False)

    assert result.verdict is Verdict.DESKTOP


def test_platform_seat_and_class_are_used(ctx, fake_runner):
    other = with_allow_list(ctx, seat="seat1", session_class="user")
    fake_runner.on(SHOW_USER, USER_CAPTURE)
    fake_runner.on(
        (LOGINCTL, "show-seat", "seat1", "-p", "ActiveSession"), SEAT_CAPTURE
    )
    fake_runner.on((LOGINCTL, "show-session"), SESSION_CAPTURE)

    result = check(other, need_display=False)

    # The seat is asked by the platform's name, and Seat=seat0 then mismatches.
    assert result.verdict is Verdict.NOT_SURE
    assert fake_runner.argvs[1][2] == "seat1"


def test_session_module_holds_no_allow_list_values():
    source = session.__file__
    with open(source, encoding="utf-8") as module_file:
        text = module_file.read()

    for value in ('"seat0"', '"KDE"', '"x11"', '"deck"', '"user"'):
        assert value not in text


# --- check: the time budget (a deadline on ctx.clock.monotonic()) ---------------------


def test_each_query_takes_at_most_what_is_left_of_the_deadline(
    ctx, fake_runner, fake_clock
):
    fake_runner.on(SHOW_USER, USER_CAPTURE, hook=lambda _c: fake_clock.advance(4))
    fake_runner.on(SHOW_SEAT, SEAT_CAPTURE, hook=lambda _c: fake_clock.advance(4))
    fake_runner.on((LOGINCTL, "show-session"), SESSION_CAPTURE)

    result = check(ctx, need_display=False, deadline=fake_clock.monotonic() + 12)

    assert result.verdict is Verdict.DESKTOP
    assert [call.timeout for call in fake_runner.calls] == [10.0, 8.0, 4.0]


def test_without_a_deadline_each_query_keeps_its_own_timeout(
    ctx, fake_runner, fake_clock
):
    script_deck(fake_runner)
    fake_clock.advance(10_000)

    result = check(ctx, need_display=False)

    assert result.verdict is Verdict.DESKTOP
    assert [call.timeout for call in fake_runner.calls] == [10.0, 10.0, 10.0]


def test_no_query_runs_once_the_deadline_has_passed(
    ctx, fake_runner, fake_clock, caplog
):
    deadline = fake_clock.monotonic()

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check(ctx, need_display=False, deadline=deadline)

    assert result.verdict is Verdict.NOT_SURE
    assert result.session_id is None
    assert fake_runner.calls == []
    assert [(r.levelname, r.getMessage()) for r in caplog.records] == [
        ("NOTICE", "session not recognized: no time left for loginctl show-user")
    ]


def test_a_deadline_passing_between_queries_stops_the_check(
    ctx, fake_runner, fake_clock, caplog
):
    fake_runner.on(SHOW_USER, USER_CAPTURE, hook=lambda _c: fake_clock.advance(10))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check(ctx, need_display=False, deadline=fake_clock.monotonic() + 10)

    assert result.verdict is Verdict.NOT_SURE
    assert result.session_id == "5"
    assert fake_runner.argvs == [SHOW_USER]
    assert [r.getMessage() for r in caplog.records] == [
        "session not recognized: no time left for loginctl show-seat"
    ]


# --- the display half: user manager DISPLAY and the X listener (steps 4 and 5) --------

SYSTEMCTL = "/usr/bin/systemctl"
SHOW_ENVIRONMENT = (SYSTEMCTL, "--user", "show-environment")
SESSION_ENV = {
    "XDG_RUNTIME_DIR": "/run/user/1000",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
}
# What a user manager holds after a Game Mode -> Desktop Mode switch (ADR-0005
# Device Facts), plus a value that must never be kept or logged.
MANAGER_ENVIRONMENT = (
    "HOME=/home/deck\n"
    "LANG=en_US.UTF-8\n"
    "DISPLAY=:0\n"
    "QT_QPA_PLATFORM=xcb\n"
    "XDG_SESSION_TYPE=x11\n"
    "PRIVATE_TOKEN=tok-5f1e-never-logged\n"
)
PRIVATE_VALUE = "tok-5f1e-never-logged"
X0_PATH = "/tmp/.X11-unix/X0"


@pytest.fixture
def proc(tmp_path) -> ProcTree:
    return ProcTree(tmp_path)


def environment(*lines: str) -> Answer:
    return answer("".join(f"{line}\n" for line in lines))


def script_display(
    fake_runner,
    *,
    env: Answer | None = None,
    session_props: Answer | str = SESSION_CAPTURE,
) -> None:
    script_deck(fake_runner, session_props=session_props)
    fake_runner.on(SHOW_ENVIRONMENT, env or answer(MANAGER_ENVIRONMENT))


def with_xauthority_flag(ctx):
    return dataclasses.replace(
        ctx, platform=dataclasses.replace(ctx.platform, xauthority_from_xserver=True)
    )


def check_display(ctx):
    return check(ctx, need_display=True)


def test_desktop_with_x0_listener_in_the_session_scope(ctx, fake_runner, proc):
    proc.desktop()
    script_display(fake_runner)

    result = check_display(ctx)

    assert result.verdict is Verdict.DESKTOP
    assert result.session_id == "5"
    assert result.scope == "session-5.scope"
    assert result.display == ":0"
    assert result.xorg_pid == XORG_PID
    assert result.xauthority is None
    assert result.detail["DISPLAY"] == ":0"
    assert result.detail["XListener"] == str(XORG_PID)


def test_show_environment_runs_after_logind_as_the_session_user_unlogged(
    ctx, fake_runner, proc
):
    proc.desktop()
    script_display(fake_runner)

    check_display(ctx)

    assert fake_runner.argvs == [SHOW_USER, SHOW_SEAT, SHOW_SESSION, SHOW_ENVIRONMENT]
    call = fake_runner.calls[-1]
    assert (call.user, call.group) == (1000, 1000)
    assert call.env_extra == SESSION_ENV
    assert call.log_output is False
    assert not call.secret_stdout
    assert not call.has_stdin
    assert call.timeout == 10.0


def test_environment_is_filtered_to_display(ctx, fake_runner, proc, caplog):
    proc.desktop()
    script_display(fake_runner)

    with caplog.at_level(logging.DEBUG):
        result = check_display(ctx)

    assert "DISPLAY" in result.detail
    assert not {"HOME", "LANG", "QT_QPA_PLATFORM", "PRIVATE_TOKEN"} & set(result.detail)
    assert PRIVATE_VALUE not in repr(result)
    assert PRIVATE_VALUE not in caplog.text


def test_environment_is_not_logged_when_the_check_is_not_sure(
    ctx, fake_runner, proc, caplog
):
    proc.net_unix()  # no X server process: the check fails after reading DISPLAY
    script_display(fake_runner)

    with caplog.at_level(logging.DEBUG):
        result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert PRIVATE_VALUE not in caplog.text
    assert "HOME" not in caplog.text


@pytest.mark.parametrize(
    "lines",
    [
        ("HOME=/home/deck",),
        ("DISPLAY=",),
        ("DISPLAY=:0.0",),
        ("DISPLAY=localhost:0",),
        ("DISPLAY=:00",),
        ("DISPLAY=:",),
        ("DISPLAY=:0 ",),
        ("DISPLAY=wayland-0",),
        ("WAYLAND_DISPLAY=wayland-0",),
    ],
)
def test_no_usable_display_is_not_sure(ctx, fake_runner, proc, caplog, lines):
    proc.desktop()
    script_display(fake_runner, env=environment(*lines))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert result.display is None
    assert result.detail["DISPLAY"] == ""
    notices = [r.getMessage() for r in caplog.records if r.levelname == "NOTICE"]
    assert len(notices) == 1
    assert "DISPLAY did not match" in notices[0]
    assert "Scope='session-5.scope'" in notices[0]


def test_stale_x1_display_without_a_listener_is_not_sure(
    ctx, fake_runner, proc, caplog
):
    proc.desktop()
    script_display(fake_runner, env=environment("DISPLAY=:1"))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert result.xorg_pid is None
    assert result.detail["DISPLAY"] == ":1"
    assert result.detail["XListener"] == ""
    journal = "\n".join(caplog.messages)
    assert "XListener did not match" in journal
    assert "DISPLAY=':1'" in journal


def test_x1_listener_outside_the_session_scope_is_not_sure(
    ctx, fake_runner, proc, caplog
):
    x1_row = unix_row(3100001, "/tmp/.X11-unix/X1")
    proc.net_unix(load_fixture("proc-net-unix-x0-listening.txt").decode() + x1_row)
    proc.xorg()
    other = load_fixture(OTHER_SCOPE_CGROUP_FIXTURE).decode()
    proc.process(5151, fds={3: socket_link(3100001)}, cgroup=other)
    script_display(fake_runner, env=environment("DISPLAY=:1"))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert result.detail["XListener"].startswith("5151 in ")
    assert "session-3.scope" in "\n".join(caplog.messages)


def test_x0_listener_in_another_scope_is_not_sure(ctx, fake_runner, proc):
    proc.net_unix()
    proc.xorg(cgroup_fixture=OTHER_SCOPE_CGROUP_FIXTURE)
    script_display(fake_runner)

    result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert result.detail["XListener"] == (
        f"{XORG_PID} in /user.slice/user-1000.slice/session-3.scope"
    )


def test_listener_without_a_cgroup_file_is_not_sure(ctx, fake_runner, proc):
    proc.net_unix()
    proc.process(XORG_PID, fds={7: socket_link(X0_INODE)})
    script_display(fake_runner)

    result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert result.detail["XListener"] == f"{XORG_PID} in no cgroup"


def test_wayland_session_is_not_sure_before_any_display_query(ctx, fake_runner, proc):
    proc.desktop()
    script_deck(fake_runner, session_props=wayland_answer())

    result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert SHOW_ENVIRONMENT not in fake_runner.argvs


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("Name", "root"),
        ("Seat", "seat1"),
        ("Active", "no"),
        ("Remote", "yes"),
        ("Class", "greeter"),
        ("State", "online"),
        ("Desktop", "gamescope"),
        ("Type", "wayland"),
    ],
)
def test_each_property_mismatch_stops_before_the_display_half(
    ctx, fake_runner, proc, name, value
):
    proc.desktop()
    text = with_property(capture_text(SESSION_CAPTURE), name, value)
    script_deck(fake_runner, session_props=answer(text))

    result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert result.display is None
    assert fake_runner.argvs == [SHOW_USER, SHOW_SEAT, SHOW_SESSION]


def test_no_session_needs_no_display_query(ctx, fake_runner):
    fake_runner.on(SHOW_USER, answer("Display=\n"))

    result = check_display(ctx)

    assert result.verdict is Verdict.NONE
    assert fake_runner.argvs == [SHOW_USER]


def test_empty_scope_is_not_sure(ctx, fake_runner, proc):
    proc.desktop()
    text = with_property(capture_text(SESSION_CAPTURE), "Scope", "")
    script_display(fake_runner, session_props=answer(text))

    result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert result.xorg_pid is None


@pytest.mark.parametrize(
    "failure",
    [
        Answer(returncode=1, stderr=b"Failed to connect to bus: No medium found"),
        Answer.timeout(),
        Answer.missing(),
    ],
)
def test_failed_show_environment_is_not_sure(ctx, fake_runner, proc, caplog, failure):
    proc.desktop()
    script_display(fake_runner, env=failure)

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert result.session_id == "5"
    notices = [r.getMessage() for r in caplog.records if r.levelname == "NOTICE"]
    assert len(notices) == 1
    assert "systemctl --user show-environment failed" in notices[0]


def test_display_check_without_the_proc_table_is_not_sure(ctx, fake_runner):
    script_display(fake_runner)

    result = check_display(ctx)

    assert result.verdict is Verdict.NOT_SURE
    assert result.detail["XListener"] == ""


def test_need_display_false_reads_no_environment_and_no_proc(ctx, fake_runner, proc):
    proc.desktop()
    script_deck(fake_runner)

    result = check(ctx, need_display=False)

    assert result.verdict is Verdict.DESKTOP
    assert result.display is None
    assert SHOW_ENVIRONMENT not in fake_runner.argvs


# --- the display half: XAUTHORITY from the X server (DD-20) -----------------------


def test_xauthority_is_read_from_xorg_only_with_the_platform_flag(
    ctx, fake_runner, proc
):
    proc.desktop()
    script_display(fake_runner)

    result = check_display(with_xauthority_flag(ctx))

    assert result.verdict is Verdict.DESKTOP
    assert result.xauthority == XORG_AUTH
    assert result.detail["XAUTHORITY"] == XORG_AUTH


def test_xauthority_stays_unset_without_the_flag(ctx, fake_runner, proc):
    proc.desktop()
    script_display(fake_runner)

    result = check_display(ctx)

    assert result.xauthority is None
    assert "XAUTHORITY" not in result.detail


@pytest.mark.parametrize(
    "cmdline",
    [
        ("/usr/lib/Xorg", "-seat", "seat0", "vt1"),
        ("/usr/lib/Xorg", "-auth"),
        ("/usr/lib/Xorg", "-auth", "xauth_relative"),
        (),
    ],
)
def test_flag_without_a_usable_auth_argument_is_not_sure(
    ctx, fake_runner, proc, cmdline
):
    proc.net_unix()
    proc.xorg(cmdline=cmdline)
    script_display(fake_runner)

    result = check_display(with_xauthority_flag(ctx))

    assert result.verdict is Verdict.NOT_SURE
    assert result.xauthority is None
    assert result.detail["XAUTHORITY"] == ""


def test_flag_with_an_unreadable_cmdline_is_not_sure(ctx, fake_runner, proc):
    proc.net_unix()
    proc.process(
        XORG_PID,
        fds={7: socket_link(X0_INODE)},
        cgroup="0::/user.slice/user-1000.slice/session-5.scope\n",
    )
    script_display(fake_runner)

    result = check_display(with_xauthority_flag(ctx))

    assert result.verdict is Verdict.NOT_SURE


# --- the display half: the time budget ----------------------------------------------


def test_show_environment_takes_at_most_what_is_left(
    ctx, fake_runner, fake_clock, proc
):
    proc.desktop()
    fake_runner.on(SHOW_USER, USER_CAPTURE, hook=lambda _c: fake_clock.advance(3))
    fake_runner.on(SHOW_SEAT, SEAT_CAPTURE, hook=lambda _c: fake_clock.advance(3))
    fake_runner.on(
        (LOGINCTL, "show-session"),
        SESSION_CAPTURE,
        hook=lambda _c: fake_clock.advance(3),
    )
    fake_runner.on(SHOW_ENVIRONMENT, answer(MANAGER_ENVIRONMENT))

    result = check(ctx, need_display=True, deadline=fake_clock.monotonic() + 12)

    assert result.verdict is Verdict.DESKTOP
    assert [call.timeout for call in fake_runner.calls] == [10.0, 9.0, 6.0, 3.0]


def test_no_time_left_for_show_environment_is_not_sure(
    ctx, fake_runner, fake_clock, proc, caplog
):
    proc.desktop()
    fake_runner.on(SHOW_USER, USER_CAPTURE)
    fake_runner.on(SHOW_SEAT, SEAT_CAPTURE)
    fake_runner.on(
        (LOGINCTL, "show-session"),
        SESSION_CAPTURE,
        hook=lambda _c: fake_clock.advance(5),
    )

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check(ctx, need_display=True, deadline=fake_clock.monotonic() + 5)

    assert result.verdict is Verdict.NOT_SURE
    assert SHOW_ENVIRONMENT not in fake_runner.argvs
    assert [r.getMessage() for r in caplog.records] == [
        "session not recognized: no time left for systemctl --user show-environment"
    ]


# --- the Deck on systemd 261: session 3, one -p per property ------------------------

SHOW_SESSION_3 = (LOGINCTL, "show-session", "3")
SESSION_3_CGROUP = "0::/user.slice/user-1000.slice/session-3.scope\n"


def script_deck_session_3(fake_runner) -> None:
    """The Deck as found in Stage A: session 3, where the comma form prints nothing.

    ``show-user deck -p Display`` gave ``Display=3`` there and the seat's
    ``ActiveSession`` named the same session.
    """
    fake_runner.on(SHOW_USER, answer("Display=3\n"))
    fake_runner.on(SHOW_SEAT, answer("ActiveSession=3\n"))
    fake_runner.on((*SHOW_SESSION_3, "-p", COMMA_PROPERTIES), answer(""))
    fake_runner.on((*SHOW_SESSION_3, *SESSION_PROPERTY_FLAGS), SESSION_3_CAPTURE)


def session_3_x_server(proc: ProcTree) -> None:
    """X0's listener, held by an X server in ``session-3.scope``."""
    proc.net_unix()
    proc.process(XORG_PID, fds={7: socket_link(X0_INODE)}, cgroup=SESSION_3_CGROUP)


def test_session_3_capture_prints_properties_in_its_own_order():
    lines = capture_text(SESSION_3_CAPTURE).splitlines()
    names = [line.partition("=")[0] for line in lines]

    assert sorted(names) == sorted(SESSION_PROPERTIES)
    assert tuple(names) != SESSION_PROPERTIES


def test_session_3_capture_is_desktop_on_the_logind_half(ctx, fake_runner):
    script_deck_session_3(fake_runner)

    result = check(ctx, need_display=False)

    assert result.verdict is Verdict.DESKTOP
    assert result.session_id == "3"
    assert result.scope == "session-3.scope"
    assert dict(result.detail) == {
        "Name": "deck",
        "Seat": "seat0",
        "Active": "yes",
        "Remote": "no",
        "Class": "user",
        "Type": "x11",
        "State": "active",
        "Desktop": "KDE",
        "Scope": "session-3.scope",
        "Display": "",
        "Service": "sddm-autologin",
        "VTNr": "1",
    }


def test_session_3_capture_is_desktop_with_the_display_half(ctx, fake_runner, proc):
    session_3_x_server(proc)
    script_deck_session_3(fake_runner)
    fake_runner.on(SHOW_ENVIRONMENT, answer(MANAGER_ENVIRONMENT))

    result = check_display(ctx)

    assert result.verdict is Verdict.DESKTOP
    assert result.session_id == "3"
    assert result.scope == "session-3.scope"
    assert result.display == ":0"
    assert result.xorg_pid == XORG_PID
    assert fake_runner.argvs == [
        SHOW_USER,
        SHOW_SEAT,
        (*SHOW_SESSION_3, *SESSION_PROPERTY_FLAGS),
        SHOW_ENVIRONMENT,
    ]


def test_empty_show_session_output_is_not_sure(ctx, fake_runner, caplog):
    # What the comma form gave in Stage A: exit 0 and no output at all, which
    # reads as every property empty. That is doubt, never a Desktop session.
    fake_runner.on(SHOW_USER, answer("Display=3\n"))
    fake_runner.on(SHOW_SEAT, answer("ActiveSession=3\n"))
    fake_runner.on(SHOW_SESSION_3, answer(""))

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = check(ctx, need_display=False)

    assert result.verdict is Verdict.NOT_SURE
    assert result.detail["Name"] == ""
    assert [record.levelname for record in caplog.records] == ["NOTICE"]
    assert caplog.messages[0].startswith(
        "session not recognized: Name, Seat, Active, Remote, Class, Type, State,"
        " Desktop did not match;"
    )


# --- user_manager_display ------------------------------------------------------------


def test_user_manager_display_keeps_only_display(ctx, fake_runner):
    fake_runner.on(SHOW_ENVIRONMENT, answer(MANAGER_ENVIRONMENT))

    assert session.user_manager_display(ctx) == ":0"
    [call] = fake_runner.calls
    assert call.log_output is False
    assert (call.user, call.group, call.env_extra) == (1000, 1000, SESSION_ENV)
    assert call.timeout == 10.0


@pytest.mark.parametrize(
    "result", [Answer(returncode=1), Answer.timeout(), Answer.missing()]
)
def test_user_manager_display_is_none_when_the_query_fails(ctx, fake_runner, result):
    fake_runner.on(SHOW_ENVIRONMENT, result)

    assert session.user_manager_display(ctx) is None


def test_user_manager_display_takes_the_first_display_line(ctx, fake_runner):
    fake_runner.on(SHOW_ENVIRONMENT, environment("DISPLAY=:7", "DISPLAY=:0"))

    assert session.user_manager_display(ctx) == ":7"


# --- x_listener_pid ------------------------------------------------------------------


def test_x0_listener_is_the_xorg_pid_from_the_synthetic_table(ctx, proc):
    proc.desktop()

    assert session.x_listener_pid(ctx, 0) == XORG_PID


def test_x1_has_no_listener_in_the_synthetic_table(ctx, proc):
    proc.desktop()

    assert session.x_listener_pid(ctx, 1) is None


def test_abstract_socket_alone_is_no_listener(ctx, proc):
    proc.net_unix(unix_table(unix_row(2205398, "@/tmp/.X11-unix/X0")))
    proc.process(XORG_PID, fds={6: socket_link(2205398)})

    assert session.x_listener_pid(ctx, 0) is None


@pytest.mark.parametrize(
    "row",
    [
        # accepted connection: no listening flag, state 03
        unix_row(X0_INODE, X0_PATH, flags="00000000", state="03"),
        # listening flag but not state 01
        unix_row(X0_INODE, X0_PATH, state="03"),
        # state 01 without the listening flag (bound, not listening)
        unix_row(X0_INODE, X0_PATH, flags="00000000"),
        # a longer path that starts the same
        unix_row(X0_INODE, f"{X0_PATH}0"),
        # no path at all
        unix_row(X0_INODE),
    ],
)
def test_only_an_exact_listening_row_counts(ctx, proc, row):
    proc.net_unix(unix_table(row))
    proc.process(XORG_PID, fds={7: socket_link(X0_INODE)})

    assert session.x_listener_pid(ctx, 0) is None


def test_x1_does_not_match_an_x10_listener(ctx, proc):
    proc.net_unix(unix_table(unix_row(3100010, "/tmp/.X11-unix/X10")))
    proc.process(5000, fds={3: socket_link(3100010)})

    assert session.x_listener_pid(ctx, 1) is None
    assert session.x_listener_pid(ctx, 10) == 5000


def test_two_listening_rows_for_one_path_are_doubt(ctx, proc):
    proc.net_unix(unix_table(unix_row(X0_INODE, X0_PATH), unix_row(2209999, X0_PATH)))
    proc.process(XORG_PID, fds={7: socket_link(X0_INODE)})

    assert session.x_listener_pid(ctx, 0) is None


def test_listener_held_by_no_process_is_none(ctx, proc):
    proc.net_unix()
    proc.process(4300, fds={3: socket_link(2207110)})

    assert session.x_listener_pid(ctx, 0) is None


def test_listener_held_by_two_processes_is_doubt(ctx, proc):
    proc.desktop()
    proc.process(4243, fds={9: socket_link(X0_INODE)})

    assert session.x_listener_pid(ctx, 0) is None


def test_unreadable_process_entries_are_skipped(ctx, proc):
    proc.desktop()
    proc.path("/proc/77").mkdir()  # no fd directory: a process that went away
    fd_dir = proc.process(78)
    (fd_dir / "fd" / "5").write_text("not a link")  # readlink fails
    proc.path("/proc/self").mkdir()  # not a pid

    assert session.x_listener_pid(ctx, 0) == XORG_PID


def test_missing_proc_table_is_none(ctx):
    assert session.x_listener_pid(ctx, 0) is None


def test_proc_table_without_a_proc_listing_is_none(ctx, proc):
    proc.desktop()
    listing = proc.path("/proc")
    listing.chmod(0o311)  # searchable, not listable: the table reads, the scan fails
    try:
        found = session.x_listener_pid(ctx, 0)
    finally:
        listing.chmod(0o755)

    assert found is None


# --- pid_in_scope --------------------------------------------------------------------


def test_xorg_cgroup_fixture_is_in_session_5_scope(ctx, proc):
    proc.xorg()

    assert session.pid_in_scope(ctx, XORG_PID, "session-5.scope") is True


def test_other_scope_fixture_is_not_in_session_5_scope(ctx, proc):
    proc.xorg(cgroup_fixture=OTHER_SCOPE_CGROUP_FIXTURE)

    assert session.pid_in_scope(ctx, XORG_PID, "session-5.scope") is False


@pytest.mark.parametrize(
    ("cgroup", "scope"),
    [
        ("0::/user.slice/user-1000.slice/session-15.scope\n", "session-5.scope"),
        # the last element only ends with the scope name
        ("0::/user.slice/user-1000.slice/app-session-5.scope\n", "session-5.scope"),
        ("0::/user.slice/user-1000.slice/session-5.scope/extra\n", "session-5.scope"),
        (
            "1:name=systemd:/user.slice/user-1000.slice/session-5.scope\n",
            "session-5.scope",
        ),
        ("", "session-5.scope"),
        ("0::/user.slice/user-1000.slice/session-5.scope\n", ""),
        (
            "0::/user.slice/user-1000.slice/session-5.scope\n",
            "user-1000.slice/session-5.scope",
        ),
    ],
)
def test_scope_must_be_the_last_path_element_of_the_v2_line(ctx, proc, cgroup, scope):
    proc.process(XORG_PID, cgroup=cgroup)

    assert session.pid_in_scope(ctx, XORG_PID, scope) is False


def test_hybrid_cgroup_file_uses_the_unified_line(ctx, proc):
    proc.process(
        XORG_PID,
        cgroup=(
            "1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n"
            "0::/user.slice/user-1000.slice/session-5.scope\n"
        ),
    )

    assert session.pid_in_scope(ctx, XORG_PID, "session-5.scope") is True


def test_missing_process_is_not_in_scope(ctx):
    assert session.pid_in_scope(ctx, 99999, "session-5.scope") is False


# --- x_server_auth -------------------------------------------------------------------


def test_x_server_auth_reads_the_auth_argument(ctx, proc):
    proc.xorg()

    assert session_display.x_server_auth(ctx, XORG_PID) == XORG_AUTH


def test_x_server_auth_without_the_option_is_none(ctx, proc):
    proc.xorg(cmdline=XORG_CMDLINE[:8])

    assert session_display.x_server_auth(ctx, XORG_PID) is None
