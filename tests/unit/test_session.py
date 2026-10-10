"""The logind half of ``session.check`` and the ``parse_props`` parser.

Design Doc "Key Dialog Unit" (session check steps 1 to 3 and 6), IP-14,
ADR-0005 D2 and DD-19. Every test runs the real code over the Deck's
``loginctl`` captures through the fake runner:

- ``loginctl-user-deck-display.txt``: ``Display=5``;
- ``loginctl-seat-seat0-active.txt``: ``ActiveSession=5``;
- ``loginctl-session-5-properties.txt``: the asked-for properties, with an
  empty ``Display=`` line;
- ``loginctl-session-5.txt``: the full ``show-session 5``, where ``Display``
  is absent instead of empty (absent equals empty);
- ``loginctl-session-wayland.txt`` (synthetic): the same session as Wayland.

Only the full allow-list match is ``DESKTOP``; any doubt is ``NOT_SURE`` and
the property values reach the journal (AC-076).
"""

import dataclasses
import logging

import pytest

from steamos_mounter import session
from steamos_mounter.session import SessionCheck, Verdict, check, parse_props
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture

LOGINCTL = "/usr/bin/loginctl"
USER_CAPTURE = "loginctl-user-deck-display.txt"
SEAT_CAPTURE = "loginctl-seat-seat0-active.txt"
SESSION_CAPTURE = "loginctl-session-5-properties.txt"
FULL_SESSION_CAPTURE = "loginctl-session-5.txt"
WAYLAND_FIXTURE = "loginctl-session-wayland.txt"
SESSION_PROPERTIES = (
    "Name,Seat,Active,Remote,Class,Type,State,Desktop,Scope,Display,Service,VTNr"
)
SHOW_USER = (LOGINCTL, "show-user", "deck", "-p", "Display")
SHOW_SEAT = (LOGINCTL, "show-seat", "seat0", "-p", "ActiveSession")
SHOW_SESSION = (LOGINCTL, "show-session", "5", "-p", SESSION_PROPERTIES)
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

    assert {name: full[name] for name in SESSION_PROPERTIES.split(",")} == dict(asked)


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


# --- check: the display half is not built yet --------------------------------------


def test_need_display_raises_until_the_display_half_lands(ctx, fake_runner):
    with pytest.raises(NotImplementedError, match="display"):
        check(ctx, need_display=True)

    assert fake_runner.calls == []


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
