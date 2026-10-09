"""The systemctl wrapper: the show parser, unit verbs and ``request_reconcile``.

Design Doc "Module Responsibilities > systemd", DD-12 (D006), the Fact
Disposition Table row "systemd-escape:instance-naming" and the Required
Specific Tests "Reload during a start job" and "Delegation to an inactive
instance". Every parser trap is pinned on a real Deck capture:

- ``systemctl-show-dev-dm-0-device.txt``: ``Names=`` is quoted with doubled
  backslashes while ``Id=`` is raw; both name the same unit;
- ``systemctl-show-device-aliases.txt``: five units, raw escapes in ``Id=`` and
  ``Following=``, an empty ``Following=``;
- ``systemctl-show-unit-not-found.txt``: a missing unit says ``Result=success``
  and ``ActiveState=inactive``; only ``LoadState=not-found`` tells the truth;
- ``systemctl-show-oneshot-exited.txt``: a ``RemainAfterExit=yes`` oneshot that
  finished is ``active``/``exited``, i.e. the instance is still there.

The poll in ``request_reconcile`` runs on the fake clock: a hook on each
``systemctl show`` moves it, and ``POLL_SECONDS`` is zero, so no test sleeps.
"""

import logging

import pytest

from steamos_mounter import systemd
from steamos_mounter.errors import ExitCode, ToolError
from steamos_mounter.systemd import (
    daemon_reload,
    list_units,
    parse_show,
    reload,
    request_reconcile,
    show,
    start,
    stop,
)
from tests.helpers.fake_runner import Answer
from tests.helpers.fixtures import load_fixture

SYSTEMCTL = "/usr/bin/systemctl"
DM0_CAPTURE = "systemctl-show-dev-dm-0-device.txt"
ALIASES_CAPTURE = "systemctl-show-device-aliases.txt"
NOT_FOUND_CAPTURE = "systemctl-show-unit-not-found.txt"
ONESHOT_CAPTURE = "systemctl-show-oneshot-exited.txt"
UNIT = (
    "steamos-mounter@dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52"
    "\\x2da297\\x2d31643c64724d.service"
)
AUTO_UNIT = "steamos-mounter-auto@sys-devices-virtual-block-dm\\x2d0.service"
STATE_PROPERTIES = "--property=LoadState,ActiveState"
SHOW_STATE = (SYSTEMCTL, "show", STATE_PROPERTIES, "--", UNIT)
RELOAD_NO_BLOCK = (SYSTEMCTL, "reload", "--no-block", "--", UNIT)
ALIAS_HEADER = "### "


def state_answer(active: str, *, load: str = "loaded") -> Answer:
    return Answer(stdout=f"LoadState={load}\nActiveState={active}\n".encode())


def capture_text(name: str) -> str:
    return load_fixture(name).decode("utf-8")


def alias_sections(text: str) -> dict[str, str]:
    """The aliases capture split at its ``### <unit>`` header lines."""
    sections: dict[str, list[str]] = {}
    current: list[str] = []
    for line in text.splitlines():
        if line.startswith(ALIAS_HEADER):
            current = sections.setdefault(line.removeprefix(ALIAS_HEADER), [])
        else:
            current.append(line)
    return {unit: "\n".join(lines) + "\n" for unit, lines in sections.items()}


def advance_on_show(clock, seconds: float):
    """A runner hook that moves the fake clock by ``seconds`` on each call."""

    def hook(cmd) -> None:
        clock.advance(seconds)

    return hook


@pytest.fixture
def no_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    """Poll without a real sleep; the fake clock is moved by the runner hook."""
    monkeypatch.setattr(systemd, "POLL_SECONDS", 0.0)


def systemctl_verbs(fake_runner) -> list[str]:
    return [argv[1] for argv in fake_runner.argvs if argv[0] == SYSTEMCTL]


# --- parse_show ----------------------------------------------------------------------


def test_parse_show_quoting():
    dm0 = parse_show(capture_text(DM0_CAPTURE))

    assert dm0 == {
        "Id": "dev-dm\\x2d0.device",
        "Names": "dev-dm\\x2d0.device",
        "ActiveState": "active",
        "SubState": "plugged",
        "SysFSPath": "/sys/devices/virtual/block/dm-0",
    }
    assert dm0["Names"] == dm0["Id"]


def test_parse_show_quoting_on_the_alias_capture():
    sections = alias_sections(capture_text(ALIASES_CAPTURE))

    parsed = {unit: parse_show(text) for unit, text in sections.items()}

    assert len(parsed) == 5
    for unit, properties in parsed.items():
        assert properties["Id"] == unit
        assert properties["ActiveState"] == "active"
    personal = parsed[
        "dev-disk-by\\x2duuid-658207d5\\x2d5177\\x2d4a52\\x2da297\\x2d31643c64724d.device"
    ]
    assert personal["Following"] == (
        "sys-devices-pci0000:00-0000:00:08.1-0000:04:00.3-usb2-2\\x2d1-2\\x2d1.1-"
        "2\\x2d1.1:1.0-host1-target1:0:0-1:0:0:0-block-sdb-sdb1.device"
    )
    assert parsed["sys-devices-virtual-block-dm\\x2d0.device"]["Following"] == ""


def test_parse_show_oneshot_exited_capture():
    properties = parse_show(capture_text(ONESHOT_CAPTURE))

    assert properties["ActiveState"] == "active"
    assert properties["SubState"] == "exited"
    assert properties["RemainAfterExit"] == "yes"
    assert properties["BindsTo"] == "dev-disk-by\\x2dpartsets-self-efi.device"


def test_parse_show_keeps_the_text_after_the_first_equals_sign():
    assert parse_show("Environment=A=1 B=2\n") == {"Environment": "A=1 B=2"}


def test_parse_show_unescapes_an_embedded_quote():
    assert parse_show('Description="say \\"hi\\""\n') == {"Description": 'say "hi"'}


def test_parse_show_leaves_a_lone_quote_alone():
    assert parse_show('Description="\n') == {"Description": '"'}


def test_parse_show_skips_blank_lines_and_lines_without_a_property():
    assert parse_show("\nnot a property\nLoadState=loaded\n\n") == {
        "LoadState": "loaded"
    }


def test_parse_show_of_nothing_is_empty():
    assert parse_show("") == {}


def test_not_found_is_not_success():
    properties = parse_show(capture_text(NOT_FOUND_CAPTURE))

    assert properties["Result"] == "success"
    assert properties["LoadState"] == "not-found"
    assert systemd.unit_exists(properties) is False


def test_a_loaded_unit_exists():
    assert systemd.unit_exists(parse_show(capture_text(ONESHOT_CAPTURE))) is True


def test_a_unit_without_load_state_does_not_exist():
    assert systemd.unit_exists({"ActiveState": "active"}) is False


# --- show ----------------------------------------------------------------------------


def test_show_asks_for_the_named_properties_only(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "show"), ONESHOT_CAPTURE)

    properties = show(ctx, UNIT, ("LoadState", "ActiveState"))

    assert fake_runner.argvs == [SHOW_STATE]
    assert properties["ActiveState"] == "active"


def test_show_of_a_missing_unit_is_not_an_error(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "show"), NOT_FOUND_CAPTURE)

    properties = show(ctx, UNIT, ("LoadState", "ActiveState"))

    assert properties["LoadState"] == "not-found"


@pytest.mark.parametrize(
    "answer",
    [Answer(returncode=1, stderr=b"Failed to connect to bus"), Answer.timeout()],
    ids=["exit-1", "timeout"],
)
def test_show_failure_is_a_tool_error(ctx, fake_runner, answer):
    fake_runner.on((SYSTEMCTL, "show"), answer)

    with pytest.raises(ToolError) as caught:
        show(ctx, UNIT, ("ActiveState",))

    assert caught.value.exit_code is ExitCode.FAILED
    assert "systemctl show" in caught.value.detail


@pytest.mark.parametrize("props", [(), ("Active State",), ("A,B",), ("",)])
def test_show_refuses_bad_property_names(ctx, fake_runner, props):
    with pytest.raises(ValueError):
        show(ctx, UNIT, props)

    assert fake_runner.calls == []


# --- start, reload, stop -------------------------------------------------------------


def test_start_blocking(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "start"), Answer())

    result = start(ctx, UNIT, block=True)

    assert result.returncode == 0
    assert fake_runner.argvs == [(SYSTEMCTL, "start", "--", UNIT)]
    assert fake_runner.calls[0].timeout == 120.0


def test_start_without_blocking(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "start"), Answer())

    start(ctx, UNIT, block=False, timeout=30.0)

    assert fake_runner.argvs == [(SYSTEMCTL, "start", "--no-block", "--", UNIT)]
    assert fake_runner.calls[0].timeout == 30.0


def test_reload_returns_the_result_for_the_caller(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "reload"), Answer(returncode=1, stderr=b"not active"))

    result = reload(ctx, UNIT, block=False)

    assert fake_runner.argvs == [RELOAD_NO_BLOCK]
    assert result.returncode == 1


def test_stop_takes_several_units(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "stop"), Answer())

    stop(ctx, (UNIT, AUTO_UNIT), block=True)

    assert fake_runner.argvs == [(SYSTEMCTL, "stop", "--", UNIT, AUTO_UNIT)]


def test_stop_of_no_units_runs_nothing(ctx, fake_runner):
    with pytest.raises(ValueError):
        stop(ctx, (), block=True)

    assert fake_runner.calls == []


@pytest.mark.parametrize("unit", ["", "--no-block", "a b.service", "x\n.service"])
def test_unit_verbs_refuse_a_bad_unit_name(ctx, fake_runner, unit):
    with pytest.raises(ValueError):
        reload(ctx, unit, block=False)

    assert fake_runner.calls == []


# --- daemon_reload, list_units -------------------------------------------------------


def test_daemon_reload(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "daemon-reload"), Answer())

    daemon_reload(ctx)

    assert fake_runner.argvs == [(SYSTEMCTL, "daemon-reload")]


def test_daemon_reload_failure_is_a_tool_error(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "daemon-reload"), Answer(returncode=1))

    with pytest.raises(ToolError):
        daemon_reload(ctx)


def test_list_units_returns_the_first_column(ctx, fake_runner):
    listing = (
        f"{UNIT} loaded active exited steamos-mounter registered volume\n"
        f"{AUTO_UNIT} loaded failed failed steamos-mounter auto volume\n"
        "\n"
    )
    fake_runner.on((SYSTEMCTL, "list-units"), Answer(stdout=listing.encode()))

    units = list_units(ctx, ("steamos-mounter@*", "steamos-mounter-auto@*"))

    assert units == (UNIT, AUTO_UNIT)
    assert fake_runner.argvs == [
        (
            SYSTEMCTL,
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--full",
            "--",
            "steamos-mounter@*",
            "steamos-mounter-auto@*",
        )
    ]


def test_list_units_of_nothing_matching_is_empty(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "list-units"), Answer())

    assert list_units(ctx, ("steamos-mounter-key@*",)) == ()


def test_list_units_failure_is_a_tool_error(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "list-units"), Answer.missing())

    with pytest.raises(ToolError):
        list_units(ctx, ("steamos-mounter@*",))


def test_list_units_needs_a_pattern(ctx, fake_runner):
    with pytest.raises(ValueError):
        list_units(ctx, ())

    assert fake_runner.calls == []


# --- request_reconcile (DD-12) -------------------------------------------------------


def test_request_reconcile_active_reloads_once(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "show"), state_answer("active"))
    fake_runner.on((SYSTEMCTL, "reload"), Answer())

    outcome = request_reconcile(ctx, UNIT)

    assert outcome == "reloaded"
    assert fake_runner.argvs == [SHOW_STATE, RELOAD_NO_BLOCK]


def test_request_reconcile_on_the_oneshot_exited_capture_reloads(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "show"), ONESHOT_CAPTURE)
    fake_runner.on((SYSTEMCTL, "reload"), Answer())

    assert request_reconcile(ctx, UNIT) == "reloaded"
    assert systemctl_verbs(fake_runner) == ["show", "reload"]


@pytest.mark.usefixtures("no_pause")
def test_request_reconcile_activating_then_active_reloads_twice(
    ctx, fake_runner, fake_clock
):
    fake_runner.on(
        (SYSTEMCTL, "show"),
        state_answer("activating"),
        state_answer("activating"),
        state_answer("active"),
        hook=advance_on_show(fake_clock, 1.0),
    )
    fake_runner.on((SYSTEMCTL, "reload"), Answer(), Answer())
    started = fake_clock.monotonic()

    outcome = request_reconcile(ctx, UNIT)

    assert outcome == "reloaded-after-wait"
    assert fake_runner.argvs.count(RELOAD_NO_BLOCK) == 2
    assert systemctl_verbs(fake_runner) == ["show", "reload", "show", "show", "reload"]
    assert fake_clock.monotonic() - started <= 15.0


@pytest.mark.usefixtures("no_pause")
def test_request_reconcile_deactivating_waits_like_activating(
    ctx, fake_runner, fake_clock
):
    fake_runner.on(
        (SYSTEMCTL, "show"),
        state_answer("deactivating"),
        state_answer("active"),
        hook=advance_on_show(fake_clock, 1.0),
    )
    fake_runner.on((SYSTEMCTL, "reload"), Answer(), Answer())

    assert request_reconcile(ctx, UNIT) == "reloaded-after-wait"
    assert systemctl_verbs(fake_runner) == ["show", "reload", "show", "reload"]


@pytest.mark.usefixtures("no_pause")
def test_request_reconcile_stops_polling_at_the_wait_limit(
    ctx, fake_runner, fake_clock
):
    fake_runner.on(
        (SYSTEMCTL, "show"),
        state_answer("activating"),
        hook=advance_on_show(fake_clock, 4.0),
        repeat=True,
    )
    fake_runner.on((SYSTEMCTL, "reload"), Answer(), Answer())
    started = fake_clock.monotonic()

    outcome = request_reconcile(ctx, UNIT, wait_activating=15.0)

    assert outcome == "reloaded-after-wait"
    assert fake_runner.argvs.count(RELOAD_NO_BLOCK) == 2
    # One show before the first reload, then polls until 15 s have passed.
    assert systemctl_verbs(fake_runner).count("show") == 5
    assert fake_clock.monotonic() - started == 20.0


@pytest.mark.usefixtures("no_pause")
def test_request_reconcile_instance_gone_during_the_wait_is_absent(
    ctx, fake_runner, fake_clock, caplog
):
    fake_runner.on(
        (SYSTEMCTL, "show"),
        state_answer("deactivating"),
        state_answer("inactive"),
        hook=advance_on_show(fake_clock, 1.0),
    )
    fake_runner.on((SYSTEMCTL, "reload"), Answer())
    caplog.set_level(logging.WARNING, logger="steamos_mounter.systemd")

    assert request_reconcile(ctx, UNIT) == "absent"
    assert systemctl_verbs(fake_runner) == ["show", "reload", "show"]
    assert len(caplog.records) == 1


@pytest.mark.parametrize("active", ["inactive", "failed"])
def test_request_reconcile_inactive_or_failed_is_absent_and_never_starts(
    ctx, fake_runner, caplog, active
):
    fake_runner.on((SYSTEMCTL, "show"), state_answer(active))
    caplog.set_level(logging.DEBUG, logger="steamos_mounter.systemd")

    outcome = request_reconcile(ctx, UNIT)

    assert outcome == "absent"
    assert fake_runner.argvs == [SHOW_STATE]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "no partition instance" in warnings[0].getMessage()
    assert warnings[0].sm_fields["SM_UNIT"] == UNIT


def test_request_reconcile_missing_unit_is_absent(ctx, fake_runner, caplog):
    fake_runner.on((SYSTEMCTL, "show"), NOT_FOUND_CAPTURE)
    caplog.set_level(logging.WARNING, logger="steamos_mounter.systemd")

    assert request_reconcile(ctx, UNIT) == "absent"
    assert systemctl_verbs(fake_runner) == ["show"]
    assert len(caplog.records) == 1


def test_request_reconcile_logs_a_failed_reload_and_still_reports_it(
    ctx, fake_runner, caplog
):
    fake_runner.on((SYSTEMCTL, "show"), state_answer("active"))
    fake_runner.on((SYSTEMCTL, "reload"), Answer(returncode=1, stderr=b"denied"))
    caplog.set_level(logging.WARNING, logger="steamos_mounter.systemd")

    assert request_reconcile(ctx, UNIT) == "reloaded"
    assert len(caplog.records) == 1
    assert "reload" in caplog.records[0].getMessage()


def test_request_reconcile_never_runs_systemctl_start(ctx, fake_runner):
    fake_runner.on((SYSTEMCTL, "show"), state_answer("inactive"))

    request_reconcile(ctx, UNIT)

    assert "start" not in systemctl_verbs(fake_runner)
