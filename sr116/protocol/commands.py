"""Capture-verified JY command IDs and allowlisted TX set."""

from __future__ import annotations

from typing import Final


class CMD:
    SET_TIME = 0x01
    OPEN_HR = 0x07
    CLOSE_HR = 0x08
    LIVE_HR = 0x0B  # rx
    HR_END = 0x11  # rx
    SPO2_CTRL = 0x17
    SPO2_SAMPLE = 0x18  # rx
    SPO2_END = 0x19  # rx
    APP_INFO = 0x1A
    STEP_STATUS = 0x1D
    AUTO_HR = 0x1E
    LIST_21 = 0x21  # step buckets (day sync) / audio list (context)
    LIST_22 = 0x22  # sleep rows
    HEALTH = 0x24
    DEVICE_INFO = 0x25
    AUDIO_DATA = 0x34
    AUDIO_EMPTY = 0x35  # rx queue empty
    AUDIO_DONE = 0x36  # echo deletes file
    AUDIO_COUNT = 0x3D
    KEEPALIVE = 0x3E
    AUDIO_PREP = 0x40
    TEARDOWN = 0x43
    NAME = 0x44
    BATTERY = 0x06


# Host→ring writes allowed by this client
ALLOWED_TX: Final[frozenset[int]] = frozenset(
    {
        CMD.SET_TIME,
        CMD.BATTERY,  # usually unsolicited; empty poll ok
        CMD.OPEN_HR,
        CMD.CLOSE_HR,
        CMD.SPO2_CTRL,
        CMD.APP_INFO,
        CMD.STEP_STATUS,
        CMD.AUTO_HR,
        CMD.LIST_21,
        CMD.LIST_22,
        CMD.HEALTH,
        CMD.AUDIO_DATA,
        CMD.AUDIO_DONE,  # only when user confirms delete
        CMD.AUDIO_COUNT,
        CMD.KEEPALIVE,
        CMD.AUDIO_PREP,
        CMD.TEARDOWN,
    }
)

CMD_NAMES: Final[dict[int, str]] = {
    CMD.SET_TIME: "setTime",
    CMD.BATTERY: "battery",
    CMD.OPEN_HR: "openHR",
    CMD.CLOSE_HR: "closeHR",
    CMD.LIVE_HR: "liveHR",
    CMD.HR_END: "hrEnd",
    CMD.SPO2_CTRL: "spo2Ctrl",
    CMD.SPO2_SAMPLE: "spo2Sample",
    CMD.SPO2_END: "spo2End",
    CMD.APP_INFO: "appInfo",
    CMD.STEP_STATUS: "stepStatus",
    CMD.AUTO_HR: "autoHR",
    CMD.LIST_21: "list21",
    CMD.LIST_22: "list22",
    CMD.HEALTH: "health",
    CMD.DEVICE_INFO: "deviceInfo",
    CMD.AUDIO_DATA: "audioData",
    CMD.AUDIO_EMPTY: "audioEmpty",
    CMD.AUDIO_DONE: "audioDone",
    CMD.AUDIO_COUNT: "audioCount",
    CMD.KEEPALIVE: "keepalive",
    CMD.AUDIO_PREP: "audioPrep",
    CMD.TEARDOWN: "teardown",
    CMD.NAME: "name",
}


def cmd_name(cmd: int) -> str:
    return CMD_NAMES.get(cmd, f"0x{cmd:02X}")


# Observed auto-HR enable payload from captures
AUTO_HR_ENABLE = bytes.fromhex("0000173b0105")
AUTO_HR_DISABLE = bytes.fromhex("0000173b0005")

# App-info blob echoed in captures (session housekeeping)
DEFAULT_APP_INFO = bytes.fromhex("001f74966785e9a3ae7d9e26ca")

WRITE_UUID = "000033f3-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "000033f4-0000-1000-8000-00805f9b34fb"
SERVICE_UUID = "000056ff-0000-1000-8000-00805f9b34fb"
