from enum import Enum
from typing import TypedDict


class _ProfileModeChannel(TypedDict):
    deviceId: str
    channelIndex: int


class GroupProfileRequestBodies:
    class SetProfileModeRequestBody(TypedDict):
        profileMode: str
        "Profile mode enumeration value. Allowed values: MANUAL, AUTOMATIC"
        groupId: str
        "The ID of the group for the request"
        channels: list[_ProfileModeChannel]
        "List of channels for which the profile mode should be set"


class HmIPGroupProfileRequestPaths(Enum):
    setProfileMode = "setProfileMode"
    "Set the profile mode for devices, i.e. channels (e.g. manual or automatic)"


# HmIPGroupProfileRequestPaths.setProfileMode: SetProfileModeRequestBody,
