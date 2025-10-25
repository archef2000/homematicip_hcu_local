from enum import Enum
from typing import TypedDict


class _GroupIdRequestBody(TypedDict):
    groupId: str
    "The ID of the group to control."


class GroupHeatingRequestBodies:
    class HmIPActivatePartyMode(_GroupIdRequestBody):
        temperature: float
        "The target temperature for the party mode. Constraints: 5.0 to 30.0"
        endTime: str
        "The end time of the vacation mode. Constraints: yyyy_MM_dd HH:mm"

    class HmIPSetActiveProfile(_GroupIdRequestBody):
        profileIndex: str
        "Allowed values: PROFILE_1-PROFILE_6"

    class HmIPSetBoost(_GroupIdRequestBody):
        boost: bool
        "true to activate the boost function, false to deactivate"

    class HmIPSetControlMode(_GroupIdRequestBody):
        controlMode: str
        "Allowed values: AUTOMATIC, MANUAL, ECO"

    class HmIPSetHotWaterOnTime(_GroupIdRequestBody):
        onTime: float
        "Duration in minutes"

    class HmIPSetHotWaterProfileMode(_GroupIdRequestBody):
        profileMode: str
        "Allowed values: AUTOMATIC, MANUAL"

    class HmIPSetHotWaterState(_GroupIdRequestBody):
        on: bool

    class HmIPSetPointTemperature(_GroupIdRequestBody):
        setPointTemperature: float
        "The new set point temperature value. Constraints: minTemperature to maxTemperature"


class HmIPGroupHeatingRequestPaths(Enum):
    activatePartyMode = "activatePartyMode"
    "Activate the party mode"
    setActiveProfile = "setActiveProfile"
    "Activate the profile on the applicable devices in the heating group"
    setBoost = "setBoost"
    "Activate or deactivate the boost function of the applicable devices in a heating group"
    setControlMode = "setControlMode"
    "Set the control mode of the applicable devices in a heating group"
    setHotWaterOnTime = "setHotWaterOnTime"
    "Set the duration for producing hot water"
    setHotWaterProfileMode = "setHotWaterProfileMode"
    "Enable / Disable profile"
    setHotWaterState = "setHotWaterState"
    "Start / Stop making hot water"
    setSetPointTemperature = "setSetPointTemperature"
    "Set the set point temperature of the applicable devices in a heating group"


#    HmIPGroupHeatingRequestPaths.activatePartyMode: HmIPActivatePartyMode,
#    HmIPGroupHeatingRequestPaths.setActiveProfile: HmIPSetActiveProfile,
#    HmIPGroupHeatingRequestPaths.setBoost: HmIPSetBoost,
#    HmIPGroupHeatingRequestPaths.setControlMode: HmIPSetControlMode,
#    HmIPGroupHeatingRequestPaths.setHotWaterOnTime: HmIPSetHotWaterOnTime,
#    HmIPGroupHeatingRequestPaths.setHotWaterProfileMode: HmIPSetHotWaterProfileMode,
#    HmIPGroupHeatingRequestPaths.setHotWaterState: HmIPSetHotWaterState,
#    HmIPGroupHeatingRequestPaths.setSetPointTemperature: HmIPSetPointTemperature,
