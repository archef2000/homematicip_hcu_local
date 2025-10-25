from enum import Enum
from typing import TypedDict


class GroupSwitchingRequestBodies:
    class HmIPGroupsSwitching(TypedDict):
        """Schema for the body of a control request to the HCU."""

        groupId: str
        "The ID of the group for the request"

    class WithTime(TypedDict):
        onTime: int
        """
        The desired duration in seconds for switching the device to the target level
        Constraints: 0.1 - 16383
        """
        rampTime: int
        """
        The time in seconds for dimming the device channel from current level to the target level
        Constraints: 0.1 - 16383
        """

    class SetDimLevel(HmIPGroupsSwitching):
        """Schema for the body of a set dim level request."""

        dimLevel: int
        "Constraints: 0.0 to 1.0"

    class SetColorTemperatureDimLevel(SetDimLevel):
        """Schema for the body of a set color temperature and dim level request."""

        colorTemperature: int
        "Constraints: 1000 K(Kelvin) to 10000 K"

    class SetDimLevelWithTime(SetDimLevel, WithTime):
        """Schema for the body of a set dim level with time request."""

        pass

    class SetColorTemperatureDimLevelWithTime(
        SetColorTemperatureDimLevel, SetDimLevelWithTime
    ):
        pass

    class SetHueSaturationDimLevel(SetDimLevel):
        """Schema for the body of a set hue, saturation and dim level request."""

        hue: int
        "Constraints: 0 to 359"
        saturationLevel: int
        "Constraints: 0.0 to 1.0"

    class SetHueSaturationDimLevelWithTime(
        SetHueSaturationDimLevel, SetDimLevelWithTime
    ):
        pass

    class SetPrimaryShadingLevel(HmIPGroupsSwitching):
        primaryShadingLevel: float
        "Constraints: 0.0 - 1.0"

    class SetSecondaryShadingLevel(SetPrimaryShadingLevel):
        secondaryShadingLevel: float
        "Constraints: 0.0 - 1.0"

    class SetSwitchState(HmIPGroupsSwitching):
        on: bool

    class SetSwitchStateWithTime(SetSwitchState):
        onTime: float

    class StartLightScene(HmIPGroupsSwitching):
        id: int
        "The ID of the light scene to start."
        dimLevel: float
        "Constraints: 0.0 - 1.0"


class HmIPGroupSwitchingRequestPaths(Enum):
    setColorTemperatureDimLevel = "setColorTemperatureDimLevel"
    "Sets the color temperature and dim level of a group to the given value"
    setColorTemperatureDimLevelWithTime = "setColorTemperatureDimLevelWithTime"
    "Sets the color temperature and dim level of a group to the given value for a certain time period (onTime)"
    setDimLevel = "setDimLevel"
    setDimLevelWithTime = "setDimLevelWithTime"
    setFavoriteShadingPosition = "setFavoriteShadingPosition"
    setHueSaturationDimLevel = "setHueSaturationDimLevel"
    setHueSaturationDimLevelWithTime = "setHueSaturationDimLevelWithTime"
    setPrimaryShadingLevel = "setPrimaryShadingLevel"
    setSecondaryShadingLevel = "setSecondaryShadingLevel"
    setState = "setState"
    setSwitchStateWithTime = "setSwitchStateWithTime"
    startLightScene = "startLightScene"
    stop = "stop"
    toggleShadingState = "toggleShadingState"
    toggleSwitchState = "toggleSwitchState"


#    HmIPGroupSwitchingRequestPaths.setColorTemperatureDimLevel: SetColorTemperatureDimLevel,
#    HmIPGroupSwitchingRequestPaths.setColorTemperatureDimLevelWithTime: SetColorTemperatureDimLevelWithTime,
#    HmIPGroupSwitchingRequestPaths.setDimLevel: SetDimLevel,
#    HmIPGroupSwitchingRequestPaths.setDimLevelWithTime: SetDimLevelWithTime,
#    HmIPGroupSwitchingRequestPaths.setFavoriteShadingPosition: HmIPGroupsSwitching,
#    HmIPGroupSwitchingRequestPaths.setHueSaturationDimLevel: SetHueSaturationDimLevel,
#    HmIPGroupSwitchingRequestPaths.setHueSaturationDimLevelWithTime: SetHueSaturationDimLevelWithTime,
#    HmIPGroupSwitchingRequestPaths.setPrimaryShadingLevel: SetPrimaryShadingLevel,
#    HmIPGroupSwitchingRequestPaths.setSecondaryShadingLevel: SetSecondaryShadingLevel,
#    HmIPGroupSwitchingRequestPaths.setState: SetSwitchState,
#    HmIPGroupSwitchingRequestPaths.setSwitchStateWithTime: SetSwitchStateWithTime,
#    HmIPGroupSwitchingRequestPaths.startLightScene: StartLightScene,
#    HmIPGroupSwitchingRequestPaths.stop: HmIPGroupsSwitching,
#    HmIPGroupSwitchingRequestPaths.toggleShadingState: HmIPGroupsSwitching,
#    HmIPGroupSwitchingRequestPaths.toggleSwitchState: HmIPGroupsSwitching,
