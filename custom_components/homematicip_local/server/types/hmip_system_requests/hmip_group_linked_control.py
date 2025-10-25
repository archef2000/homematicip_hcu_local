from enum import Enum
from typing import TypedDict


class _GroupIdRequestBody(TypedDict):
    groupId: str
    "The ID of the group to control."


class GroupLinkedControlRequestBodies:
    class HmIPSetOpticalSignalBehaviour(_GroupIdRequestBody):
        onTime: float
        "The time in seconds for switching the group"
        simpleRGBColor: str
        "Allowed values: BLACK BLUE GREEN TURQUOISE RED PURPLE YELLOW WHITE"

    class SetSoundFileVolumeLevel(_GroupIdRequestBody):
        onTime: float
        "The time in seconds for switching the group"
        soundFile: str
        "INTERNAL_SOUNDFILE, SOUNDFILE_001-SOUNDFILE_252, RANDOM_SOUNDFILE, OLD_VALUE, DO_NOT_CARE"
        volumeLevel: float
        "The volume level of the sound file. Constraints: 0.0 - 1.0"

    class HmIPSetVentilationLevel(_GroupIdRequestBody):
        ventilationLevel: float
        "The desired ventilation level. Constraints: 0.0 - 1.0"

    class HmIPSetVentilationLevelWithTime(HmIPSetVentilationLevel):
        ventilationTime: float
        "The time in seconds for switching the device to the ventilation level. Constraints: 0.1 - 16383"

    class HmIPSetVentilationState(_GroupIdRequestBody):
        ventilationState: str
        "The desired ventilation state. Allowed values: NO_VENTILATION, VENTILATION"

    class HmIPSetVentilationStateWithTime(HmIPSetVentilationState):
        ventilationTime: float
        "The time in seconds for switching the device to VENTILATION Constraints: 0.1 - 16383"

    class HmIPSetWateringSwitchState(_GroupIdRequestBody):
        wateringActive: bool
        "The desired watering switch state"

    class HmIPSetWateringSwitchStateWithTime(HmIPSetWateringSwitchState):
        wateringTime: float
        "The desired watering time. Constraints: 0.1 - 16383"


class HmIPGroupLinkedControlRequestPaths(Enum):
    setOpticalSignalBehaviour = "setOpticalSignalBehaviour"
    "Set the optical signal behaviour of the group"
    setSoundFileVolumeLevel = "setSoundFileVolumeLevel"
    "Sets the volume level and the sound file of the group"
    setVentilationLevel = "setVentilationLevel"
    "Set the ventilation level of all devices of the applicable type of a group to the given value"
    setVentilationLevelWithTime = "setVentilationLevelWithTime"
    "Set the ventilation level of all devices of the applicable type of a group to the given value for a certain time period (ventilationTime)"
    setVentilationState = "setVentilationState"
    "Set the ventilation state of all devices of the applicable type of a group to the given value"
    setVentilationStateWithTime = "setVentilationStateWithTime"
    "Set the ventilation state of all devices of the applicable type of a group to the given value for a certain time period (ventilationTime)"
    setWateringSwitchState = "setWateringSwitchState"
    "Set the watering switch state of all devices of the applicable type of a group to the given value"
    setWateringSwitchStateWithTime = "setWateringSwitchStateWithTime"
    "Set the watering switch state of all devices of the applicable type of a group to the given value for a certain time period (wateringTime)"
    startNotification = "startNotification"
    "Start the notification"
    stopNotification = "stopNotification"
    "Stop the notification"
    toggleVentilationState = "toggleVentilationState"
    "Toggle the ventilation state of all devices of the applicable type of a group to the given value"
    toggleWateringState = "toggleWateringState"
    "Toggle the watering state of all devices of the applicable type of a group to the given value"


#     HmIPGroupLinkedControlRequestPaths.setOpticalSignalBehaviour: HmIPSetOpticalSignalBehaviour,
#     HmIPGroupLinkedControlRequestPaths.setSoundFileVolumeLevel: SetSoundFileVolumeLevel,
#     HmIPGroupLinkedControlRequestPaths.setVentilationLevel: HmIPSetVentilationLevel,
#     HmIPGroupLinkedControlRequestPaths.setVentilationLevelWithTime: HmIPSetVentilationLevelWithTime,
#     HmIPGroupLinkedControlRequestPaths.setVentilationState: HmIPSetVentilationState,
#     HmIPGroupLinkedControlRequestPaths.setVentilationStateWithTime: HmIPSetVentilationStateWithTime,
#     HmIPGroupLinkedControlRequestPaths.setWateringSwitchState: HmIPSetWateringSwitchState,
#     HmIPGroupLinkedControlRequestPaths.setWateringSwitchStateWithTime: HmIPSetWateringSwitchStateWithTime,
#     HmIPGroupLinkedControlRequestPaths.startNotification: _GroupIdRequestBody,
#     HmIPGroupLinkedControlRequestPaths.stopNotification: _GroupIdRequestBody,
#     HmIPGroupLinkedControlRequestPaths.toggleVentilationState: _GroupIdRequestBody,
#     HmIPGroupLinkedControlRequestPaths.toggleWateringState: _GroupIdRequestBody,
