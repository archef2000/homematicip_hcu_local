from enum import Enum
from typing import Any, Literal, TypeAlias, TypedDict

from .hmip_system import SystemState


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


class DeviceControlRequestBodies:
    class HmIPDeviceControl(TypedDict):
        """Schema for the body of a control request to the HCU."""

        deviceId: str
        channelIndex: int

    class PullLatch(HmIPDeviceControl):
        """Schema for the body of a pull latch request."""

        authorizationPin: str

    class SendDoorCommand(HmIPDeviceControl):
        """Schema for the body of a send door command request."""

        doorCommand: str

    class SetDimLevel(HmIPDeviceControl):
        """Schema for the body of a set dim level request."""

        dimLevel: float
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

    class SetDoorLockActive(HmIPDeviceControl):
        """Schema for the body of a set door lock active request."""

        doorLockActive: bool
        "True to activate the door lock, False to deactivate it."

    class SetDoorLockActiveWithAuthorization(SetDoorLockActive):
        """Schema for the body of a set door lock active request with authorization."""

        authorizationPin: str

    class SetHueSaturationDimLevel(SetDimLevel):
        """Schema for the body of a set hue, saturation and dim level request."""

        hue: int
        "Constraints: 0 to 359"
        saturationLevel: float
        "Constraints: 0.0 to 1.0"

    class SetHueSaturationDimLevelWithTime(
        SetHueSaturationDimLevel, SetDimLevelWithTime
    ):
        pass

    class SetLockState(HmIPDeviceControl):
        """Locks, unlocks or opens a door lock device by setting the lock state."""

        authorizationPin: str
        targetLockState: str
        "LOCKED, UNLOCKED, OPEN"

    class SetMotionDetectionActive(HmIPDeviceControl):
        """Sets motion detection active state."""

        motionDetectionActive: bool

    class SetOpticalSignalBase(HmIPDeviceControl):
        """Base for optical signal (without time)."""

        simpleRGBColorState: str
        "BLACK BLUE GREEN TURQUOISE RED PURPLE YELLOW WHITE"
        opticalSignalBehaviour: str
        "OFF, ON, BLINKING_MIDDLE, FLASH_MIDDLE, BILLOW_MIDDLE"
        dimLevel: float
        "Constraints: 0.0 to 1.0"

    class SetOpticalSignalWithTime(SetOpticalSignalBase, WithTime):
        pass

    class SetPrimaryShadingLevel(HmIPDeviceControl):
        primaryShadingLevel: float
        "Constraints: 0.0 - 1.0"

    class SetSecondaryShadingLevel(SetPrimaryShadingLevel):
        secondaryShadingLevel: float
        "Constraints: 0.0 - 1.0"

    class SetShutterLevel(HmIPDeviceControl):
        "Shutter level depends on reference running time (50% means shutter will move 50% of configured reference running time)"

        shutterLevel: float
        "Constraints: 0.0 - 1.0"

    class SetSimpleRGBColorDimLevel(HmIPDeviceControl):
        simpleRGBColorState: str
        "BLACK BLUE GREEN TURQUOISE RED PURPLE YELLOW WHITE"
        dimLevel: float
        "Constraints: 0.0 - 1.0"

    class SetSimpleRGBColorDimLevelWithTime(SetSimpleRGBColorDimLevel, WithTime):
        pass

    class SetSlatsLevel(SetShutterLevel):
        slatsLevel: float
        "Constraints: 0.0 - 1.0"

    class SetSoundFileVolumeLevel(HmIPDeviceControl):
        soundFile: str
        "INTERNAL_SOUNDFILE, SOUNDFILE_001-SOUNDFILE_252, RANDOM_SOUNDFILE, OLD_VALUE, DO_NOT_CARE"
        volumeLevel: float
        "The volume level of the sound file. Constraints: 0.0 - 1.0"

    class SetSoundFileVolumeLevelWithTime(SetSoundFileVolumeLevel, WithTime):
        pass

    class SetSwitchState(HmIPDeviceControl):
        on: bool

    class SetSwitchStateWithTime(SetSwitchState):
        onTime: float

    class SetVentilationLevel(HmIPDeviceControl):
        ventilationLevel: float
        "Constraints: 0.0 - 1.0"

    class SetVentilationLevelWithTime(SetVentilationLevel):
        ventilationTime: float
        "Constraints: 0.1 - 16383"
        ventilationLevel: float
        "Constraints: 0.0 - 1.0"

    class SetVentilationState(HmIPDeviceControl):
        ventilationState: str
        "NO_VENTILATION, VENTILATION"

    class SetVentilationStateWithTime(SetVentilationState):
        ventilationTime: float
        "Constraints: 0.1 - 16383"

    class SetWateringSwitchState(HmIPDeviceControl):
        wateringActive: bool

    class SetWateringSwitchStateWithTime(SetWateringSwitchState):
        wateringTime: float
        "The desired watering time (in s). Constraints: 0.1 - 16383"

    class StartLightScene(HmIPDeviceControl):
        id: int
        "The ID of the light scene to start."
        dimLevel: float
        "Constraints: 0.0 - 1.0"


class HmIPDeviceControlRequestPaths(Enum):
    acknowledgeFrostProtectionError = (
        "/hmip/device/control/acknowledgeFrostProtectionError"
    )
    "Acknowledges the frost protection error for a device channel."
    pullLatch = "/hmip/device/control/pullLatch"
    "Triggers the latch of a door opening device by activating the switching output of the target device channel for the configured duration."
    resetBlocking = "/hmip/device/control/resetBlocking"
    "Sends a reset of the blockings for a device channel."
    resetEnergyCounter = "/hmip/device/control/resetEnergyCounter"
    "Resets the energy counter of the specified device."
    resetPassageCounter = "/hmip/device/control/resetPassageCounter"
    "Resets the passage counter of the specified device."
    resetWaterVolume = "/hmip/device/control/resetWaterVolume"
    "Resets the water volume counter of the specified device."
    sendDoorCommand = "/hmip/device/control/sendDoorCommand"
    "Sends a door command to control a channel of a (garage) door device."
    setColorTemperatureDimLevel = "/hmip/device/control/setColorTemperatureDimLevel"
    "Sets the color temperature and dim level of a device channel to the given value."
    setColorTemperatureDimLevelWithTime = (
        "/hmip/device/control/setColorTemperatureDimLevelWithTime"
    )
    "Sets the color temperature and dim level of a device channel to the given value over a specified duration."
    setDimLevel = "/hmip/device/control/setDimLevel"
    "Sets the dim level of a device channel to the given value."
    setDimLevelWithTime = "/hmip/device/control/setDimLevelWithTime"
    "Sets the dim level of a device channel to the given value for a certain time period (onTime)"
    setDoorLockActive = "/hmip/device/control/setDoorLockActive"
    "Activates or deactivates the locking of a door for a device channel."
    setDoorLockActiveWithAuthorization = (
        "/hmip/device/control/setDoorLockActiveWithAuthorization"
    )
    "Activates or deactivates the locking of a door for a device channel with authorization."
    setFavoriteShadingPosition = "/hmip/device/control/setFavoriteShadingPosition"
    "Sets favorite shading position"
    setHueSaturationDimLevel = "/hmip/device/control/setHueSaturationDimLevel"
    "Sets the hue, saturation and dim level of a device channel to the given value"
    setHueSaturationDimLevelWithTime = (
        "/hmip/device/control/setHueSaturationDimLevelWithTime"
    )
    "Sets the hue, saturation and dim level of a device channel to the given value for a certain time period (onTime)"
    setIdentify = "/hmip/device/control/setIdentify"
    "Sets the Identify"
    setIdentifyOem = "/hmip/device/control/setIdentifyOem"
    "Sets the identify of oem"
    setLockState = "/hmip/device/control/setLockState"
    "Locks, unlocks or opens a door lock device by setting the lock state."
    setMotionDetectionActive = "/hmip/device/control/setMotionDetectionActive"
    "Sets the motion detection active state of a device channel."
    setOpticalSignal = "/hmip/device/control/setOpticalSignal"
    "Sets the optical signal / color / behaviour / dim level"
    setOpticalSignalWithTime = "/hmip/device/control/setOpticalSignalWithTime"
    "Sets the optical signal for a certain time period (onTime)"
    setPrimaryShadingLevel = "/hmip/device/control/setPrimaryShadingLevel"
    setSecondaryShadingLevel = "/hmip/device/control/setSecondaryShadingLevel"
    setShutterLevel = "/hmip/device/control/setShutterLevel"
    setSimpleRGBColorDimLevel = "/hmip/device/control/setSimpleRGBColorDimLevel"
    setSimpleRGBColorDimLevelWithTime = (
        "/hmip/device/control/setSimpleRGBColorDimLevelWithTime"
    )
    setSlatsLevel = "/hmip/device/control/setSlatsLevel"
    setSoundFileVolumeLevel = "/hmip/device/control/setSoundFileVolumeLevel"
    setSoundFileVolumeLevelWithTime = (
        "/hmip/device/control/setSoundFileVolumeLevelWithTime"
    )
    setSwitchState = "/hmip/device/control/setSwitchState"
    setSwitchStateForIdentify = "/hmip/device/control/setSwitchStateForIdentify"
    setSwitchStateWithTime = "/hmip/device/control/setSwitchStateWithTime"
    setVentilationLevel = "/hmip/device/control/setVentilationLevel"
    setVentilationLevelWithTime = "/hmip/device/control/setVentilationLevelWithTime"
    setVentilationState = "/hmip/device/control/setVentilationState"
    setVentilationStateWithTime = "/hmip/device/control/setVentilationStateWithTime"
    setWateringSwitchState = "/hmip/device/control/setWateringSwitchState"
    setWateringSwitchStateWithTime = (
        "/hmip/device/control/setWateringSwitchStateWithTime"
    )
    startImpulse = "/hmip/device/control/startImpulse"
    startLightScene = "/hmip/device/control/startLightScene"
    stop = "/hmip/device/control/stop"
    toggleCameraNightVision = "/hmip/device/control/toggleCameraNightVision"
    toggleGarageDoorState = "/hmip/device/control/toggleGarageDoorState"
    toggleShadingState = "/hmip/device/control/toggleShadingState"
    toggleSwitchState = "/hmip/device/control/toggleSwitchState"
    toggleVentilationState = "/hmip/device/control/toggleVentilationState"
    toggleWateringState = "/hmip/device/control/toggleWateringState"

    #    HmIPDeviceControlRequestPaths.acknowledgeFrostProtectionError: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.pullLatch: PullLatch,
    #    HmIPDeviceControlRequestPaths.resetBlocking: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.resetEnergyCounter: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.resetPassageCounter: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.resetWaterVolume: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.sendDoorCommand: SendDoorCommand,
    #    HmIPDeviceControlRequestPaths.setColorTemperatureDimLevel: SetColorTemperatureDimLevel,
    #    HmIPDeviceControlRequestPaths.setColorTemperatureDimLevelWithTime: SetColorTemperatureDimLevelWithTime,
    #    HmIPDeviceControlRequestPaths.setDimLevel: SetDimLevel,
    #    HmIPDeviceControlRequestPaths.setDimLevelWithTime: SetDimLevelWithTime,
    #    HmIPDeviceControlRequestPaths.setDoorLockActive: SetDoorLockActive,
    #    HmIPDeviceControlRequestPaths.setDoorLockActiveWithAuthorization: SetDoorLockActiveWithAuthorization,
    #    HmIPDeviceControlRequestPaths.setFavoriteShadingPosition: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.setHueSaturationDimLevel: SetHueSaturationDimLevel,
    #    HmIPDeviceControlRequestPaths.setHueSaturationDimLevelWithTime: SetHueSaturationDimLevelWithTime,
    #    HmIPDeviceControlRequestPaths.setIdentify: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.setIdentifyOem: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.setLockState: SetLockState,
    #    HmIPDeviceControlRequestPaths.setMotionDetectionActive: SetMotionDetectionActive,
    #    HmIPDeviceControlRequestPaths.setOpticalSignal: SetOpticalSignalBase,
    #    HmIPDeviceControlRequestPaths.setOpticalSignalWithTime: SetOpticalSignalWithTime,
    #    HmIPDeviceControlRequestPaths.setPrimaryShadingLevel: SetPrimaryShadingLevel,
    #    HmIPDeviceControlRequestPaths.setSecondaryShadingLevel: SetSecondaryShadingLevel,
    #    HmIPDeviceControlRequestPaths.setShutterLevel: SetShutterLevel,
    #    HmIPDeviceControlRequestPaths.setSimpleRGBColorDimLevel: SetSimpleRGBColorDimLevel,
    #    HmIPDeviceControlRequestPaths.setSimpleRGBColorDimLevelWithTime: SetSimpleRGBColorDimLevelWithTime,
    #    HmIPDeviceControlRequestPaths.setSlatsLevel: SetSlatsLevel,
    #    HmIPDeviceControlRequestPaths.setSoundFileVolumeLevel: SetSoundFileVolumeLevel,
    #    HmIPDeviceControlRequestPaths.setSoundFileVolumeLevelWithTime: SetSoundFileVolumeLevelWithTime,
    #    HmIPDeviceControlRequestPaths.setSwitchState: SetSwitchState,
    #    HmIPDeviceControlRequestPaths.setSwitchStateForIdentify: SetSwitchState,
    #    HmIPDeviceControlRequestPaths.setSwitchStateWithTime: SetSwitchStateWithTime,
    #    HmIPDeviceControlRequestPaths.setVentilationLevel: SetVentilationLevel,
    #    HmIPDeviceControlRequestPaths.setVentilationLevelWithTime: SetVentilationLevelWithTime,
    #    HmIPDeviceControlRequestPaths.setVentilationState: SetVentilationState,
    #    HmIPDeviceControlRequestPaths.setVentilationStateWithTime: SetVentilationStateWithTime,
    #    HmIPDeviceControlRequestPaths.setWateringSwitchState: SetWateringSwitchState,
    #    HmIPDeviceControlRequestPaths.setWateringSwitchStateWithTime: SetWateringSwitchStateWithTime,
    #    HmIPDeviceControlRequestPaths.startImpulse: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.startLightScene: StartLightScene,
    #    HmIPDeviceControlRequestPaths.stop: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.toggleCameraNightVision: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.toggleGarageDoorState: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.toggleShadingState: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.toggleSwitchState: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.toggleVentilationState: HmIPDeviceControl,
    #    HmIPDeviceControlRequestPaths.toggleWateringState: HmIPDeviceControl,


class GroupLinkedControlRequestBodies:
    class GroupId(TypedDict):
        groupId: str
        "The ID of the group to control."

    class HmIPSetOpticalSignalBehaviour(GroupId):
        onTime: float
        "The time in seconds for switching the group"
        simpleRGBColor: str
        "Allowed values: BLACK BLUE GREEN TURQUOISE RED PURPLE YELLOW WHITE"

    class SetSoundFileVolumeLevel(GroupId):
        onTime: float
        "The time in seconds for switching the group"
        soundFile: str
        "INTERNAL_SOUNDFILE, SOUNDFILE_001-SOUNDFILE_252, RANDOM_SOUNDFILE, OLD_VALUE, DO_NOT_CARE"
        volumeLevel: float
        "The volume level of the sound file. Constraints: 0.0 - 1.0"

    class HmIPSetVentilationLevel(GroupId):
        ventilationLevel: float
        "The desired ventilation level. Constraints: 0.0 - 1.0"

    class HmIPSetVentilationLevelWithTime(HmIPSetVentilationLevel):
        ventilationTime: float
        "The time in seconds for switching the device to the ventilation level. Constraints: 0.1 - 16383"

    class HmIPSetVentilationState(GroupId):
        ventilationState: str
        "The desired ventilation state. Allowed values: NO_VENTILATION, VENTILATION"

    class HmIPSetVentilationStateWithTime(HmIPSetVentilationState):
        ventilationTime: float
        "The time in seconds for switching the device to VENTILATION Constraints: 0.1 - 16383"

    class HmIPSetWateringSwitchState(GroupId):
        wateringActive: bool
        "The desired watering switch state"

    class HmIPSetWateringSwitchStateWithTime(HmIPSetWateringSwitchState):
        wateringTime: float
        "The desired watering time. Constraints: 0.1 - 16383"


class HmIPGroupLinkedControlRequestPaths(Enum):
    setOpticalSignalBehaviour = "/hmip/group/linked/control/setOpticalSignalBehaviour"
    "Set the optical signal behaviour of the group"
    setSoundFileVolumeLevel = "/hmip/group/linked/control/setSoundFileVolumeLevel"
    "Sets the volume level and the sound file of the group"
    setVentilationLevel = "/hmip/group/linked/control/setVentilationLevel"
    "Set the ventilation level of all devices of the applicable type of a group to the given value"
    setVentilationLevelWithTime = (
        "/hmip/group/linked/control/setVentilationLevelWithTime"
    )
    "Set the ventilation level of all devices of the applicable type of a group to the given value for a certain time period (ventilationTime)"
    setVentilationState = "/hmip/group/linked/control/setVentilationState"
    "Set the ventilation state of all devices of the applicable type of a group to the given value"
    setVentilationStateWithTime = (
        "/hmip/group/linked/control/setVentilationStateWithTime"
    )
    "Set the ventilation state of all devices of the applicable type of a group to the given value for a certain time period (ventilationTime)"
    setWateringSwitchState = "/hmip/group/linked/control/setWateringSwitchState"
    "Set the watering switch state of all devices of the applicable type of a group to the given value"
    setWateringSwitchStateWithTime = (
        "/hmip/group/linked/control/setWateringSwitchStateWithTime"
    )
    "Set the watering switch state of all devices of the applicable type of a group to the given value for a certain time period (wateringTime)"
    startNotification = "/hmip/group/linked/control/startNotification"
    "Start the notification"
    stopNotification = "/hmip/group/linked/control/stopNotification"
    "Stop the notification"
    toggleVentilationState = "/hmip/group/linked/control/toggleVentilationState"
    "Toggle the ventilation state of all devices of the applicable type of a group to the given value"
    toggleWateringState = "/hmip/group/linked/control/toggleWateringState"
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


class GroupHeatingRequestBodies:
    class GroupId(TypedDict):
        groupId: str
        "The ID of the group to control."

    class HmIPActivatePartyMode(GroupId):
        temperature: float
        "The target temperature for the party mode. Constraints: 5.0 to 30.0"
        endTime: str
        "The end time of the vacation mode. Constraints: yyyy_MM_dd HH:mm"

    class HmIPSetActiveProfile(GroupId):
        profileIndex: str
        "Allowed values: PROFILE_1-PROFILE_6"

    class HmIPSetBoost(GroupId):
        boost: bool
        "true to activate the boost function, false to deactivate"

    class HmIPSetControlMode(GroupId):
        controlMode: Literal["AUTOMATIC", "MANUAL", "ECO"]
        "Allowed values: AUTOMATIC, MANUAL, ECO"

    class HmIPSetHotWaterOnTime(GroupId):
        onTime: float
        "Duration in minutes"

    class HmIPSetHotWaterProfileMode(GroupId):
        profileMode: Literal["AUTOMATIC", "MANUAL"]
        "Allowed values: AUTOMATIC, MANUAL"

    class HmIPSetHotWaterState(GroupId):
        on: bool

    class HmIPSetPointTemperature(GroupId):
        setPointTemperature: float
        "The new set point temperature value. Constraints: minTemperature to maxTemperature"


class HmIPGroupHeatingRequestPaths(Enum):
    activatePartyMode = "/hmip/group/heating/activatePartyMode"
    "Activate the party mode"
    setActiveProfile = "/hmip/group/heating/setActiveProfile"
    "Activate the profile on the applicable devices in the heating group"
    setBoost = "/hmip/group/heating/setBoost"
    "Activate or deactivate the boost function of the applicable devices in a heating group"
    setControlMode = "/hmip/group/heating/setControlMode"
    "Set the control mode of the applicable devices in a heating group"
    setHotWaterOnTime = "/hmip/group/heating/setHotWaterOnTime"
    "Set the duration for producing hot water"
    setHotWaterProfileMode = "/hmip/group/heating/setHotWaterProfileMode"
    "Enable / Disable profile"
    setHotWaterState = "/hmip/group/heating/setHotWaterState"
    "Start / Stop making hot water"
    setSetPointTemperature = "/hmip/group/heating/setSetPointTemperature"
    "Set the set point temperature of the applicable devices in a heating group"


#    HmIPGroupHeatingRequestPaths.activatePartyMode: HmIPActivatePartyMode,
#    HmIPGroupHeatingRequestPaths.setActiveProfile: HmIPSetActiveProfile,
#    HmIPGroupHeatingRequestPaths.setBoost: HmIPSetBoost,
#    HmIPGroupHeatingRequestPaths.setControlMode: HmIPSetControlMode,
#    HmIPGroupHeatingRequestPaths.setHotWaterOnTime: HmIPSetHotWaterOnTime,
#    HmIPGroupHeatingRequestPaths.setHotWaterProfileMode: HmIPSetHotWaterProfileMode,
#    HmIPGroupHeatingRequestPaths.setHotWaterState: HmIPSetHotWaterState,
#    HmIPGroupHeatingRequestPaths.setSetPointTemperature: HmIPSetPointTemperature,


class HomeSecurityRequestBodies:
    class SetZonesActivation(TypedDict):
        zonesActivation: dict[str, bool]
        """
        A map for functional zone identifier to activation state
        `"EXTERNAL": true,
        "INTERNAL": true`
        """

    class SetExtendedZonesActivation(SetZonesActivation):
        ignoreLowBat: bool
        "Determines if lowbat should be ignored"


class HmIPHomeSecurityRequestPaths(Enum):
    acknowledgeSafetyAlarm = "/hmip/home/security/acknowledgeSafetyAlarm"
    "Acknowledges the safety alarm"
    setExtendedZonesActivation = "/hmip/home/security/setExtendedZonesActivation"
    "Set the extended activation state for one or more security zones"
    setZonesActivation = "/hmip/home/security/setZonesActivation"
    "Set the activation state for one or more security zones"


# acknowledgeSafetyAlarm =
# setExtendedZonesActivation = SetExtendedZonesActivation
# setZonesActivation = SetZonesActivation


class RoleRequestBodies:
    class EnableSimpleRule(TypedDict):
        ruleId: str
        "id of the automation in question"
        enabled: bool
        "Flag if the automation will be enabled or disabled"


class HmIPRoleRequestPaths(Enum):
    enableSimpleRule = "/hmip/rule/enableSimpleRule"


class HomeRequestBodies:
    class Empty(TypedDict):
        pass


class HmIPHomeRequestPaths(Enum):
    checkAuthToken = "/hmip/home/checkAuthToken"
    "Check if an AuthToken is still valid for a client on a server. Use case: Check if a client still has a valid token in a multi HAP environment (multiple HAPs / installations are paired via app)"
    getState = "/hmip/home/getState"
    "Get the state of the home"
    getStateForClient = "/hmip/home/getStateForClient"
    "Get the state that is relevant for the requesting (smart watch) client"
    getSystemState = "/hmip/home/getSystemState"
    "Get the current state of the system"


class _TemperatureRequestBody(TypedDict):
    temperature: float
    "The temperature that should be used during vacation mode Constraints: 5.0 to 30.0"


class HomeHeatingRequestBodies:
    class ActivateAbsenceWithDuration(TypedDict):
        duration: int
        "The amount of minutes that the economy mode should be activated"

    class ActivateAbsenceWithPeriod(TypedDict):
        endTime: str
        "The end time of the economy mode Constraints: yyyy_MM_dd HH:mm"

    class ActivateAbsenceWithFuturePeriod(ActivateAbsenceWithPeriod):
        startTime: str
        "The start time of the economy mode Constraints: yyyy_MM_dd HH:mm"

    class ActivateFutureVacation(
        ActivateAbsenceWithFuturePeriod, _TemperatureRequestBody
    ):
        pass

    class ActivateVacation(ActivateAbsenceWithPeriod, _TemperatureRequestBody):
        pass

    class SetCooling(TypedDict):
        cooling: bool
        "Flag that determines whether the cooling should be enabled or deactivated"


class HmIPHomeHeatingRequestPaths(Enum):
    activateAbsencePermanent = "/hmip/home/heating/activateAbsencePermanent"
    "Activate the economy mode"
    activateAbsenceWithDuration = "/hmip/home/heating/activateAbsenceWithDuration"
    "Activate the economy mode for the given amount of minutes"
    activateAbsenceWithFuturePeriod = (
        "/hmip/home/heating/activateAbsenceWithFuturePeriod"
    )
    "Activate the economy mode for the given period"
    activateAbsenceWithPeriod = "/hmip/home/heating/activateAbsenceWithPeriod"
    "Activate the economy mode for the given period"
    activateFutureVacation = "/hmip/home/heating/activateFutureVacation"
    "Activate the vacation mode"
    activateVacation = "/hmip/home/heating/activateVacation"
    "Activate the vacation mode"
    deactivateAbsence = "/hmip/home/heating/deactivateAbsence"
    "Deactivate the economy mode"
    deactivateVacation = "/hmip/home/heating/deactivateVacation"
    "Deactivate the vacation mode"
    setCooling = "/hmip/home/heating/setCooling"
    "Activate or deactivate the cooling mode"


# activateAbsenceWithDuration = ActivateAbsenceWithDuration
# activateAbsenceWithFuturePeriod = ActivateAbsenceWithFuturePeriod
# activateAbsenceWithPeriod = ActivateAbsenceWithPeriod
# activateFutureVacation = ActivateFutureVacation
# activateVacation = ActivateVacation
# deactivateAbsence =
# deactivateVacation =
# setCooling = SetCooling


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
    setProfileMode = "/hmip/group/profile/setProfileMode"
    "Set the profile mode for devices, i.e. channels (e.g. manual or automatic)"


# HmIPGroupProfileRequestPaths.setProfileMode: SetProfileModeRequestBody,


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
    setColorTemperatureDimLevel = "/hmip/group/switching/setColorTemperatureDimLevel"
    "Sets the color temperature and dim level of a group to the given value"
    setColorTemperatureDimLevelWithTime = (
        "/hmip/group/switching/setColorTemperatureDimLevelWithTime"
    )
    "Sets the color temperature and dim level of a group to the given value for a certain time period (onTime)"
    setDimLevel = "/hmip/group/switching/setDimLevel"
    setDimLevelWithTime = "/hmip/group/switching/setDimLevelWithTime"
    setFavoriteShadingPosition = "/hmip/group/switching/setFavoriteShadingPosition"
    setHueSaturationDimLevel = "/hmip/group/switching/setHueSaturationDimLevel"
    setHueSaturationDimLevelWithTime = (
        "/hmip/group/switching/setHueSaturationDimLevelWithTime"
    )
    setPrimaryShadingLevel = "/hmip/group/switching/setPrimaryShadingLevel"
    setSecondaryShadingLevel = "/hmip/group/switching/setSecondaryShadingLevel"
    setState = "/hmip/group/switching/setState"
    setSwitchStateWithTime = "/hmip/group/switching/setSwitchStateWithTime"
    startLightScene = "/hmip/group/switching/startLightScene"
    stop = "/hmip/group/switching/stop"
    toggleShadingState = "/hmip/group/switching/toggleShadingState"
    toggleSwitchState = "/hmip/group/switching/toggleSwitchState"


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


HmIPSystemRequestPaths: TypeAlias = (
    HmIPDeviceControlRequestPaths
    | HmIPGroupLinkedControlRequestPaths
    | HmIPGroupHeatingRequestPaths
    | HmIPHomeSecurityRequestPaths
    | HmIPRoleRequestPaths
    | HmIPHomeRequestPaths
    | HmIPHomeHeatingRequestPaths
    | HmIPGroupProfileRequestPaths
    | HmIPGroupSwitchingRequestPaths
)

HmIPSystemRequestBodies: TypeAlias = (
    DeviceControlRequestBodies
    | GroupLinkedControlRequestBodies
    | GroupHeatingRequestBodies
    | HomeSecurityRequestBodies
    | RoleRequestBodies
    | HomeRequestBodies
    | HomeHeatingRequestBodies
    | GroupProfileRequestBodies
    | GroupSwitchingRequestBodies
)


class HmIpSystemResponseBody(TypedDict):
    code: int


class HmIPSystemGetStateResponseBody(HmIpSystemResponseBody):
    body: dict[str, Any]  # pyright: ignore[reportExplicitAny]


class HmIPSystemGetStateForClientResponseBody(HmIpSystemResponseBody):
    body: dict[str, Any]  # pyright: ignore[reportExplicitAny]


class HmIPSystemGetSystemStateResponseBody(HmIpSystemResponseBody):
    body: SystemState


class HmIPSystemSetExtendedZonesActivationResponseBody(HmIpSystemResponseBody):
    body: dict[str, Any]  # pyright: ignore[reportExplicitAny]
