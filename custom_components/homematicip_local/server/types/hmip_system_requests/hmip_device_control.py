from enum import Enum
from typing import TypedDict


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
        saturationLevel: int
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
    acknowledgeFrostProtectionError = "acknowledgeFrostProtectionError"
    "Acknowledges the frost protection error for a device channel."
    pullLatch = "pullLatch"
    "Triggers the latch of a door opening device by activating the switching output of the target device channel for the configured duration."
    resetBlocking = "resetBlocking"
    "Sends a reset of the blockings for a device channel."
    resetEnergyCounter = "resetEnergyCounter"
    "Resets the energy counter of the specified device."
    resetPassageCounter = "resetPassageCounter"
    "Resets the passage counter of the specified device."
    resetWaterVolume = "resetWaterVolume"
    "Resets the water volume counter of the specified device."
    sendDoorCommand = "sendDoorCommand"
    "Sends a door command to control a channel of a (garage) door device."
    setColorTemperatureDimLevel = "setColorTemperatureDimLevel"
    "Sets the color temperature and dim level of a device channel to the given value."
    setColorTemperatureDimLevelWithTime = "setColorTemperatureDimLevelWithTime"
    "Sets the color temperature and dim level of a device channel to the given value over a specified duration."
    setDimLevel = "setDimLevel"
    "Sets the dim level of a device channel to the given value."
    setDimLevelWithTime = "setDimLevelWithTime"
    "Sets the dim level of a device channel to the given value for a certain time period (onTime)"
    setDoorLockActive = "setDoorLockActive"
    "Activates or deactivates the locking of a door for a device channel."
    setDoorLockActiveWithAuthorization = "setDoorLockActiveWithAuthorization"
    "Activates or deactivates the locking of a door for a device channel with authorization."
    setFavoriteShadingPosition = "setFavoriteShadingPosition"
    "Sets favorite shading position"
    setHueSaturationDimLevel = "setHueSaturationDimLevel"
    "Sets the hue, saturation and dim level of a device channel to the given value"
    setHueSaturationDimLevelWithTime = "setHueSaturationDimLevelWithTime"
    "Sets the hue, saturation and dim level of a device channel to the given value for a certain time period (onTime)"
    setIdentify = "setIdentify"
    "Sets the Identify"
    # 6.8.1.18 - 6.8.1.48 additional endpoints
    setIdentifyOem = "setIdentifyOem"
    "Sets the identify of oem"
    setLockState = "setLockState"
    "Locks, unlocks or opens a door lock device by setting the lock state."
    setMotionDetectionActive = "setMotionDetectionActive"
    "Sets the motion detection active state of a device channel."
    setOpticalSignal = "setOpticalSignal"
    "Sets the optical signal / color / behaviour / dim level"
    setOpticalSignalWithTime = "setOpticalSignalWithTime"
    "Sets the optical signal for a certain time period (onTime)"
    setPrimaryShadingLevel = "setPrimaryShadingLevel"
    setSecondaryShadingLevel = "setSecondaryShadingLevel"
    setShutterLevel = "setShutterLevel"
    setSimpleRGBColorDimLevel = "setSimpleRGBColorDimLevel"
    setSimpleRGBColorDimLevelWithTime = "setSimpleRGBColorDimLevelWithTime"
    setSlatsLevel = "setSlatsLevel"
    setSoundFileVolumeLevel = "setSoundFileVolumeLevel"
    setSoundFileVolumeLevelWithTime = "setSoundFileVolumeLevelWithTime"
    setSwitchState = "setSwitchState"
    setSwitchStateForIdentify = "setSwitchStateForIdentify"
    setSwitchStateWithTime = "setSwitchStateWithTime"
    setVentilationLevel = "setVentilationLevel"
    setVentilationLevelWithTime = "setVentilationLevelWithTime"
    setVentilationState = "setVentilationState"
    setVentilationStateWithTime = "setVentilationStateWithTime"
    setWateringSwitchState = "setWateringSwitchState"
    setWateringSwitchStateWithTime = "setWateringSwitchStateWithTime"
    startImpulse = "startImpulse"
    startLightScene = "startLightScene"
    stop = "stop"
    toggleCameraNightVision = "toggleCameraNightVision"
    toggleGarageDoorState = "toggleGarageDoorState"
    toggleShadingState = "toggleShadingState"
    toggleSwitchState = "toggleSwitchState"
    toggleVentilationState = "toggleVentilationState"
    toggleWateringState = "toggleWateringState"


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
