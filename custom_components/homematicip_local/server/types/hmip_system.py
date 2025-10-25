from typing import Literal, TypeAlias, TypedDict


class UserRoleChangeStatus(TypedDict):
    clientId: str
    clientLabel: str
    timestamp: int


FriendlyName: TypeAlias = dict[str, str]
"<language>:<friendly_name>"


class _BaseClient(TypedDict):
    id: str
    label: str
    homeId: str
    createdAtTimestamp: int
    lastSeenAtTimestamp: int


class AppClient(_BaseClient):
    clientType: Literal["APP"]
    userRole: Literal["ADMIN", "USER"]
    userRoleChangeStatus: UserRoleChangeStatus
    adminInitializationRequired: bool


class PluginClient(_BaseClient):
    clientType: Literal["PLUGIN"]
    pluginId: str
    partnerIdentifier: None
    friendlyName: FriendlyName
    visible: bool


VentilationState = Literal["NO_VENTILATION", "VENTILATION"]

ProfileMode: TypeAlias = Literal["AUTOMATIC", "MANUAL"]

Client: TypeAlias = AppClient | PluginClient

Clients: TypeAlias = dict[str, Client]

ConnectionType: TypeAlias = Literal["HMIP_LAN", "HMIP_RF"]


DeviceArchetype: TypeAlias = Literal["HMIP"]


ActionParameter: TypeAlias = Literal["NOT_CUSTOMISABLE"]


class PushButtonSupportedOptionalFeatures(TypedDict):
    IFeatureDoorLockAuthorizationSensorChannel: bool
    IOptionalFeatureLongPressSupported: bool
    IFeatureGarageGroupSensorChannel: bool
    IOptionalFeatureDoorBellSensorEventTimestamp: bool
    IOptionalFeatureDoublePressTime: bool
    IFeatureLightGroupSensorChannel: bool
    IOptionalFeatureAcousticSendStateEnabled: bool
    IFeatureAccessAuthorizationSensorChannel: bool
    IFeatureWateringGroupSensorChannel: bool
    IFeatureVentilationGroupSensorChannel: bool
    IFeatureShadingGroupSensorChannel: bool


class _BaseFunctionalChannel(TypedDict):
    label: str
    deviceId: str
    index: int
    groupIndex: int
    groups: list[str]


class SingleKeyFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["SINGLE_KEY_CHANNEL"]
    channelRole: None | Literal["KEY_OR_SWITCH_FOR_GROUP"]
    supportedOptionalFeatures: PushButtonSupportedOptionalFeatures
    visibleChannelIndex: int
    doorBellSensorEventTimestamp: None
    acousticSendStateEnabled: bool
    actionParameter: ActionParameter
    doublePressTime: float


LiveUpdateState: TypeAlias = Literal["LIVE_UPDATE_NOT_SUPPORTED"]
OEM: TypeAlias = Literal["eQ-3"] | str
UpdateState: TypeAlias = Literal["UP_TO_DATE", "TRANSFERING_UPDATE"]


class HeatingThermostatSupportedOptionalFeatures(TypedDict):
    IOptionalFeatureBoostSignalColor: bool
    IOptionalFeatureThermostatCoolingSupported: bool


class HeatingThermostatFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["HEATING_THERMOSTAT_CHANNEL"]
    "uuid v4"
    channelRole: Literal["HEATING_CONTROLLER"]
    supportedOptionalFeatures: HeatingThermostatSupportedOptionalFeatures
    temperatureOffset: float
    valvePosition: float | None
    "during adaption: None"
    setPointTemperature: float
    valveState: Literal["ADAPTION_DONE", "ADAPTION_IN_PROGRESS"]
    valveActualTemperature: float
    boostSignalHue: None
    boostSignalSaturation: None
    boostSignalLevel: None


class DeviceOperationlockSupportedOptionalFeatures(TypedDict):
    IFeatureDeviceParticulateMatterSensorCommunicationError: bool
    IFeatureDeviceCoProRestart: bool
    IFeatureDeviceOverheated: bool
    IFeatureDeviceMountingModuleError: bool
    IOptionalFeatureInvertedDisplayColors: bool
    IFeatureTicVersionError: bool
    IFeatureDeviceDaliBusError: bool
    IOptionalFeatureDutyCycle: bool
    IFeatureMulticastRouter: bool
    IOptionalFeatureDeviceSwitchChannelMode: bool
    IFeaturePowerShortCircuit: bool
    IOptionalFeatureDeviceValveError: bool
    IFeatureDeviceDriveModeError: bool
    IFeatureDeviceTempSensorError: bool
    IFeatureDeviceTemperatureHumiditySensorCommunicationError: bool
    IFeatureDeviceDriveError: bool
    IFeatureRssiValue: bool
    IFeatureNoDataFromLinkyError: bool
    IFeatureBusConfigMismatch: bool
    IOptionalFeatureOperationDays: bool
    IOptionalFeatureDeviceFrostProtectionError: bool
    IOptionalFeatureDisplayMode: bool
    IFeatureDeviceOverloaded: bool
    IOptionalFeatureDisplayContrast: bool
    IFeatureDeviceIdentify: bool
    IOptionalFeatureLowBat: bool
    IOptionalFeatureMountingOrientation: bool
    IFeatureDeviceTemperatureOutOfRange: bool
    IFeatureDeviceTemperatureHumiditySensorError: bool
    IOptionalFeatureDeviceErrorLockJammed: bool
    IOptionalFeatureDeviceAliveSignalEnabled: bool
    IFeatureProfilePeriodLimit: bool
    IFeatureDeviceCoProUpdate: bool
    IFeatureDeviceSensorCommunicationError: bool
    IOptionalFeatureDefaultLinkedGroup: bool
    IFeatureDevicePowerFailure: bool
    IOptionalFeatureAltitude: bool
    IOptionalFeatureDeviceInputLayoutMode: bool
    IFeatureShortCircuitDataLine: bool
    IFeatureDeviceSensorError: bool
    IOptionalFeatureDeviceOperationMode: bool
    IFeatureDeviceCommunicationError: bool
    IFeatureDeviceUndervoltage: bool
    IFeatureDeviceParticulateMatterSensorError: bool
    IFeatureDeviceCoProError: bool
    IFeatureDataDecodingFailedError: bool
    IOptionalFeatureDeviceWaterError: bool


class DeviceOperationlockFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["DEVICE_OPERATIONLOCK"]
    unreach: bool
    lowBat: bool
    routerModuleEnabled: bool
    multicastRoutingEnabled: bool
    routerModuleSupported: bool
    rssiDeviceValue: int | None
    rssiPeerValue: int | None
    configPending: bool
    dutyCycle: bool
    deviceOverloaded: bool
    coProUpdateFailure: bool
    coProFaulty: bool
    coProRestartNeeded: bool
    deviceUndervoltage: bool
    deviceOverheated: bool
    temperatureOutOfRange: bool
    devicePowerFailureDetected: bool
    supportedOptionalFeatures: DeviceOperationlockSupportedOptionalFeatures
    busConfigMismatch: None
    powerShortCircuit: None
    shortCircuitDataLine: None
    profilePeriodLimitReached: None
    mountingOrientation: Literal["LEFT"] | None
    controlsMountingOrientation: Literal["UPSIDE_UP"] | None
    displayMountingOrientation: None
    displayMode: None
    invertedDisplayColors: None
    temperatureHumiditySensorError: None
    temperatureHumiditySensorCommunicationError: None
    particulateMatterSensorError: None
    particulateMatterSensorCommunicationError: None
    sensorError: None
    sensorCommunicationError: None
    displayContrast: None | int
    lockJammed: None
    deviceDriveError: None
    deviceDriveModeError: None
    deviceCommunicationError: None
    daliBusState: None
    deviceOperationMode: str | None
    defaultLinkedGroup: list[None]
    operationDays: None
    deviceAliveSignalEnabled: None
    altitude: None
    temperatureSensorError: None
    mountingModuleError: None
    inputLayoutMode: None
    switchChannelMode: None
    frostProtectionError: None
    frostProtectionErrorAcknowledged: None
    valveFlowError: None
    valveWaterError: None
    noDataFromLinkyError: None
    dataDecodingFailedError: None
    ticVersionError: None
    operationLockActive: bool


class HeatingThermostatDevice(TypedDict):
    id: str
    type: Literal["HEATING_THERMOSTAT", "HEATING_THERMOSTAT_EVO"]
    homeId: str
    "uuid v4"
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str, DeviceOperationlockFunctionalChannel | HeatingThermostatFunctionalChannel
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    automaticValveAdaptionNeeded: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "1.4.8, 2.2.22"
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-eTRV-2 I9F", "HmIP-eTRV-E"]
    "HmIP-eTRV-2 I9F, HmIP-eTRV-E"
    firmwareVersion: str
    "1.4.8, 2.2.22"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class DeviceBaseSupportedOptionalFeatures(TypedDict):
    IFeatureDeviceParticulateMatterSensorCommunicationError: bool
    IFeatureDeviceCoProRestart: bool
    IFeatureDeviceOverheated: bool
    IFeatureDeviceMountingModuleError: bool
    IOptionalFeatureInvertedDisplayColors: bool
    IFeatureTicVersionError: bool
    IFeatureDeviceDaliBusError: bool
    IOptionalFeatureDutyCycle: bool
    IFeatureMulticastRouter: bool
    IOptionalFeatureDeviceSwitchChannelMode: bool
    IFeaturePowerShortCircuit: bool
    IOptionalFeatureDeviceValveError: bool
    IFeatureDeviceDriveModeError: bool
    IFeatureDeviceTempSensorError: bool
    IFeatureDeviceTemperatureHumiditySensorCommunicationError: bool
    IFeatureDeviceDriveError: bool
    IFeatureRssiValue: bool
    IFeatureNoDataFromLinkyError: bool
    IFeatureBusConfigMismatch: bool
    IOptionalFeatureOperationDays: bool
    IOptionalFeatureDeviceFrostProtectionError: bool
    IOptionalFeatureDisplayMode: bool
    IFeatureDeviceOverloaded: bool
    IOptionalFeatureDisplayContrast: bool
    IFeatureDeviceIdentify: bool
    IOptionalFeatureLowBat: bool
    IFeatureDeviceTemperatureOutOfRange: bool
    IFeatureDeviceTemperatureHumiditySensorError: bool
    IOptionalFeatureDeviceErrorLockJammed: bool
    IOptionalFeatureDeviceAliveSignalEnabled: bool
    IFeatureProfilePeriodLimit: bool
    IFeatureDeviceCoProUpdate: bool
    IFeatureDeviceSensorCommunicationError: bool
    IOptionalFeatureDefaultLinkedGroup: bool
    IFeatureDevicePowerFailure: bool
    IOptionalFeatureAltitude: bool
    IOptionalFeatureDeviceInputLayoutMode: bool
    IFeatureShortCircuitDataLine: bool
    IFeatureDeviceSensorError: bool
    IOptionalFeatureDeviceOperationMode: bool
    IFeatureDeviceCommunicationError: bool
    IFeatureDeviceUndervoltage: bool
    IFeatureDeviceParticulateMatterSensorError: bool
    IFeatureDeviceCoProError: bool
    IFeatureDataDecodingFailedError: bool
    IOptionalFeatureDeviceWaterError: bool
    # rare
    IOptionalFeatureMountingOrientation: bool | None
    IOptionalFeatureControlsMountingOrientation: bool | None
    IOptionalFeatureColorTemperature: bool | None
    IOptionalFeatureHueSaturationValue: bool | None
    IOptionalFeaturePowerUpHueSaturationValue: bool | None
    IOptionalFeaturePowerUpColorTemperature: bool | None
    IOptionalFeatureLightSceneWithShortTimes: bool | None
    IOptionalFeaturePowerUpSwitchState: bool | None
    IOptionalFeatureColorTemperatureDynamicDaylight: bool | None
    IOptionalFeaturePowerUpDimmerState: bool | None
    IOptionalFeatureHardwareColorTemperature: bool | None
    IOptionalFeatureColorTemperatureDim2Warm: bool | None
    IOptionalFeatureLightScene: bool | None
    IOptionalFeatureDimmerState: bool | None


class DeviceBaseFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["DEVICE_BASE"]
    unreach: bool
    lowBat: bool | None
    routerModuleEnabled: bool
    multicastRoutingEnabled: bool
    routerModuleSupported: bool
    rssiDeviceValue: int | None
    "negative (normal), 128"
    rssiPeerValue: None | int
    configPending: bool
    dutyCycle: bool
    deviceOverloaded: bool
    coProUpdateFailure: bool
    coProFaulty: bool
    coProRestartNeeded: bool
    deviceUndervoltage: bool
    deviceOverheated: bool
    temperatureOutOfRange: bool
    devicePowerFailureDetected: bool
    supportedOptionalFeatures: DeviceBaseSupportedOptionalFeatures
    busConfigMismatch: None
    powerShortCircuit: None
    shortCircuitDataLine: None
    profilePeriodLimitReached: None
    mountingOrientation: None
    controlsMountingOrientation: str | None
    displayMountingOrientation: None
    displayMode: None
    invertedDisplayColors: None
    temperatureHumiditySensorError: None
    temperatureHumiditySensorCommunicationError: None
    particulateMatterSensorError: None
    particulateMatterSensorCommunicationError: None
    sensorError: None
    sensorCommunicationError: None
    displayContrast: None
    lockJammed: None
    deviceDriveError: None
    deviceDriveModeError: None
    deviceCommunicationError: None
    daliBusState: None
    deviceOperationMode: str | None
    defaultLinkedGroup: list[None]
    operationDays: float | int | None
    deviceAliveSignalEnabled: bool | None
    altitude: None
    temperatureSensorError: None
    mountingModuleError: None
    inputLayoutMode: None
    switchChannelMode: None
    frostProtectionError: None
    frostProtectionErrorAcknowledged: None
    valveFlowError: None
    valveWaterError: None
    noDataFromLinkyError: None
    dataDecodingFailedError: None
    ticVersionError: None


class MultiNodeInputChannelSupportedOptionalFeatures(TypedDict):
    IFeatureDoorLockAuthorizationSensorChannel: bool
    IOptionalFeatureLongPressSupported: bool
    IFeatureGarageGroupSensorChannel: bool
    IOptionalFeatureDoorBellSensorEventTimestamp: bool
    IFeatureLightGroupSensorChannel: bool
    IOptionalFeatureWindowState: bool
    IOptionalFeatureEventDelay: bool
    IFeatureAccessAuthorizationSensorChannel: bool
    IFeatureWateringGroupSensorChannel: bool
    IFeatureShadingGroupSensorChannel: bool


class MultiNodeInputChannelFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["MULTI_MODE_INPUT_CHANNEL"]
    channelRole: Literal["DOOR_BELL_INPUT"]
    supportedOptionalFeatures: MultiNodeInputChannelSupportedOptionalFeatures
    multiModeInputMode: Literal["KEY_BEHAVIOR"]
    binaryBehaviorType: Literal["NORMALLY_CLOSE"]
    windowState: Literal["CLOSED"]
    corrosionPreventionActive: bool
    doorBellSensorEventTimestamp: None
    actionParameter: Literal["NOT_CUSTOMISABLE"]
    eventDelay: int


class DoorBellContactInterfaceDevice(TypedDict):
    id: str
    type: Literal["DOOR_BELL_CONTACT_INTERFACE"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str, DeviceBaseFunctionalChannel | MultiNodeInputChannelFunctionalChannel
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-DSD-PCB"] | str
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class PushButtonDevice(TypedDict):
    id: str
    type: Literal["PUSH_BUTTON", "BRAND_PUSH_BUTTON"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str, DeviceBaseFunctionalChannel | SingleKeyFunctionalChannel
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "x.x.x"
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HMIP-WRC2"] | Literal["HmIP-BRC2"] | str
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


FirstInputAction: TypeAlias = Literal["OFF", "TOGGLE"]

OpticalSignalBehaviour: TypeAlias = Literal[
    "OFF", "ON", "BLINKING_MIDDLE", "FLASH_MIDDLE", "BILLOW_MIDDLE"
]


class SwitchMeasuringInternalLinkConfiguration(TypedDict):
    internalLinkConfigurationType: Literal["DOUBLE_INPUT_SWITCH"]
    onTime: float
    firstInputAction: FirstInputAction
    secondInputAction: Literal["ON", "OFF"]
    longPressOnTimeEnabled: bool


PowerUpSwitchState: TypeAlias = Literal["PERMANENT_OFF", "PERMANENT_ON"]


class SwitchChannelInternalLinkConfiguration(TypedDict):
    internalLinkConfigurationType: Literal["SINGLE_INPUT_SWITCH"]
    onTime: float
    firstInputAction: FirstInputAction
    longPressOnTimeEnabled: bool


class SwitchFunctionalSupportedOptionalFeatures(TypedDict):
    IFeatureLightGroupActuatorChannel: bool
    IFeatureAccessAuthorizationActuatorChannel: bool
    IFeatureGarageGroupActuatorChannel: bool
    IOptionalFeatureInternalLinkConfiguration: bool
    IOptionalFeaturePowerUpSwitchState: bool
    IFeatureLightProfileActuatorChannel: bool


class SwitchFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["SWITCH_CHANNEL"]
    channelRole: Literal["SWITCH_ACTUATOR", "GARAGE_DOOR_ACTUATOR"]
    supportedOptionalFeatures: SwitchFunctionalSupportedOptionalFeatures
    profileMode: ProfileMode
    userDesiredProfileMode: ProfileMode
    on: bool
    internalLinkConfiguration: SwitchChannelInternalLinkConfiguration
    powerUpSwitchState: PowerUpSwitchState


class _SwitchDevice(TypedDict):
    id: str
    homeId: str
    lastStatusUpdate: int
    label: str
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "x.x.x"
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: str
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class SwitchDevice(_SwitchDevice):
    type: Literal["PLUGABLE_SWITCH"]
    functionalChannels: dict[str, DeviceBaseFunctionalChannel | SwitchFunctionalChannel]


class MultiModeInputSwitchInternalLinkConfiguration(TypedDict):
    internalLinkConfigurationType: Literal["SINGLE_INPUT_SWITCH"]
    onTime: float
    firstInputAction: FirstInputAction
    longPressOnTimeEnabled: bool


class MultiModeInputSwitchFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["MULTI_MODE_INPUT_SWITCH_CHANNEL"]
    channelRole: Literal["SWITCH_ACTUATOR"] | None
    supportedOptionalFeatures: SwitchFunctionalSupportedOptionalFeatures
    profileMode: ProfileMode
    userDesiredProfileMode: ProfileMode
    on: bool
    internalLinkConfiguration: MultiModeInputSwitchInternalLinkConfiguration
    powerUpSwitchState: PowerUpSwitchState
    multiModeInputMode: Literal["KEY_BEHAVIOR"]
    binaryBehaviorType: Literal["NORMALLY_CLOSE"]


class DinRailSwitch4Device(_SwitchDevice):
    type: Literal["DIN_RAIL_SWITCH_4"]
    functionalChannels: dict[
        str, DeviceBaseFunctionalChannel | MultiModeInputSwitchFunctionalChannel
    ]
    "4x SwitchChannel"


class SwitchMeasuringSupportedOptionalFeatures(TypedDict):
    IFeatureLightGroupActuatorChannel: bool
    IFeatureAccessAuthorizationActuatorChannel: bool
    IFeatureGarageGroupActuatorChannel: bool
    IOptionalFeatureInternalLinkConfiguration: bool
    IOptionalFeatureEnergyMeterMode: bool
    IOptionalFeatureEnergyCounterTwo: bool
    IOptionalFeaturePowerMeasuringCategory: bool
    IOptionalFeatureCurrentDetectionBehavior: bool
    IOptionalFeaturePowerUpSwitchState: bool
    IFeatureLightProfileActuatorChannel: bool


class SwitchMeasuringFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["SWITCH_MEASURING_CHANNEL"]
    channelRole: Literal["SWITCH_ACTUATOR_WITH_MEASURING"]
    supportedOptionalFeatures: SwitchMeasuringSupportedOptionalFeatures
    profileMode: ProfileMode
    userDesiredProfileMode: ProfileMode
    on: bool
    internalLinkConfiguration: None | SwitchMeasuringInternalLinkConfiguration
    "only 'BRAND_*' type devices have it"
    powerUpSwitchState: PowerUpSwitchState
    energyCounter: float
    currentPowerConsumption: float
    energyMeterMode: Literal["CONSUMPTION_MEASURING"]
    currentDetectionBehavior: Literal["CURRENTDETECTION_ACTIVE"]
    energyCounterTwo: None
    energyCounterTwoType: Literal["ENERGY_COUNTER_INPUT_SINGLE_TARIFF"]
    powerMeasuringCategory: Literal["OTHER"]


class SwitchingMeasuringDevice(TypedDict):
    id: str
    type: Literal["FULL_FLUSH_SWITCH_MEASURING", "BRAND_SWITCH_MEASURING"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str, DeviceBaseFunctionalChannel | SwitchMeasuringFunctionalChannel
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-FSM16"] | str
    firmwareVersion: str
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class DoubleDimmerFunctionalChannelInternalLinkConfiguration(TypedDict):
    internalLinkConfigurationType: Literal["DOUBLE_INPUT_DIMMER"]
    onTime: float
    firstInputAction: Literal["ON", "OFF"]
    onLevel: float
    dimStep: float
    secondInputAction: Literal["ON", "OFF"]


class SingleDimmerFunctionalChannelInternalLinkConfiguration(TypedDict):
    internalLinkConfigurationType: Literal["SINGLE_INPUT_DIMMER"]
    onTime: float
    firstInputAction: Literal["TOGGLE"]
    onLevel: float
    dimStep: float


class DimmerSupportedOptionalFeatures(TypedDict):
    IFeatureDeviceCoProRestart: bool
    IOptionalFeatureDimmerMode: bool
    IFeatureLightGroupActuatorChannel: bool
    IFeatureDeviceOverheated: bool
    IOptionalFeatureLedDimmingRange: bool
    IOptionalFeatureInternalLinkConfiguration: bool
    IFeatureDeviceOverloaded: bool
    IFeatureDeviceCoProError: bool
    IOptionalFeaturePowerUpDimmerState: bool
    IOptionalFeaturePowerUpSwitchState: bool
    IOptionalFeatureOnMinLevel: bool
    IFeatureLightProfileActuatorChannel: bool


class DimmerFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["DIMMER_CHANNEL"]
    channelRole: Literal["DIMMING_ACTUATOR"]
    supportedOptionalFeatures: DimmerSupportedOptionalFeatures
    profileMode: ProfileMode
    userDesiredProfileMode: ProfileMode
    on: bool
    dimLevel: float
    rampTime: float
    dimmingMode: Literal["REGULAR_DIMMING"]
    dimLevelLowest: float
    dimLevelHighest: float
    deviceOverloaded: bool
    coProFaulty: bool
    coProRestartNeeded: bool
    deviceOverheated: bool
    internalLinkConfiguration: (
        DoubleDimmerFunctionalChannelInternalLinkConfiguration
        | SingleDimmerFunctionalChannelInternalLinkConfiguration
        | None
    )
    powerUpSwitchState: PowerUpSwitchState
    powerUpDimLevel: float
    onMinLevel: float | None


class MotionDetectionChannelSupportedOptionalFeatures(TypedDict):
    IOptionalFeatureBlockingPeriod: bool
    IOptionalFeatureIlluminationCalculationThree: bool | None  # either exists
    IOptionalFeatureIlluminationCalculationTwo: bool | None
    IFeatureLightGroupSensorChannel: bool
    IOptionalFeatureMotionSensorZones: bool
    IOptionalFeatureMotionSensorZoneSensitivity: bool
    IOptionalFeatureMotionSensorSensitivity: bool
    IFeatureWateringGroupSensorChannel: bool


class MotionDetectionFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["MOTION_DETECTION_CHANNEL"]
    channelRole: Literal["MOTION_SENSOR"] | None
    supportedOptionalFeatures: MotionDetectionChannelSupportedOptionalFeatures
    motionDetectionActive: bool
    illumination: float
    currentIllumination: None
    numberOfBrightnessMeasurements: int
    motionDetectionSendInterval: str
    "SECONDS_240"
    motionBufferActive: bool
    blockingPeriod: float
    motionSensorSensitivity: int
    motionDetected: bool
    motionSensorZones: None
    motionSensorZoneSensitivityMap: dict[None, None]


class DeviceSabotageFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["DEVICE_SABOTAGE"]
    unreach: bool
    lowBat: bool
    routerModuleEnabled: bool
    multicastRoutingEnabled: bool
    routerModuleSupported: bool
    rssiDeviceValue: int | None
    rssiPeerValue: int | None
    configPending: bool
    dutyCycle: bool
    deviceOverloaded: bool
    coProUpdateFailure: bool
    coProFaulty: bool
    coProRestartNeeded: bool
    deviceUndervoltage: bool
    deviceOverheated: bool
    temperatureOutOfRange: bool
    devicePowerFailureDetected: bool
    supportedOptionalFeatures: DeviceOperationlockSupportedOptionalFeatures
    busConfigMismatch: None
    powerShortCircuit: None
    shortCircuitDataLine: None
    profilePeriodLimitReached: None
    mountingOrientation: None
    controlsMountingOrientation: None
    displayMountingOrientation: None
    displayMode: None
    invertedDisplayColors: None
    temperatureHumiditySensorError: None
    temperatureHumiditySensorCommunicationError: None
    particulateMatterSensorError: None
    particulateMatterSensorCommunicationError: None
    sensorError: None
    sensorCommunicationError: None
    displayContrast: None
    lockJammed: None
    deviceDriveError: None
    deviceDriveModeError: None
    deviceCommunicationError: None
    daliBusState: None
    deviceOperationMode: None
    defaultLinkedGroup: list[None]
    operationDays: None
    deviceAliveSignalEnabled: None
    altitude: None
    temperatureSensorError: None
    mountingModuleError: None
    inputLayoutMode: None
    switchChannelMode: None
    frostProtectionError: None
    frostProtectionErrorAcknowledged: None
    valveFlowError: None
    valveWaterError: None
    noDataFromLinkyError: None
    dataDecodingFailedError: None
    ticVersionError: None
    sabotage: bool


class _MotionDetectorDevice(TypedDict):
    id: str
    homeId: str
    lastStatusUpdate: int
    label: str
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "x.x.x"
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    "HMIP_RF"
    liveUpdateState: LiveUpdateState


class MotionDetectorIndoorDevice(_MotionDetectorDevice):
    type: Literal["MOTION_DETECTOR_INDOOR"]
    functionalChannels: dict[
        str,
        DeviceSabotageFunctionalChannel | MotionDetectionFunctionalChannel,
    ]
    modelType: Literal["HmIP-SMI"] | str
    "HmIP-SMI"


class MotionDetectorOutdoorDevice(_MotionDetectorDevice):
    type: Literal["MOTION_DETECTOR_OUTDOOR"]
    functionalChannels: dict[
        str,
        DeviceBaseFunctionalChannel | MotionDetectionFunctionalChannel,
    ]
    modelType: Literal["HmIP-SMO"] | str
    "HmIP-SMO"


class DevicePermanentFullRxFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["DEVICE_PERMANENT_FULL_RX"]
    unreach: bool
    lowBat: bool
    routerModuleEnabled: bool
    multicastRoutingEnabled: bool
    routerModuleSupported: bool
    rssiDeviceValue: int | None
    rssiPeerValue: int | None
    configPending: bool
    dutyCycle: bool
    deviceOverloaded: bool
    coProUpdateFailure: bool
    coProFaulty: bool
    coProRestartNeeded: bool
    deviceUndervoltage: bool
    deviceOverheated: bool
    temperatureOutOfRange: bool
    devicePowerFailureDetected: bool
    supportedOptionalFeatures: DeviceOperationlockSupportedOptionalFeatures
    busConfigMismatch: None
    powerShortCircuit: None
    shortCircuitDataLine: None
    profilePeriodLimitReached: None
    mountingOrientation: None
    controlsMountingOrientation: str | None
    displayMountingOrientation: None
    displayMode: None
    invertedDisplayColors: None
    temperatureHumiditySensorError: None
    temperatureHumiditySensorCommunicationError: None
    particulateMatterSensorError: None
    particulateMatterSensorCommunicationError: None
    sensorError: None
    sensorCommunicationError: None
    displayContrast: None
    lockJammed: None
    deviceDriveError: None
    deviceDriveModeError: None
    deviceCommunicationError: None
    daliBusState: None
    deviceOperationMode: None
    defaultLinkedGroup: list[None]
    operationDays: None
    deviceAliveSignalEnabled: None
    altitude: None
    temperatureSensorError: None
    mountingModuleError: None
    inputLayoutMode: None
    switchChannelMode: None
    frostProtectionError: None
    frostProtectionErrorAcknowledged: None
    valveFlowError: None
    valveWaterError: None
    noDataFromLinkyError: None
    dataDecodingFailedError: None
    ticVersionError: None
    permanentFullRx: bool


class MotionDetectorPushButtonDevice(_MotionDetectorDevice):
    type: Literal["MOTION_DETECTOR_PUSH_BUTTON"]
    functionalChannels: dict[
        str,
        DevicePermanentFullRxFunctionalChannel
        | SingleKeyFunctionalChannel
        | MotionDetectionFunctionalChannel,
    ]
    "2x SingleKeyFunctionalChannel"
    modelType: Literal["HmIP-SMI55"] | str
    "HmIP-SMI55"


class WallMountedThermostatWithoutDisplayChannelSupportedOptionalFeatures(TypedDict):
    IOptionalFeatureThermostatCoolingSupported: bool


class WallMountedThermostatProSupportedOptionalFeatures(
    WallMountedThermostatWithoutDisplayChannelSupportedOptionalFeatures
):
    IOptionalFeatureClimateControlDisplayCarbonSupported: bool
    IOptionalFeatureClimateControlDisplayHumidityOnlySupported: bool


class _WallMountedThermostatFunctionalChannel(_BaseFunctionalChannel):
    channelRole: Literal["WALL_MOUNTED_THERMOSTAT"]
    temperatureOffset: float
    actualTemperature: float
    setPointTemperature: float
    humidity: int
    vaporAmount: float


class WallMountedThermostatWithoutDisplayFunctionalChannel(
    _WallMountedThermostatFunctionalChannel
):
    supportedOptionalFeatures: (
        WallMountedThermostatWithoutDisplayChannelSupportedOptionalFeatures
    )
    functionalChannelType: Literal["WALL_MOUNTED_THERMOSTAT_WITHOUT_DISPLAY_CHANNEL"]


class WallMountedThermostatProFunctionalChannel(
    _WallMountedThermostatFunctionalChannel
):
    display: Literal["ACTUAL"]
    supportedOptionalFeatures: WallMountedThermostatProSupportedOptionalFeatures
    functionalChannelType: Literal["WALL_MOUNTED_THERMOSTAT_PRO_CHANNEL"]


class WallMountedThermostatProDevice(TypedDict):
    id: str
    type: Literal["WALL_MOUNTED_THERMOSTAT_PRO"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str,
        DeviceOperationlockFunctionalChannel
        | WallMountedThermostatProFunctionalChannel,
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "x.x.x"
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-WTH-1"] | str
    "HmIP-WTH-1"
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class AlarmSirenFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["ALARM_SIREN_CHANNEL"]
    channelRole: Literal["ALARM_SIREN"]


class AlarmSirenIndoorDevice(TypedDict):
    id: str
    type: Literal["ALARM_SIREN_INDOOR"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str, DeviceSabotageFunctionalChannel | AlarmSirenFunctionalChannel
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "x.x.x"
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-ASIR"] | str
    "HmIP-ASIR"
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class DimmerDevice(TypedDict):
    id: str
    type: Literal["PLUGGABLE_DIMMER", "BRAND_DIMMER", "FULL_FLUSH_DIMMER"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[str, DeviceBaseFunctionalChannel | DimmerFunctionalChannel]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "x.x.x"
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-BDT", "HmIP-PDT", "HmIP-FDT"] | str
    "HmIP-BDT, HmIP-PDT, HmIP-FDT"
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class TemperatureHumiditySensorDevice(TypedDict):
    id: str
    type: Literal["TEMPERATURE_HUMIDITY_SENSOR"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str,
        DeviceBaseFunctionalChannel
        | WallMountedThermostatWithoutDisplayFunctionalChannel,
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-STH"] | str
    firmwareVersion: str
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


WindowState: TypeAlias = Literal["CLOSED", "OPEN"]


class SmokeDetectorChannelSupportedOptionalFeatures(TypedDict):
    IOptionalFeatureSmokeDetectorStatistic: bool
    IOptionalFeatureDirtLevel: bool
    IOptionalFeatureSmokeDetectorGroupAssignment: bool


class SmokeDetectorFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["SMOKE_DETECTOR_CHANNEL"]
    channelRole: Literal["SMOKE_ALARM"]
    supportedOptionalFeatures: SmokeDetectorChannelSupportedOptionalFeatures
    smokeDetectorAlarmType: Literal["IDLE_OFF"]
    smokeEventRepeatingActive: bool
    chamberDegraded: bool
    dirtLevel: float
    smokeDetectorGroupAssignment: list[str]
    'seen: ["NO_GROUP"]'
    inclusionTimestamp: int
    lastSmokeTestTimestamp: None
    lastCommunicationTestTimestamp: None
    lastSmokeAlarmTimestamp: None
    lastIntrusionAlarmTimestamp: None
    counterUpdateTimestamp: None
    smokeTestCounter: None
    communicationTestCounter: None
    smokeAlarmCounter: None
    intrusionAlarmCounter: None
    factoryResetCounter: None
    otauAttemptsCounter: None
    wakeupCounter: None
    serviceInformationReceived: bool


class SmokeDetectorDevice(TypedDict):
    id: str
    type: Literal["SMOKE_DETECTOR"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str, DeviceBaseFunctionalChannel | SmokeDetectorFunctionalChannel
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "x.x.x"
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-SWSD-2"] | str
    "HmIP-SWSD-2"
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class UniversalLightSupportedOptionalFeatures(TypedDict):
    IOptionalFeaturePowerUpColorTemperature: bool
    IOptionalFeatureDimmerState: bool
    IFeatureConnectedDeviceUnreach: bool
    IOptionalFeatureHardwareColorTemperature: bool
    IOptionalFeatureLightScene: bool
    IFeatureLimitFailure: bool
    IOptionalFeatureHueSaturationValue: bool
    IOptionalFeatureChannelActive: bool
    IFeatureControlGearFailure: bool
    IOptionalFeatureColorTemperatureDim2Warm: bool
    IFeatureLightProfileActuatorChannel: bool
    IOptionalFeatureLightSceneWithShortTimes: bool
    IFeatureLightGroupActuatorChannel: bool
    IFeatureLampFailure: bool
    IOptionalFeatureColorTemperature: bool
    IOptionalFeaturePowerUpDimmerState: bool
    IOptionalFeaturePowerUpHueSaturationValue: bool
    IOptionalFeatureColorTemperatureDynamicDaylight: bool
    IOptionalFeaturePowerUpSwitchState: bool
    IOptionalFeatureOnMinLevel: bool


class UniversalLightFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["UNIVERSAL_LIGHT_CHANNEL"]
    channelRole: None | Literal["UNIVERSAL_LIGHT_ACTUATOR"]
    supportedOptionalFeatures: UniversalLightSupportedOptionalFeatures
    profileMode: ProfileMode
    userDesiredProfileMode: ProfileMode
    on: bool | None
    colorTemperature: None
    hue: int | None
    saturationLevel: float | None
    dimLevel: float | None
    rampTime: float
    hardwareColorTemperatureColdWhite: int
    hardwareColorTemperatureWarmWhite: int
    dim2WarmActive: bool | None
    humanCentricLightActive: bool | None
    lightSceneId: int | None
    channelActive: bool
    connectedDeviceUnreach: None
    controlGearFailure: None
    lampFailure: None
    limitFailure: None
    onMinLevel: float
    powerUpSwitchState: PowerUpSwitchState
    powerUpDimLevel: float
    powerUpSaturationLevel: float
    powerUpHue: int
    powerUpColorTemperature: int
    minimalColorTemperature: int
    maximumColorTemperature: int


class RGBWDimmerDevice(TypedDict):
    id: str
    type: Literal["RGBW_DIMMER"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str, DeviceBaseFunctionalChannel | UniversalLightFunctionalChannel
    ]
    "4x UNIVERSAL_LIGHT_CHANNEL"
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    fastColorChangeSupported: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-RGBW"] | str
    "HmIP-RGBW"
    firmwareVersion: str
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class ShutterContactChannelFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["SHUTTER_CONTACT_CHANNEL"]
    channelRole: Literal["WINDOW_SENSOR"]
    supportedOptionalFeatures: dict[Literal["IFeatureLightGroupSensorChannel"], bool]
    windowState: WindowState
    eventDelay: int


class _ShutterContactDevice(TypedDict):
    id: str
    homeId: str
    lastStatusUpdate: int
    label: str
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "x.x.x"
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class ShutterContactDevice(_ShutterContactDevice):
    type: Literal["SHUTTER_CONTACT_OPTICAL_PLUS", "SHUTTER_CONTACT"]
    functionalChannels: dict[
        str, DeviceSabotageFunctionalChannel | ShutterContactChannelFunctionalChannel
    ]
    modelType: Literal["HmIP-SWDO-2", "HmIP-SWDO-PL-2"] | str
    "HmIP-SWDO-2, HmIP-SWDO-PL-2"


class ShutterContactMagneticDevice(_ShutterContactDevice):
    type: Literal["SHUTTER_CONTACT_MAGNETIC"]
    functionalChannels: dict[
        str, DeviceBaseFunctionalChannel | ShutterContactChannelFunctionalChannel
    ]
    modelType: Literal["HmIP-SWDM-2"] | str
    "HmIP-SWDM-2"


class PushButton6ChannelDevice(TypedDict):
    id: str
    type: Literal["PUSH_BUTTON_6"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str, DeviceBaseFunctionalChannel | SingleKeyFunctionalChannel
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    oem: OEM
    firmwareVersionInteger: int
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: UpdateState
    modelType: Literal["HmIP-WRC6-A"] | str
    firmwareVersion: str
    "x.x.x"
    connectionType: ConnectionType
    liveUpdateState: LiveUpdateState


class AccessControllerSupportedOptionalFeatures(
    DeviceOperationlockSupportedOptionalFeatures
):
    IOptionalFeatureFilteredMulticastRouter: bool


class AccessControllerFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["ACCESS_CONTROLLER_CHANNEL"]
    unreach: bool
    lowBat: None
    routerModuleEnabled: bool
    multicastRoutingEnabled: bool
    routerModuleSupported: bool
    rssiDeviceValue: None
    rssiPeerValue: None
    configPending: bool
    dutyCycle: None | bool
    deviceOverloaded: bool
    coProUpdateFailure: bool
    coProFaulty: bool
    coProRestartNeeded: bool
    deviceUndervoltage: bool
    deviceOverheated: bool
    temperatureOutOfRange: bool
    devicePowerFailureDetected: bool
    supportedOptionalFeatures: AccessControllerSupportedOptionalFeatures
    busConfigMismatch: None
    powerShortCircuit: None
    shortCircuitDataLine: None
    profilePeriodLimitReached: None
    mountingOrientation: None
    controlsMountingOrientation: str | None
    displayMountingOrientation: None
    displayMode: None
    invertedDisplayColors: None
    temperatureHumiditySensorError: None
    temperatureHumiditySensorCommunicationError: None
    particulateMatterSensorError: None
    particulateMatterSensorCommunicationError: None
    sensorError: None
    sensorCommunicationError: None
    displayContrast: None
    lockJammed: None
    deviceDriveError: None
    deviceDriveModeError: None
    deviceCommunicationError: None
    daliBusState: None
    deviceOperationMode: str | None
    defaultLinkedGroup: list[None]
    operationDays: None
    deviceAliveSignalEnabled: None
    altitude: None
    temperatureSensorError: None
    mountingModuleError: None
    inputLayoutMode: None
    switchChannelMode: None
    frostProtectionError: None
    frostProtectionErrorAcknowledged: None
    valveFlowError: None
    valveWaterError: None
    noDataFromLinkyError: None
    dataDecodingFailedError: None
    ticVersionError: None
    signalBrightness: float
    dutyCycleLevel: float
    carrierSenseLevel: float
    filteredMulticastRoutingEnabled: bool


class NotificationCategoryActiveMap(TypedDict):
    ERROR_ALARM: bool


class NotificationCategoryToMap(TypedDict):
    ERROR_ALARM: float


class NotificationCategoryToTriggerCounterMap(TypedDict):
    ERROR_ALARM: int


class NotificationCategoryToTimestampMap(TypedDict):
    ERROR_ALARM: int


AlarmCategories: TypeAlias = Literal["ERROR_ALARM", "TOP_LED_ONLY"]


class NotificationTriggerToCategoryMap(TypedDict):
    INTRUSION_ALARM: AlarmCategories
    PLUGIN_ERROR: AlarmCategories
    DEVICE_BLOCKED_TEMPORARILY: AlarmCategories
    REMOTE_CLIENT_CREATION_ENABLED: AlarmCategories
    DEVICE_BLOCKED_SABOTAGE: AlarmCategories
    MASS_STORAGE_ERROR: AlarmCategories
    DEVICE_BLOCKED_PERMANENTLY: AlarmCategories
    SAFETY_ALARM: AlarmCategories


class StatusNotificationSettings(TypedDict):
    statusNotificationActive: bool
    notificationTriggerToCategoryMap: NotificationTriggerToCategoryMap
    notificationCategoryActiveMap: NotificationCategoryActiveMap
    notificationCategoryToDimLevelMap: NotificationCategoryToMap
    notificationCategoryToTriggerCounterMap: NotificationCategoryToTriggerCounterMap
    notificationCategoryToTimestampMap: NotificationCategoryToTimestampMap


class NotificationLightSupportedFeatures(TypedDict):
    IOptionalFeatureStatusNotificationSettings: bool
    IOptionalFeaturePowerUpNotificationLightState: bool
    IFeatureNotificationLightGroupActuatorChannel: bool
    IFeatureOpticalSignalBehaviourState: bool
    IOptionalFeaturePowerUpDimmerState: bool
    IOptionalFeaturePowerUpSwitchState: bool
    IOptionalFeatureOnMinLevel: bool


SimpleRGBColor = Literal[
    "BLACK", "BLUE", "GREEN", "TURQUOISE", "RED", "PURPLE", "YELLOW", "WHITE"
]


class NotificationLightFunctionalChannel(_BaseFunctionalChannel):
    functionalChannelType: Literal["NOTIFICATION_LIGHT_CHANNEL"]
    channelRole: None
    supportedOptionalFeatures: NotificationLightSupportedFeatures
    profileMode: ProfileMode | None
    userDesiredProfileMode: ProfileMode
    on: bool | None
    dimLevel: float | None
    simpleRGBColorState: SimpleRGBColor | None
    opticalSignalBehaviour: OpticalSignalBehaviour | None
    statusNotificationSettings: StatusNotificationSettings
    powerUpSwitchState: PowerUpSwitchState
    powerUpDimLevel: float | int
    powerUpSimpleRGBColor: SimpleRGBColor
    powerUpOpticalSignalBehaviour: OpticalSignalBehaviour
    onMinLevel: float | None


FunctionalChannel: TypeAlias = (
    SingleKeyFunctionalChannel
    | HeatingThermostatFunctionalChannel
    | DeviceOperationlockFunctionalChannel
    | DeviceBaseFunctionalChannel
    | MultiNodeInputChannelFunctionalChannel
    | SwitchFunctionalChannel
    | MultiModeInputSwitchFunctionalChannel
    | SwitchMeasuringFunctionalChannel
    | DimmerFunctionalChannel
    | MotionDetectionFunctionalChannel
    | DeviceSabotageFunctionalChannel
    | DevicePermanentFullRxFunctionalChannel
    | WallMountedThermostatProFunctionalChannel
    | WallMountedThermostatWithoutDisplayFunctionalChannel
    | AlarmSirenFunctionalChannel
    | SmokeDetectorFunctionalChannel
    | UniversalLightFunctionalChannel
    | ShutterContactChannelFunctionalChannel
    | AccessControllerFunctionalChannel
    | NotificationLightFunctionalChannel
)


class AccessPointDevice(TypedDict):
    "HCU"

    id: str
    type: Literal["ACCESS_POINT"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[
        str, AccessControllerFunctionalChannel | NotificationLightFunctionalChannel
    ]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    availableFirmwareVersion: str
    "x.x.x"
    firmwareVersionInteger: None
    firmwareVersion: str
    "x.x.x"
    manufacturerCode: int
    modelId: int
    oem: OEM
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: Literal["BACKGROUND_UPDATE_NOT_SUPPORTED"]
    modelType: Literal["HmIP-HCU1-A"] | str
    "HmIP-HCU1-A"
    connectionType: ConnectionType
    "HMIP_RF"
    liveUpdateState: LiveUpdateState


class HomeControlAccessPointDevice(TypedDict):
    id: str
    type: Literal["HOME_CONTROL_ACCESS_POINT"]
    homeId: str
    lastStatusUpdate: int
    label: str
    functionalChannels: dict[str, AccessControllerFunctionalChannel]
    deviceArchetype: DeviceArchetype
    manuallyUpdateForced: bool
    manufacturerCode: int
    modelId: int
    availableFirmwareVersion: str
    "x.x.x"
    firmwareVersionInteger: None | int
    firmwareVersion: str
    "x.x.x"
    oem: OEM
    serializedGlobalTradeItemNumber: str
    permanentlyReachable: bool
    measuredAttributes: dict[None, None]
    updateState: Literal["BACKGROUND_UPDATE_NOT_SUPPORTED"]
    modelType: Literal["HmIP-HAP"] | str
    "HmIP-HAP"
    connectionType: ConnectionType
    "HMIP_LAN"
    liveUpdateState: LiveUpdateState


Device: TypeAlias = (
    PushButtonDevice
    | HeatingThermostatDevice
    | MotionDetectorIndoorDevice
    | MotionDetectorOutdoorDevice
    | MotionDetectorPushButtonDevice
    | SmokeDetectorDevice
    | WallMountedThermostatProDevice
    | RGBWDimmerDevice
    | AccessPointDevice
    | SwitchingMeasuringDevice
    | DimmerDevice
    | SwitchDevice
    | AlarmSirenIndoorDevice
    | ShutterContactMagneticDevice
    | HomeControlAccessPointDevice
    | DinRailSwitch4Device
    | PushButton6ChannelDevice
    | ShutterContactDevice
    | DoorBellContactInterfaceDevice
    | TemperatureHumiditySensorDevice
)

Devices: TypeAlias = dict[str, Device]


class Channel(TypedDict):
    deviceId: str
    channelIndex: int


ProfileIndex: TypeAlias = Literal[
    "PROFILE_1", "PROFILE_2", "PROFILE_3", "PROFILE_4", "PROFILE_5", "PROFILE_6"
]


class Profile(TypedDict):
    profileId: str
    groupId: str
    index: ProfileIndex
    name: str
    visible: bool
    enabled: bool


Profiles: TypeAlias = dict[ProfileIndex, Profile]


class _BaseGroup(TypedDict):
    id: str
    homeId: str
    metaGroupId: str | None
    label: str
    lastStatusUpdate: int
    "unix"
    unreach: bool | None
    lowBat: bool | None
    dutyCycle: bool | None
    channels: list[Channel]


class AccessControlGroup(_BaseGroup):
    type: Literal["ACCESS_CONTROL"]


class SecurityGroup(_BaseGroup):
    type: Literal["SECURITY"]
    windowState: WindowState | None
    motionDetected: bool | None
    presenceDetected: None
    sabotage: bool | None
    moistureDetected: None
    waterlevelDetected: None
    powerMainsFailure: None
    smokeDetectorAlarmType: Literal["IDLE_OFF"] | None


class MetaGroup(_BaseGroup):
    type: Literal["META"]
    groups: list[str]
    configPending: bool | None
    sabotage: None | bool
    incorrectPositioned: None
    groupIcon: str


class IndoorClimateGroup(_BaseGroup):
    type: Literal["INDOOR_CLIMATE"]
    processing: bool | None
    ventilationState: VentilationState | None
    ventilationLevel: VentilationState | None
    windowState: WindowState | None
    sabotage: bool | None


class AlarmSwitchingGroup(_BaseGroup):
    type: Literal["ALARM_SWITCHING"]
    on: bool | None
    dimLevel: float | None
    onTime: float | None
    signalAcoustic: Literal["FREQUENCY_RISING"]
    signalOptical: Literal["DOUBLE_FLASHING_REPEATING"]
    smokeDetectorAlarmType: Literal["IDLE_OFF"] | None
    acousticFeedbackEnabled: bool
    opticalFeedbackEnabled: None
    supportedOptionalFeatures: dict[
        Literal["IOptionalFeatureOpticalFeedbackEnabled"], bool
    ]


class SwitchingGroupSupportedOptionalFeatures(TypedDict):
    IOptionalFeatureDimmerState: bool
    IOptionalFeatureLightSceneWithShortTimes: bool
    IOptionalFeatureLightScene: bool
    IOptionalFeatureColorTemperature: bool
    IOptionalFeatureHueSaturationValue: bool
    IOptionalFeatureColorTemperatureDynamicDaylight: bool
    IOptionalFeatureColorTemperatureDim2Warm: bool


class SwitchingGroup(_BaseGroup):
    type: Literal["SWITCHING"]
    on: bool | None
    dimLevel: float | None
    processing: bool | None
    shutterLevel: float | None
    primaryShadingLevel: float | None
    primaryShadingStateType: str | None
    slatsLevel: float | None
    secondaryShadingLevel: float | None
    secondaryShadingStateType: str | None
    hue: int | None
    saturationLevel: float | None
    colorTemperature: int | None
    minimalColorTemperature: int | None
    maximumColorTemperature: int | None
    supportedOptionalFeatures: (
        SwitchingGroupSupportedOptionalFeatures | dict[str, object]
    )
    dim2WarmActive: bool | None
    humanCentricLightActive: bool | None
    lightSceneId: int | None


class InboxGroup(_BaseGroup):
    type: Literal["INBOX"]


class HeatingHumidityLimiterGroup(_BaseGroup):
    type: Literal["HEATING_HUMIDITY_LIMITER"]
    humidityLimiterActive: bool | None


class HeatingGroupOptionalSupportedFeatures(TypedDict):
    IOptionalFeatureHumidityLimitPre: bool
    IOptionalFeatureHumidityLimitPreAlarm: bool
    IOptionalFeatureSwitchClimateFunction: bool
    IOptionalFeatureSwitchClimateHeatingCoolingEnabled: bool
    IOptionalFeatureWindowOpenTemperatureCooling: bool


class HeatingGroup(_BaseGroup):
    type: Literal["HEATING"]
    processing: None
    ventilationState: None
    ventilationLevel: None
    windowOpenTemperature: float
    setPointTemperature: float
    minTemperature: float
    maxTemperature: float
    windowState: None
    cooling: None | bool
    partyMode: bool
    controlMode: Literal["AUTOMATIC", "MANUAL", "ECO"]
    controlDifferantialTemperature: float
    duration: float
    profiles: Profiles
    activeProfile: ProfileIndex
    boostMode: bool
    boostDuration: int
    actualTemperature: None | float
    humidity: None | int
    coolingAllowed: bool
    coolingIgnored: bool
    ecoAllowed: bool
    ecoIgnored: bool
    controllable: bool
    boostAllowed: bool
    floorHeatingMode: Literal["FLOOR_HEATING_STANDARD"]
    humidityLimitEnabled: bool
    humidityLimitValue: int
    humidityLimiterAlarm: None
    humidityLimitPreEnabled: bool
    humidityLimitPreValue: int
    humidityLimiterPreAlarm: None
    externalClockEnabled: bool
    externalClockHeatingTemperature: float
    externalClockCoolingTemperature: float
    valvePosition: float | None
    "during adaption: None"
    sabotage: bool | None
    valveSilentModeSupported: bool
    valveSilentModeEnabled: bool
    lastSetPointReachedTimestamp: int
    lastSetPointUpdatedTimestamp: int
    heatingFailureSupported: bool
    switchClimateFunction: Literal["THERMOSTAT"]
    supportedOptionalFeatures: HeatingGroupOptionalSupportedFeatures
    switchClimateCoolingEnable: bool
    switchClimateHeatingEnable: bool
    windowOpenTemperatureCooling: float
    valveActualTemperature: float


class HotWaterGroup(_BaseGroup):
    type: Literal["HOT_WATER"]
    on: bool | None
    onTime: float | None
    profileId: str
    profileMode: ProfileMode | None


class ExtendedLinkedSwitchingGroup(_BaseGroup):
    type: Literal["EXTENDED_LINKED_SWITCHING"]
    on: bool | None
    dimLevel: float | None
    onTime: float | None
    rampTime: float | None
    triggered: bool | None
    onLevel: float | None
    dimStep: float | None
    onHue: int | None
    onSaturationLevel: float | None
    onColorTemperature: int | None
    longPressBehavior: Literal["LEVEL_DIMMING"]
    sensorSpecificParameters: dict[None, None]
    groupVisibility: Literal["VISIBLE"]
    hue: int | None
    saturationLevel: float | None
    colorTemperature: int | None
    minimalColorTemperature: int | None
    maximumColorTemperature: int | None
    supportedOptionalFeatures: SwitchingGroupSupportedOptionalFeatures
    dim2WarmActive: bool | None
    humanCentricLightActive: bool | None
    lightSceneId: int | None
    onLightSceneId: int | None


class SecurityZoneGroup(_BaseGroup):
    type: Literal["SECURITY_ZONE"]
    active: bool
    silent: bool
    ignorableDeviceChannels: list[Channel]
    windowState: None | WindowState
    motionDetected: None | bool
    presenceDetected: None
    sabotage: bool | None
    zoneAssignmentIndex: Literal[
        "ALARM_MODE_ZONE_2", "ALARM_MODE_ZONE_3", "ALARM_MODE_ZONE_1"
    ]
    configPending: bool


class HeatingExternalClockGroup(_BaseGroup):
    type: Literal["HEATING_EXTERNAL_CLOCK"]
    externalClockActive: None


class HeatingCoolingDemandPumpGroup(_BaseGroup):
    type: Literal["HEATING_COOLING_DEMAND_PUMP"]
    on: bool | None
    pumpLeadTime: int
    pumpFollowUpTime: int
    pumpProtectionDuration: int
    pumpProtectionSwitchingInterval: int
    heatDemand: None


class LinkedSwitchingGroup(_BaseGroup):
    type: Literal["LINKED_SWITCHING"]
    on: bool | None
    dimLevel: float | None
    triggered: bool | None


class SecurityBackupAlarmSwitchingGroup(_BaseGroup):
    type: Literal["SECURITY_BACKUP_ALARM_SWITCHING"]
    on: bool | None
    dimLevel: float | None
    onTime: float | None
    signalAcoustic: Literal["FREQUENCY_RISING"]
    signalOptical: Literal["DOUBLE_FLASHING_REPEATING"]
    smokeDetectorAlarmType: Literal["IDLE_OFF"]
    acousticFeedbackEnabled: bool
    opticalFeedbackEnabled: None
    supportedOptionalFeatures: dict[
        Literal["IOptionalFeatureOpticalFeedbackEnabled"], bool
    ]


class HeatingCoolingDemandBoilerGroup(_BaseGroup):
    type: Literal["HEATING_COOLING_DEMAND_BOILER"]
    on: bool | None
    boilerLeadTime: int
    boilerFollowUpTime: int
    heatDemand: None


class ExtendedLinkedGarageDoorGroup(_BaseGroup):
    type: Literal["EXTENDED_LINKED_GARAGE_DOOR"]
    processing: None
    doorState: None
    sensorSpecificParameters: dict[None, None]
    groupVisibility: Literal["VISIBLE"]
    ventilationPositionSupported: bool
    impulseDuration: float


class HeatingChangeoverGroup(_BaseGroup):
    type: Literal["HEATING_CHANGEOVER"]
    on: bool | None
    changeOver: None


class HeatingTemperatureLimiterGroup(_BaseGroup):
    type: Literal["HEATING_TEMPERATURE_LIMITER"]
    temperatureLimiterActive: None


class SwitchingProfileGroup(_BaseGroup):
    type: Literal["SWITCHING_PROFILE"]
    on: bool | None
    dimLevel: float | None
    profileId: str
    profileMode: ProfileMode


class HeatingDehumidifierGroup(_BaseGroup):
    type: Literal["HEATING_DEHUMIDIFIER"]
    on: bool | None


Group: TypeAlias = (
    AccessControlGroup
    | SecurityGroup
    | MetaGroup
    | IndoorClimateGroup
    | AlarmSwitchingGroup
    | SwitchingGroup
    | InboxGroup
    | HeatingHumidityLimiterGroup
    | HeatingGroup
    | HotWaterGroup
    | ExtendedLinkedSwitchingGroup
    | HeatingExternalClockGroup
    | HeatingCoolingDemandPumpGroup
    | LinkedSwitchingGroup
    | SecurityBackupAlarmSwitchingGroup
    | HeatingCoolingDemandBoilerGroup
    | ExtendedLinkedGarageDoorGroup
    | HeatingChangeoverGroup
    | HeatingTemperatureLimiterGroup
    | SecurityZoneGroup
    | SwitchingProfileGroup
    | HeatingDehumidifierGroup
)

Groups: TypeAlias = dict[str, Group]


class AccessPointUpdateState(TypedDict):
    successfulUpdateTimestamp: int
    updateStateChangedTimestamp: int
    accessPointUpdateState: UpdateState


class ExternalServiceAccountLinking(TypedDict):
    externalService: str
    accountLinkingId: None


class ExternalServiceSupportingMap(TypedDict):
    HUE: int
    MY_UPLINK: int
    DOORBIRD: int
    ALEXA: int


class AccessControl(TypedDict):
    functionalGroups: list[str]
    accessAuthorizationProfileGroups: list[None]
    doorLockAuthorizationProfileGroups: list[None]
    lockProfileGroups: list[None]
    autoRelockProfileGroups: list[None]
    extendedLinkedGarageDoorGroups: list[str]
    extendedLinkedNotificationGroups: list[None]
    solution: Literal["ACCESS_CONTROL"]
    active: bool


class Energy(TypedDict):
    functionalGroups: list[None]
    energyDashboardChannels: list[None]
    solution: Literal["ENERGY"]
    active: bool


class FloorHeatingSpecificGroups(TypedDict):
    HEATING_DEHUMIDIFIER: str
    HEATING_HUMIDITY_LIMITER: str
    HEATING_CHANGEOVER: str
    HEATING_COOLING_DEMAND_BOILER: str
    HEATING_EXTERNAL_CLOCK: str
    HEATING_COOLING_DEMAND_PUMP: str
    HEATING_TEMPERATURE_LIMITER: str
    HOT_WATER: str


class IndoorClimate(TypedDict):
    functionalGroups: list[str]
    absenceType: Literal["NOT_ABSENT", "PARTY"]
    absenceStartTime: None | str
    "only for party mode"
    absenceEndTime: None | str
    "only for party mode"
    floorHeatingSpecificGroups: FloorHeatingSpecificGroups
    ecoTemperature: float
    coolingEnabled: bool
    ecoDuration: Literal["PERMANENT"]
    optimumStartStopEnabled: bool
    cooling: None
    deviceChannelSpecificFunction: dict[None, None]
    extendedLinkedVentilationGroups: list[None]
    ventilationProfileGroups: list[None]
    demandControlledVentilationGroups: list[None]
    demandControlledVentilationSpecificGroups: dict[None, None]
    lastVacationTemperature: None
    solution: Literal["INDOOR_CLIMATE"]
    active: bool


LightSceneEntryState: TypeAlias = Literal[
    "CONFIGURED", "CONFIGURED_WITH_SHORT_TIMES", "UNUSED"
]


class LightSceneEntry(TypedDict):
    id: int
    sortingIndex: int
    label: None
    type: str
    state: LightSceneEntryState
    interrupt: bool
    sceneIcon: None


class LightAndShadow(TypedDict):
    functionalGroups: list[str]
    extendedLinkedSwitchingGroups: list[str]
    extendedLinkedShutterGroups: list[None]
    switchingProfileGroups: list[str]
    shutterProfileGroups: list[None]
    lightSceneEntries: list[LightSceneEntry]
    extendedLinkedNotificationGroups: list[None]
    solution: Literal["LIGHT_AND_SHADOW"]
    active: bool


class SecuritySwitchingGroups(TypedDict):
    SIREN: str
    PANIC: str
    ALARM: str
    COMING_HOME: str
    BACKUP_ALARM_SIREN: str
    SIREN_SAFETY: str


class SecurityZones(TypedDict):
    EXTERNAL: str
    INTERNAL: str


class AlarmEventDeviceChannel(TypedDict):
    deviceId: str
    channelIndex: int


class SecurityAndAlarm(TypedDict):
    functionalGroups: list[str]
    alarmEventTimestamp: None | int
    alarmEventTriggerId: None
    alarmEventDeviceChannel: None | AlarmEventDeviceChannel
    alarmSecurityJournalEntryType: None | Literal["SENSOR_EVENT"]
    alarmActive: bool
    safetyAlarmEventTimestamp: None
    safetyAlarmEventDeviceChannel: None
    safetyAlarmSecurityJournalEntryType: None
    safetyAlarmActive: bool
    intrusionAlarmEventTimestamp: None | int
    intrusionAlarmEventTriggerId: None
    intrusionAlarmEventTriggerLabel: None | str
    intrusionAlarmEventDeviceChannel: None | AlarmEventDeviceChannel
    intrusionAlarmSecurityJournalEntryType: None | Literal["SENSOR_EVENT"]
    intrusionAlarmActive: bool
    securityZones: SecurityZones
    securitySwitchingGroups: SecuritySwitchingGroups
    zoneActivationDelay: float
    intrusionAlertThroughSmokeDetectors: bool
    securityZoneActivationMode: Literal["ACTIVATION_IF_ALL_IN_VALID_STATE"]
    deviceChannelSpecificFunction: dict[None, None]
    activationInProgress: bool
    solution: Literal["SECURITY_AND_ALARM"]
    active: bool


class WeatherAndEnvironment(TypedDict):
    functionalGroups: list[None]
    extendedLinkedWateringGroups: list[None]
    wateringProfileGroups: list[None]
    solution: Literal["WEATHER_AND_ENVIRONMENT"]
    active: bool


class FunctionalHomes(TypedDict):
    LIGHT_AND_SHADOW: LightAndShadow
    ENERGY: Energy
    WEATHER_AND_ENVIRONMENT: WeatherAndEnvironment
    INDOOR_CLIMATE: IndoorClimate
    ACCESS_CONTROL: AccessControl
    SECURITY_AND_ALARM: SecurityAndAlarm


class MassStorageDevice(TypedDict):
    id: str
    label: str
    mountingStatus: Literal["MOUNTED"]
    mountingStatusChangedTimestamp: int
    discUsageStatus: Literal["LESSER_THRESHOLDS"]
    discUsageStatusChangedTimestamp: int


MassStorageDeviceMap: TypeAlias = dict[str, MassStorageDevice]


class UpdatePeriods(TypedDict):
    MONDAY: list[None]
    TUESDAY: list[None]
    WEDNESDAY: list[None]
    THURSDAY: list[None]
    FRIDAY: list[None]
    SATURDAY: list[None]
    SUNDAY: list[None]


class SystemUpdateConfiguration(TypedDict):
    systemUpdateMode: Literal["AUTOMATIC"]
    updatePeriods: UpdatePeriods
    updateDuringSecurityMode: bool
    updatePeriodsEmpty: bool


class SystemUpdateState(TypedDict):
    updateActionId: None
    currentVersion: str
    availableVersion: None
    updateState: UpdateState
    updateActionState: Literal["OPEN"]
    updateTimestamp: None
    updateConfirmationNotificationSent: bool


class HomeExtension(TypedDict):
    homeExtensionType: str
    connectivityMode: str
    offlineModeLastActivationTimestamp: None
    commissioningResponseReceived: bool
    initialUpdateDone: bool
    initializationDone: bool
    systemPasswordAssigned: bool
    massStorageDeviceMap: MassStorageDeviceMap
    systemUpdateConfiguration: SystemUpdateConfiguration
    systemUpdateState: SystemUpdateState
    remoteClientCreationEnabled: bool
    remoteClientCreationTimeoutTimestamp: int
    wiredLanConnectionState: str
    wiFiConnectionState: str
    wiFiSsid: str
    wiFiApActive: bool
    accessPointUpgradeState: None
    developerModeActive: bool
    developerModeDeactivationAllowed: bool
    pluginApiExposed: bool
    developerModeActivationTimestamp: int


class LiveOTAUStatus(TypedDict):
    liveOTAUState: Literal["INACTIVE"]
    progress: float
    deviceId: None


class Location(TypedDict):
    city: str
    latitude: str
    longitude: str


class PluginInformation(TypedDict):
    id: str
    localizedLabels: FriendlyName
    pluginRuntimeStatus: Literal["CONFIG_REQUIRED", "NO_ERROR"]
    pluginUserMessageMap: dict[None, None]
    pluginUpdateState: UpdateState | None
    "remote have no update"
    lastPluginUpdateStateChanged: int | None
    "remote have no update"


PluginInformationMap: TypeAlias = dict[str, PluginInformation]


class RuleMetaData(TypedDict):
    id: str
    homeId: str
    label: str
    type: Literal["SIMPLE"]
    active: bool
    ruleErrorCategories: list[None]
    executionCounterOfDay: int
    specialInterestCategories: list[Literal["pushNotification"]]
    lastExecutionTimestamp: int | None


class VoiceControlSettings(TypedDict):
    language: None
    allowedActiveSecurityZoneIds: list[None]
    stateReportEnabled: dict[None, None]


class Weather(TypedDict):
    temperature: float
    weatherCondition: str
    weatherDayTime: str
    minTemperature: float
    maxTemperature: float
    humidity: int
    windSpeed: float
    windDirection: int
    vaporAmount: float


class Home(TypedDict):
    weather: Weather
    metaGroups: list[str]
    clients: list[str]
    connected: bool
    currentAPVersion: str
    availableAPVersion: None
    timeZoneId: str
    location: Location
    pinAssigned: bool
    pinChangeTimestamp: int
    pinChangeClientLabel: None
    userRightsManagementActive: bool
    liveUpdateSupported: bool
    dutyCycle: float
    carrierSense: float
    updateState: UpdateState
    powerMeterUnitPrice: float
    powerMeterCurrency: str
    deviceUpdateStrategy: str
    lastReadyForUpdateTimestamp: int
    functionalHomes: FunctionalHomes
    inboxGroup: str
    apExchangeClientId: None
    apExchangeState: str
    voiceControlSettings: VoiceControlSettings
    ruleGroups: list[str]
    ruleMetaDatas: dict[str, RuleMetaData]
    liveOTAUStatus: LiveOTAUStatus
    accessPointUpdateStates: dict[str, AccessPointUpdateState]
    accountLinkingStatus: None
    userRightsManagementActiveChangeStatus: UserRoleChangeStatus
    accountLinkingStatuses: dict[None, None]
    linkedExternalServices: list[None]
    accountLinkingStatusSet: list[None]
    externalServiceAccountLinkings: list[ExternalServiceAccountLinking]
    pluginInformationMap: PluginInformationMap
    pendingDeviceExchanges: dict[None, None]
    deviceExchangeErrors: dict[None, None]
    deviceExchangeHistoryEntries: list[None]
    notEntireExcludedAccessPoints: dict[None, None]
    homeExtension: HomeExtension
    exchangeTimestamp: None
    fixedDefaultGroups: dict[None, None]
    deviceDebugLoggingAllowed: None
    id: str
    userRightsManagementSupported: bool
    hueLinkingSupported: bool
    measuringBaseURL: str
    externalServiceSupportingMap: ExternalServiceSupportingMap


class SystemState(TypedDict):
    home: Home
    groups: Groups
    devices: Devices
    clients: Clients


class HomePushEvent(TypedDict):
    pushEventType: Literal["HOME_CHANGED"]
    home: Home


class DevicePushEvent(TypedDict):
    pushEventType: Literal["DEVICE_ADDED", "DEVICE_CHANGED"]
    device: Device


class DeviceRemovedPushEvent(TypedDict):
    pushEventType: Literal["DEVICE_REMOVED"]
    id: str


class GroupPushEvent(TypedDict):
    pushEventType: Literal["GROUP_ADDED", "GROUP_CHANGED"]
    group: Group


class GroupRemovedPushEvent(TypedDict):
    pushEventType: Literal["GROUP_REMOVED"]
    id: str


class ClientPushEvent(TypedDict):
    pushEventType: Literal["CLIENT_ADDED", "CLIENT_CHANGED"]
    client: Client


class ClientRemovedPushEvent(TypedDict):
    pushEventType: Literal["CLIENT_REMOVED"]
    id: str


class DeviceChannelEvent(TypedDict):
    pushEventType: Literal["DEVICE_CHANNEL_EVENT"]
    deviceId: str
    channelIndex: int
    channelEventType: Literal[
        "KEY_PRESS_LONG",
        "KEY_PRESS_SHORT",
        "KEY_PRESS_LONG_START",
        "KEY_PRESS_LONG_STOP",
    ]
    functionalChannelIndex: int


class SecurityJournalEvent(TypedDict):
    pushEventType: Literal["SECURITY_JOURNAL_CHANGED"]


Event: TypeAlias = (
    HomePushEvent
    | DevicePushEvent
    | DeviceRemovedPushEvent
    | GroupPushEvent
    | GroupRemovedPushEvent
    | ClientPushEvent
    | ClientRemovedPushEvent
    | DeviceChannelEvent
    | SecurityJournalEvent
)


class EventOrigin(TypedDict):
    originType: Literal["DEVICE", "INTERNAL", "CLIENT"]
    id: str


class EventTransaction(TypedDict):
    events: dict[str, Event]
    origin: EventOrigin
    accessPointId: str
    timestamp: int


class Events(TypedDict):
    eventTransaction: EventTransaction
