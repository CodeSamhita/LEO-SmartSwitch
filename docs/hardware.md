# Hardware and wiring

## Hub: ESP32-S3 dev board (8 MB flash)
| Function | GPIO |
|---|---|
| Onboard RGB status LED | 48 (38 on DevKitC v1.1); the firmware drives both |
| BOOT button: hold 15 s = factory reset | 0 |

Power it from any good USB supply. Nothing else is connected.

## Smart switch: ESP32-C3 Super Mini
| Function | GPIO | Notes |
|---|---|---|
| Relay 1–4 | 0, 1, 3, 10 | active-LOW relay board; all OFF at power-up |
| Touch pad 1–4 (TTP223 OUT) | 4, 5, 6, 7 | OUT goes HIGH when touched; unwired pins are pulled down. Off by default, enable in the app |
| Status LED (WS2812 / NeoPixel) | 2 | replaces the power LED |
| BOOT button: hold 15 s = factory reset | 9 | |

Relays run from the module's own supply. Touch pads take 3.3 V and GND from the C3.

## Water tank: ESP32-C3 Super Mini
Same wiring as the earlier tank_v9 / AquaNode builds.

| Function | GPIO | Notes |
|---|---|---|
| HC-SR04 TRIG | 4 | |
| HC-SR04 ECHO | 3 | pulled down: no sensor reads as "no echo" |
| 9× WS2812B strip | 2 | GRB. LEDs 1–8 from the bottom can show the level (count and colours set in the app); LED 9 (top) is the status light. All level LEDs blink yellow rapidly when the sensor fails |
| LDR divider | 0 | ADC; a higher value means brighter. This is the room light sensor for every device |
| Push button to GND | 1 | silences an alarm |
| BOOT button: hold 15 s = factory reset | 9 | on the board |
| Buzzer (active) | 10 | HIGH = sound |

The sensor sits at the top of the tank, looking down. With the default calibration, 15 cm to the water
reads 100 % and 103 cm reads 0 %. Recalibrate on the tank page.

## Radio placement
Signal strength is shown on each device page and under *Advanced*:
- −50 to −70 dBm is good.
- Around −85 dBm works, but updates take longer.
- Below −90 dBm is unreliable.

The C3 Super Mini runs at reduced transmit power (8.5 dBm) because its radio is unstable at full power.
Move it a little closer to the hub if the signal is weak.
