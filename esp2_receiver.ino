/*
  ESP2 - RECEIVER (3 independent external LEDs, 1-word toggle)
  -----------------------------------------------------------------
  Listens for a 1-byte command on LED_CTRL_ID:
    data[0] = which LED (1, 2, or 3)

  On receipt, TOGGLES that LED's state - on if it was off, off if it
  was on - and leaves the other two completely untouched. State is
  tracked locally per LED (ledState[]).

  WIRING (per LED, x3):
    ESP32 GPIO --- 220ohm resistor --- LED anode (+, longer leg)
    LED cathode (-, shorter leg)   --- GND

  Pin assignment:
    LED1 (red)   -> GPIO 25
    LED2 (green) -> GPIO 26
    LED3 (blue)  -> GPIO 27

  All 3 LED cathodes share the same GND rail as the ESP32 and the
  CAN transceiver.
*/

#include <Arduino.h>
#include "driver/twai.h"

#define CAN_TX GPIO_NUM_21
#define CAN_RX GPIO_NUM_22

#define LED_CTRL_ID 0x120

#define LED1_PIN GPIO_NUM_25
#define LED2_PIN GPIO_NUM_26
#define LED3_PIN GPIO_NUM_27

// Index 0 unused, 1=LED1, 2=LED2, 3=LED3
bool ledState[4] = {false, false, false, false};

gpio_num_t pinFor(uint8_t ledIndex) {
  switch (ledIndex) {
    case 1: return LED1_PIN;
    case 2: return LED2_PIN;
    case 3: return LED3_PIN;
    default: return GPIO_NUM_NC;
  }
}

void toggleLED(uint8_t ledIndex) {
  ledState[ledIndex] = !ledState[ledIndex];
  digitalWrite(pinFor(ledIndex), ledState[ledIndex] ? HIGH : LOW);
}

void setup() {
  Serial.begin(115200);

  pinMode(LED1_PIN, OUTPUT);
  pinMode(LED2_PIN, OUTPUT);
  pinMode(LED3_PIN, OUTPUT);
  digitalWrite(LED1_PIN, LOW);
  digitalWrite(LED2_PIN, LOW);
  digitalWrite(LED3_PIN, LOW);

  twai_general_config_t g = TWAI_GENERAL_CONFIG_DEFAULT(CAN_TX, CAN_RX, TWAI_MODE_NORMAL);
  twai_timing_config_t t = TWAI_TIMING_CONFIG_250KBITS();
  twai_filter_config_t f = TWAI_FILTER_CONFIG_ACCEPT_ALL();

  if (twai_driver_install(&g, &t, &f) != ESP_OK || twai_start() != ESP_OK) {
    Serial.println("CAN setup failed");
    while (true) delay(1000);
  }

  Serial.println("ESP2 - RECEIVER READY (3 independent external LEDs, toggle)");
}

void loop() {
  twai_message_t rx = {};

  if (twai_receive(&rx, pdMS_TO_TICKS(100)) != ESP_OK) {
    return;
  }

  if (rx.extd || rx.rtr || rx.identifier != LED_CTRL_ID || rx.data_length_code != 1) {
    return; // not our control frame
  }

  uint8_t ledIndex = rx.data[0];

  Serial.printf("RECEIVED | ID: 0x%03lX | TOGGLE LED: %u\n",
                (unsigned long)rx.identifier, ledIndex);

  if (ledIndex < 1 || ledIndex > 3) {
    Serial.println("UNKNOWN LED INDEX");
    return;
  }

  toggleLED(ledIndex);
  Serial.printf("LED%u is now %s\n", ledIndex, ledState[ledIndex] ? "ON" : "OFF");
}
