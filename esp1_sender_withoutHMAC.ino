/*
  ESP1 - AUTHORIZED SENDER (3 independent external LEDs, 1-word toggle)
  --------------------------------------------------------------------
  Sends a 1-byte command on one CAN ID:
    data[0] = which LED (1, 2, or 3)

  ESP2 TOGGLES that LED's state on receipt - on if it was off, off if
  it was on - and leaves the other two LEDs completely untouched. So
  typing "red" then "blue" leaves both on; typing "red" twice turns
  it off again.

  Serial commands (type in Serial Monitor, 115200 baud):
    red     -> toggle LED1
    green   -> toggle LED2
    blue    -> toggle LED3

  No "announcement" frame in this version - ESP3 (the tap) is meant
  to be completely blind to what any ID/byte means, so there is
  nothing here for it to learn from. It just watches raw traffic.
*/

#include <Arduino.h>
#include "driver/twai.h"

#define CAN_TX GPIO_NUM_21
#define CAN_RX GPIO_NUM_22

// Single control channel. ESP3 does NOT know this ID means anything -
// it is only meaningful to ESP1 and ESP2.
#define LED_CTRL_ID 0x120

#define LED1_RED   1
#define LED2_GREEN 2
#define LED3_BLUE  3

bool sendFrame(twai_message_t &msg) {
  msg.ss = 1; // single-shot: one attempt, don't hammer a broken bus
  return twai_transmit(&msg, pdMS_TO_TICKS(100)) == ESP_OK;
}

void sendCommand(uint8_t ledIndex) {
  twai_message_t msg = {};
  msg.identifier = LED_CTRL_ID;
  msg.data_length_code = 1;
  msg.data[0] = ledIndex;

  if (sendFrame(msg)) {
    Serial.printf("CAN TX | ID: 0x%03X | TOGGLE LED: %u\n", LED_CTRL_ID, ledIndex);
  } else {
    Serial.println("CAN TX FAILED");
  }
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(50);

  twai_general_config_t g = TWAI_GENERAL_CONFIG_DEFAULT(CAN_TX, CAN_RX, TWAI_MODE_NORMAL);
  twai_timing_config_t t = TWAI_TIMING_CONFIG_250KBITS();
  twai_filter_config_t f = TWAI_FILTER_CONFIG_ACCEPT_ALL();

  if (twai_driver_install(&g, &t, &f) != ESP_OK || twai_start() != ESP_OK) {
    Serial.println("CAN setup failed");
    while (true) delay(1000);
  }

  twai_reconfigure_alerts(
    TWAI_ALERT_TX_SUCCESS | TWAI_ALERT_TX_FAILED |
    TWAI_ALERT_BUS_ERROR  | TWAI_ALERT_BUS_OFF,
    NULL
  );

  Serial.println("ESP1 - AUTHORIZED SENDER READY");
  Serial.println("Commands: red, green, blue  (each toggles that LED independently)");
}

void loop() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    cmd.toLowerCase();

    uint8_t ledIndex;
    if (cmd == "red")        ledIndex = LED1_RED;
    else if (cmd == "green") ledIndex = LED2_GREEN;
    else if (cmd == "blue")  ledIndex = LED3_BLUE;
    else {
      Serial.println("Invalid command. Use: red, green, blue");
      return;
    }

    sendCommand(ledIndex);
  }

  uint32_t alerts = 0;
  if (twai_read_alerts(&alerts, 0) == ESP_OK) {
    if (alerts & TWAI_ALERT_TX_SUCCESS) Serial.println("CAN TX SUCCESS");
    if (alerts & TWAI_ALERT_TX_FAILED)  Serial.println("CAN TX FAILED");
    if (alerts & TWAI_ALERT_BUS_ERROR)  Serial.println("CAN BUS ERROR");
    if (alerts & TWAI_ALERT_BUS_OFF)    Serial.println("CAN BUS OFF");
  }
}
