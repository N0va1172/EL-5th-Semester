
/*
  ESP1 - AUTHORIZED SENDER WITH HMAC-SHA256

  Original functions preserved:
    red   -> toggle LED1
    green -> toggle LED2
    blue  -> toggle LED3

  CAN TX: GPIO21
  CAN RX: GPIO22
  Bitrate: 250 kbps

  CAN frames:
    0x120: LED index (1 byte)
    0x121: counter   (4 bytes)
    0x122: HMAC tag  (8 bytes)

  The command and counter are authenticated
  using a shared HMAC-SHA256 secret key.
*/

#include <Arduino.h>
#include "driver/twai.h"
#include <mbedtls/md.h>
#include <Preferences.h>

#define CAN_TX GPIO_NUM_21
#define CAN_RX GPIO_NUM_22

#define LED_CTRL_ID 0x120
#define COUNTER_ID  0x121
#define HMAC_ID     0x122

#define LED1_RED   1
#define LED2_GREEN 2
#define LED3_BLUE  3

// Demonstration key.
// Replace with your own random 32-byte key.
// ESP1 and ESP2 must contain identical keys.
const uint8_t HMAC_KEY[32] = {
  0x4B, 0x91, 0x2F, 0xA6,
  0xD3, 0x58, 0x17, 0xE0,
  0x6C, 0xB4, 0x29, 0x7D,
  0x83, 0xF1, 0x05, 0xAC,
  0x37, 0xDE, 0x62, 0x19,
  0xB8, 0x43, 0x0F, 0x95,
  0xE2, 0x76, 0xCA, 0x31,
  0x54, 0x8D, 0xFB, 0x20
};

Preferences counterStore;
uint32_t txCounter = 0;

// Convert a 32-bit counter to four bytes.
void encodeCounter(uint32_t counter, uint8_t *out) {
  out[0] = (counter >> 24) & 0xFF;
  out[1] = (counter >> 16) & 0xFF;
  out[2] = (counter >> 8)  & 0xFF;
  out[3] = counter & 0xFF;
}

/*
  HMAC input (12 bytes):

  [LEDv1] [CAN ID] [LED INDEX] [COUNTER]

  This binds the authentication tag to:
    - the LED protocol
    - the CAN control ID
    - the selected LED
    - the command counter
*/
bool calculateHMAC(
    uint8_t ledIndex,
    uint32_t counter,
    uint8_t output[32]) {

  uint8_t message[12] = {
    'L', 'E', 'D', 'v', '1',
    (uint8_t)(LED_CTRL_ID >> 8),
    (uint8_t)(LED_CTRL_ID & 0xFF),
    ledIndex,
    0, 0, 0, 0
  };

  encodeCounter(counter, &message[8]);

  const mbedtls_md_info_t *md =
      mbedtls_md_info_from_type(
        MBEDTLS_MD_SHA256
      );

  if (md == nullptr) {
    return false;
  }

  int result = mbedtls_md_hmac(
    md,
    HMAC_KEY,
    sizeof(HMAC_KEY),
    message,
    sizeof(message),
    output
  );

  return result == 0;
}

// Keep the original single-shot CAN behavior.
bool sendFrame(twai_message_t &msg) {
  msg.ss = 1;

  return twai_transmit(
    &msg,
    pdMS_TO_TICKS(100)
  ) == ESP_OK;
}

void sendCommand(uint8_t ledIndex) {

  if (txCounter == UINT32_MAX) {
    Serial.println("COUNTER EXHAUSTED");
    return;
  }

  uint32_t nextCounter = txCounter + 1;

  // Calculate HMAC before sending anything.
  uint8_t digest[32] = {};

  if (!calculateHMAC(
      ledIndex, nextCounter, digest)) {
    Serial.println("HMAC GENERATION FAILED");
    return;
  }

  // Persist the counter before transmission.
  // Prevents reuse after a normal reboot.
  if (counterStore.putUInt(
      "tx_ctr", nextCounter) != sizeof(uint32_t)) {
    Serial.println("COUNTER STORAGE FAILED");
    return;
  }

  txCounter = nextCounter;

  // FRAME 1: Original LED command, unchanged.
  twai_message_t commandFrame = {};

  commandFrame.identifier = LED_CTRL_ID;
  commandFrame.data_length_code = 1;
  commandFrame.data[0] = ledIndex;

  // FRAME 2: 32-bit monotonic counter.
  twai_message_t counterFrame = {};

  counterFrame.identifier = COUNTER_ID;
  counterFrame.data_length_code = 4;

  encodeCounter(
    txCounter,
    counterFrame.data
  );

  // FRAME 3: First 8 bytes of HMAC-SHA256.
  twai_message_t hmacFrame = {};

  hmacFrame.identifier = HMAC_ID;
  hmacFrame.data_length_code = 8;

  memcpy(hmacFrame.data, digest, 8);

  // Queue the frames in sequence.
  if (!sendFrame(commandFrame)) {
    Serial.println("COMMAND FRAME QUEUE FAILED");
    return;
  }

  if (!sendFrame(counterFrame)) {
    Serial.println("COUNTER FRAME QUEUE FAILED");
    return;
  }

  if (!sendFrame(hmacFrame)) {
    Serial.println("HMAC FRAME QUEUE FAILED");
    return;
  }

  Serial.printf(
    "\nCAN TX | ID: 0x%03X | TOGGLE LED: %u\n",
    LED_CTRL_ID,
    ledIndex
  );

  Serial.printf(
    "COUNTER: %lu\n",
    (unsigned long)txCounter
  );

  Serial.print("HMAC TAG: ");

  for (int i = 0; i < 8; i++) {
    Serial.printf("%02X ", digest[i]);
  }

  Serial.println();
  Serial.println("3 CAN frames queued");
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(50);

  if (!counterStore.begin("can_auth", false)) {
    Serial.println("NVS INITIALIZATION FAILED");
    while (true) delay(1000);
  }

  txCounter = counterStore.getUInt("tx_ctr", 0);

  twai_general_config_t g =
      TWAI_GENERAL_CONFIG_DEFAULT(
        CAN_TX,
        CAN_RX,
        TWAI_MODE_NORMAL
      );

  twai_timing_config_t t =
      TWAI_TIMING_CONFIG_250KBITS();

  twai_filter_config_t f =
      TWAI_FILTER_CONFIG_ACCEPT_ALL();

  if (twai_driver_install(&g, &t, &f) != ESP_OK ||
      twai_start() != ESP_OK) {

    Serial.println("CAN setup failed");
    while (true) delay(1000);
  }

  twai_reconfigure_alerts(
    TWAI_ALERT_TX_SUCCESS |
    TWAI_ALERT_TX_FAILED |
    TWAI_ALERT_BUS_ERROR |
    TWAI_ALERT_BUS_OFF,
    NULL
  );

  Serial.println("ESP1 - HMAC AUTHORIZED SENDER READY");
  Serial.println("Commands: red, green, blue");
  Serial.printf(
    "Stored counter: %lu\n",
    (unsigned long)txCounter
  );
}

void loop() {

  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');

    cmd.trim();
    cmd.toLowerCase();

    uint8_t ledIndex;

    if (cmd == "red") {
      ledIndex = LED1_RED;
    }
    else if (cmd == "green") {
      ledIndex = LED2_GREEN;
    }
    else if (cmd == "blue") {
      ledIndex = LED3_BLUE;
    }
    else {
      Serial.println(
        "Invalid command. Use: red, green, blue"
      );
      return;
    }

    sendCommand(ledIndex);
  }

  uint32_t alerts = 0;

  if (twai_read_alerts(&alerts, 0) == ESP_OK) {

    if (alerts & TWAI_ALERT_TX_SUCCESS)
      Serial.println("CAN TX SUCCESS");

    if (alerts & TWAI_ALERT_TX_FAILED)
      Serial.println("CAN TX FAILED");

    if (alerts & TWAI_ALERT_BUS_ERROR)
      Serial.println("CAN BUS ERROR");

    if (alerts & TWAI_ALERT_BUS_OFF)
      Serial.println("CAN BUS OFF");
  }
}
