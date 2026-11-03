
/*
  ESP2 - RECEIVER WITH HMAC-SHA256

  Unchanged LED pins:
    LED1 RED   -> GPIO25
    LED2 GREEN -> GPIO26
    LED3 BLUE  -> GPIO27

  Unchanged CAN pins:
    TX -> GPIO21
    RX -> GPIO22

  Unchanged behavior:
    Each valid command toggles one LED
    independently.

  New security:
    - HMAC-SHA256 authentication
    - 32-bit anti-replay counter
    - Persistent counter storage
    - Reject unauthenticated commands
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

#define LED1_PIN GPIO_NUM_25
#define LED2_PIN GPIO_NUM_26
#define LED3_PIN GPIO_NUM_27

#define AUTH_TIMEOUT_MS 1000

// Must match ESP1 exactly.
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

// Original independent LED state tracking.
bool ledState[4] = {
  false, false, false, false
};

Preferences counterStore;
uint32_t lastAcceptedCounter = 0;

// Authentication state machine.
enum AuthState {
  WAIT_COMMAND,
  WAIT_COUNTER,
  WAIT_HMAC
};

AuthState authState = WAIT_COMMAND;

uint8_t pendingLED = 0;
uint32_t pendingCounter = 0;
uint32_t pendingStart = 0;

// Original pin selection.
gpio_num_t pinFor(uint8_t ledIndex) {
  switch (ledIndex) {
    case 1: return LED1_PIN;
    case 2: return LED2_PIN;
    case 3: return LED3_PIN;
    default: return GPIO_NUM_NC;
  }
}

// Original toggle behavior.
void toggleLED(uint8_t ledIndex) {
  ledState[ledIndex] = !ledState[ledIndex];

  digitalWrite(
    pinFor(ledIndex),
    ledState[ledIndex] ? HIGH : LOW
  );
}

// Decode four-byte big-endian counter.
uint32_t decodeCounter(const uint8_t *data) {
  return
    ((uint32_t)data[0] << 24) |
    ((uint32_t)data[1] << 16) |
    ((uint32_t)data[2] << 8) |
    ((uint32_t)data[3]);
}

void encodeCounter(uint32_t counter, uint8_t *out) {
  out[0] = (counter >> 24) & 0xFF;
  out[1] = (counter >> 16) & 0xFF;
  out[2] = (counter >> 8)  & 0xFF;
  out[3] = counter & 0xFF;
}

// Identical HMAC calculation to ESP1.
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

  return mbedtls_md_hmac(
    md,
    HMAC_KEY,
    sizeof(HMAC_KEY),
    message,
    sizeof(message),
    output
  ) == 0;
}

// Fixed-length comparison without an
// early exit on the first differing byte.
bool verifyTag(
    const uint8_t *received,
    const uint8_t *expected) {

  uint8_t difference = 0;

  for (int i = 0; i < 8; i++) {
    difference |= received[i] ^ expected[i];
  }

  return difference == 0;
}

void resetAuthentication() {
  authState = WAIT_COMMAND;
  pendingLED = 0;
  pendingCounter = 0;
  pendingStart = 0;
}

void handleCommand(const twai_message_t &rx) {

  if (rx.data_length_code != 1) {
    Serial.println("REJECTED: INVALID COMMAND LENGTH");
    resetAuthentication();
    return;
  }

  uint8_t ledIndex = rx.data[0];

  if (ledIndex < 1 || ledIndex > 3) {
    Serial.println("REJECTED: UNKNOWN LED INDEX");
    resetAuthentication();
    return;
  }

  // Do NOT toggle yet.
  pendingLED = ledIndex;
  pendingStart = millis();
  pendingCounter = 0;
  authState = WAIT_COUNTER;

  Serial.printf(
    "COMMAND RECEIVED | LED: %u | AUTH PENDING\n",
    pendingLED
  );
}

void handleCounter(const twai_message_t &rx) {

  if (authState != WAIT_COUNTER) {
    Serial.println("REJECTED: UNEXPECTED COUNTER");
    resetAuthentication();
    return;
  }

  if (rx.data_length_code != 4) {
    Serial.println("REJECTED: INVALID COUNTER LENGTH");
    resetAuthentication();
    return;
  }

  pendingCounter = decodeCounter(rx.data);

  Serial.printf(
    "COUNTER RECEIVED: %lu\n",
    (unsigned long)pendingCounter
  );

  // Reject previously accepted counters.
  if (pendingCounter <= lastAcceptedCounter) {
    Serial.println("REJECTED: REPLAY / OLD COUNTER");
    resetAuthentication();
    return;
  }

  authState = WAIT_HMAC;
}

void handleHMAC(const twai_message_t &rx) {

  if (authState != WAIT_HMAC) {
    Serial.println("REJECTED: UNEXPECTED HMAC");
    resetAuthentication();
    return;
  }

  if (rx.data_length_code != 8) {
    Serial.println("REJECTED: INVALID HMAC LENGTH");
    resetAuthentication();
    return;
  }

  uint8_t expectedDigest[32] = {};

  if (!calculateHMAC(
      pendingLED,
      pendingCounter,
      expectedDigest)) {
    Serial.println("REJECTED: HMAC CALCULATION ERROR");
    resetAuthentication();
    return;
  }

  if (!verifyTag(rx.data, expectedDigest)) {
    Serial.println("REJECTED: HMAC MISMATCH");
    resetAuthentication();
    return;
  }

  // A command can only be accepted once.
  if (pendingCounter <= lastAcceptedCounter) {
    Serial.println("REJECTED: REPLAY DETECTED");
    resetAuthentication();
    return;
  }

  // Persist the new counter BEFORE toggling.
  // If storage fails, the command is rejected.
  if (counterStore.putUInt(
      "rx_ctr", pendingCounter) != sizeof(uint32_t)) {
    Serial.println("REJECTED: COUNTER STORAGE FAILED");
    resetAuthentication();
    return;
  }

  lastAcceptedCounter = pendingCounter;

  uint8_t acceptedLED = pendingLED;
  uint32_t acceptedCounter = pendingCounter;

  resetAuthentication();

  Serial.println("HMAC VERIFIED");
  Serial.println("COUNTER VERIFIED");
  Serial.println("COMMAND AUTHENTICATED");

  // Only now does the original LED action happen.
  toggleLED(acceptedLED);

  Serial.printf(
    "RECEIVED | ID: 0x%03X | TOGGLE LED: %u\n",
    LED_CTRL_ID, acceptedLED
  );

  Serial.printf(
    "LED%u is now %s\n",
    acceptedLED,
    ledState[acceptedLED] ? "ON" : "OFF"
  );

  Serial.printf(
    "LAST ACCEPTED COUNTER: %lu\n",
    (unsigned long)acceptedCounter
  );
}

void setup() {
  Serial.begin(115200);

  // Original LED initialization.
  pinMode(LED1_PIN, OUTPUT);
  pinMode(LED2_PIN, OUTPUT);
  pinMode(LED3_PIN, OUTPUT);

  digitalWrite(LED1_PIN, LOW);
  digitalWrite(LED2_PIN, LOW);
  digitalWrite(LED3_PIN, LOW);

  if (!counterStore.begin("can_auth", false)) {
    Serial.println("NVS INITIALIZATION FAILED");
    while (true) delay(1000);
  }

  lastAcceptedCounter =
      counterStore.getUInt("rx_ctr", 0);

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

  Serial.println("ESP2 - HMAC RECEIVER READY");

  Serial.printf(
    "Last accepted counter: %lu\n",
    (unsigned long)lastAcceptedCounter
  );
}

void loop() {

  twai_message_t rx = {};

  if (twai_receive(
      &rx, pdMS_TO_TICKS(50)) == ESP_OK) {

    // Accept standard CAN data frames only.
    if (!rx.extd && !rx.rtr) {

      if (rx.identifier == LED_CTRL_ID) {
        handleCommand(rx);
      }

      else if (rx.identifier == COUNTER_ID) {
        handleCounter(rx);
      }

      else if (rx.identifier == HMAC_ID) {
        handleHMAC(rx);
      }
    }
  }

  // Discard incomplete authentication sequences.
  if (authState != WAIT_COMMAND &&
      millis() - pendingStart > AUTH_TIMEOUT_MS) {

    Serial.println("REJECTED: AUTHENTICATION TIMEOUT");
    resetAuthentication();
  }
}
