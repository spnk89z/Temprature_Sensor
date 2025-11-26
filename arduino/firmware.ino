#ifndef FW_VERSION
#define FW_VERSION "3.5.1-ULTIMUM"
#endif

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("Ultimum Arduino Firmware starting...");
  Serial.print("FW_VERSION: ");
  Serial.println(FW_VERSION);
}

void loop() {
  delay(1000);
}
