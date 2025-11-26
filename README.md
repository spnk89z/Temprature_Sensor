
# ESP8266 DHT SENSOR - ULTIMUM EDITION (Firmware + OTA)

This repository contains the ESP8266-based Ultimum DHT Temperature sensor firmware and helper scripts for building, signing, publishing, and verifying OTA updates.

Current firmware (example in source): `FW_VERSION = "3.5.1-ULTIMUM"` — devices will check the `version.json` at the configured URL and automatically perform OTA updates when a newer `version` is present.

Overview & features
-------------------
- Asynchronous web server & WebSocket live charts
- Role-based users (admin / viewer)
- REST API for state, config, OTA
- Home Assistant discovery + MQTT integration
- Optional Sinric Pro integration
- Encrypted configuration storage using `LittleFS` and a simple symmetrical XOR key
- Auto OTA updates via GitHub `raw.githubusercontent.com` link
- OTA signature verification example (ECDSA P-256) for secure updates
Note: If `sig` is present in `version.json`, device firmware must be built with MBEDTLS enabled to verify signatures before applying updates. Enable MBEDTLS in CI by setting the workflow input `with_mbedtls` to `true` when dispatching the workflow; locally build with `-D MBEDTLS` (PlatformIO or Arduino CLI build flags).

If a `sig` value is present, devices built without MBEDTLS will refuse to apply the update for safety.

Files in this repository
------------------------
- `src/` - example code and helpers (ota update / signature example)
  - `src/ota_signature_example.cpp` - example functions for verifying signed binaries before applying OTA updates (mbed TLS example present)
- `generate_firmware.py` - small generator to produce a firmware placeholder binary for testing and optionally sign with a private key
- `verify_version.py` - local verification script to compute SHA256 and optionally verify the signature using `scripts/public.pem` and `cryptography` library
- `version.json` - the version trigger that devices fetch to know whether to OTA update (must point to a raw GitHub URL for `bin`)
- `scripts/` - helper scripts
  - `scripts/gen_keys.sh` - generate an ECDSA P-256 key pair (private.pem / public.pem)
  - `scripts/sign_firmware.py` - sign a binary via openssl (DER and base64 output)
  - `scripts/sign_and_update_version.py` - sign and write a `version.json` containing `sig`, `sha256`, `size`, `build_date`, and `bin` fields
- `.github/workflows/ota_build.yml` - workflow to build/sign artifacts and update `version.json` (if configured with `SIGNING_KEY` secret)

Important constants & defaults (from firmware file)
-----------------------------------------------
- `FW_VERSION` in firmware: `3.5.1-ULTIMUM` (update before building to your next published version)
- `DHTPIN` : 14 (D5)
- `DHTTYPE` : DHT11
- WiFi AP for setup: `ULTIMUM_SETUP` / `12345678`
- Encrypted config file: `/config.enc` with `ENC_KEY` (default `ChangeThisKey123!` — change in production)
- `URL_VERSION_JSON` (OTA trigger): `https://raw.githubusercontent.com/spnk89z/Temprature_Sensor/main/version.json` (NOTE: must use raw.githubusercontent link)

- `version.json` — metadata and trigger information describing the binary (version, sha256, size, date).

How to verify locally:

1. Regenerate or inspect the firmware binary. To generate a test `firmware.bin` run:

```bash
python3 generate_firmware.py --version 1.0.0 --output firmware.bin --size-kb 16
```

2. Compute the file's SHA256 and compare to `version.json`:

```bash
python3 verify_version.py
```

3. If everything matches, commit and push the two files to GitHub.

Note: This `firmware.bin` is a placeholder used to test upload flows and automatic updates. Replace it with your real compiled firmware binary when ready.

How to publish a new update (manual):

1. Compile the firmware for the ESP8266 with the updated `FW_VERSION` in your code (e.g., from `3.5.1-ULTIMUM` to `3.6.0-ULTIMUM`).
2. Add the compiled binary to the repo (e.g., `firmware_3.6.0-ULTIMUM.bin`) or as a release asset.
3. Update `version.json` with:
	- `version` - the new version string that matches the binary (e.g. `3.6.0-ULTIMUM`)
	- `bin` - URL to the `raw.githubusercontent.com` path for the new binary
	- `sha256`, `size`, `build_date`, and other optional fields.
4. Commit & push changes to the `main` branch.

When a device running `FW_VERSION` (in your code) sees a `version.json` with a different `version` field (e.g., `3.6.0-ULTIMUM` != `3.5.1-ULTIMUM`), it will download the `bin` URL and flash it using OTA.

Automated Build & Publish (recommended):

The repo includes a GitHub Actions workflow `.github/workflows/ota_build.yml` that can be triggered manually (workflow_dispatch). It will:
- Generate a firmware binary using `generate_firmware.py` (replace with your build step if you compile with PlatformIO/Arduino CLI).
- Update `version.json` with the new version metadata.
- Commit the generated binary and `version.json` back to the repo and create a release.
To build with Arduino CLI in the workflow, set the `builder` input to `arduino` when dispatching the workflow; default is `platformio`.

Notes:
- Make sure your firmware's `FW_VERSION` is set to the version string in `version.json` once you flash it to devices, so devices don't self-update back to an older version.
- For security: use HTTPS links (`raw.githubusercontent.com`) and consider signing/validating the binary on device before flashing.
- If you prefer not to store compiled binaries on the repo, you can use GitHub Releases and update `version.json` with the `bin` URL pointing to the release asset's raw link.

Arduino CLI (alternative build instructions)
-----------------------------------------
If you want to build locally with Arduino CLI instead of PlatformIO:
1. Install and configure the Arduino CLI.
```bash
arduino-cli core update-index
arduino-cli core install esp8266:esp8266
```
2. Build and output the binary to a local build directory:
```bash
arduino-cli compile --fqbn esp8266:esp8266:nodemcuv2 --output-dir build --build-property build.extra_flags=-DFW_VERSION=\"3.6.0-ULTIMUM\" ./arduino
```
3. The compiled binary will be in `build` — copy out the first `*.bin` as `firmware_3.6.0-ULTIMUM.bin` and sign as usual.

Note: If your real firmware references additional libraries (ESPAsyncWebServer, DHT, etc.), you'll need to install those libraries with `arduino-cli lib install` or include them in the sketch directory as required.
Signing & Verification (Recommended)

1. Generate a signing ECDSA P-256 key pair locally:

```bash
cd scripts
./gen_keys.sh
```

2. Sign a compiled firmware binary and update `version.json` automatically:

```bash
python3 scripts/sign_and_update_version.py --bin firmware_3.6.0-ULTIMUM.bin --version 3.6.0-ULTIMUM --key scripts/private.pem --json version.json --raw-base-url "https://raw.githubusercontent.com/spnk89z/Temprature_Sensor/main"
```

3. Embed the public key PEM (`scripts/public.pem`) into the firmware code (set `OTA_PUBKEY_PEM`) so the device can verify signatures before flashing.

4. The example firmware code in `src/ota_signature_example.cpp` demonstrates how to:
	- download the binary to LittleFS, compute SHA256 and verify it matches `sha256` in `version.json`.
	- verify the binary's ECDSA signature (base64 `sig`) using the embedded public key (mbed TLS usage shown).
	- apply the update if both checks pass.

Security notes:
- Keep your private key secret and do not commit it to the repo. Use CI secrets or off-line signing.
- For production, replace `client.setInsecure()` with certificate pinning or proper TLS validation.
- Consider adding a robust rollback strategy and signature/public key rotation plan for production devices.
