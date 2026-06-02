---
name: iot-embedded-hardware-security-assessment
description: Use for IoT, embedded, firmware, hardware security, UART/JTAG/SWD, bootloader, secure boot, OTA update, radio protocol, device cloud, mobile companion app, and embedded Linux assessment work.
---

# IoT, embedded, and hardware security assessment

Use this skill for device security reviews, firmware analysis, hardware interface testing, OTA validation, embedded Linux, and connected-device ecosystems.

## Guardrails

- Confirm authorization and lab safety before hardware probing, radio testing, or destructive firmware operations.
- Preserve original firmware and device state before modification.
- Avoid live radio or carrier testing outside approved spectrum and lab conditions.

## Workflow

1. Scope device model, firmware version, board revision, cloud/API endpoints, mobile apps, radios, and update mechanisms.
2. Acquire firmware safely: vendor download, OTA capture, flash dump, filesystem extraction, or debug interface.
3. Analyze firmware:
   - hardcoded secrets and certificates
   - update signing and rollback protection
   - exposed services and default credentials
   - SBOM/dependency CVEs
   - writable paths, init scripts, cron, and persistence
4. Analyze hardware:
   - UART/JTAG/SWD exposure
   - secure boot state
   - flash encryption
   - debug locks and test pads
5. Analyze ecosystem:
   - mobile app API behavior
   - cloud auth and device identity
   - MQTT/CoAP/HTTP/TLS configuration
   - BLE/Wi-Fi/Zigbee/Z-Wave protocol risks where applicable
6. Report exploitability with physical access level, required tools, persistence, and recovery impact.

## Output pattern

| Surface | Finding | Access needed | Evidence | Impact | Fix | Verification |
| --- | --- | --- | --- | --- | --- | --- |
