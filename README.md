# Hardware Certificate Tool

An open-source Android utility for provisioning and verifying Hardware-Backed credentials (TEE/StrongBox).

## Features
* **Key Generation:** Create RSA/EC keys inside the Android Keystore.
* **CSR Creation:** Generate PKCS#10 Certificate Signing Requests.
* **Verification:** Inspect installed certificates to confirm hardware storage type (TEE vs StrongBox).
* **Import:** Install signed certificates into the System KeyChain for use by Chrome and other apps.

## Getting Started
1. Clone the repository.
2. Open in **Android Studio**.
3. Sync Gradle and run on a device (API 31+ recommended).

## License
[Apache 2.0](LICENSE)
