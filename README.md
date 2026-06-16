# esp32-atecc608a-iot-data
An ESP32-based IoT edge node utilizing an ATECC608A secure element for hardware key storage  and AES-128-GCM encryption to securely transmit sensor data over UDP.

# Secure Data Communication in IoT using Cryptography

An ESP32-based IoT edge node utilizing an ATECC608A secure element for hardware key storage (master key), session key derivation (encryption key) and AES-128-GCM encryption to securely transmit sensor telemetry over UDP.

## Overview

This repository contains the firmware and backend architecture for a highly secure, resource-efficient IoT edge device. The system acquires environmental data (DHT11) via an ESP32 and transmits it over Wi-Fi (UDP). To overcome the physical extraction vulnerabilities of standard microcontrollers, this project implements a **"Zero-Key-in-Flash"** policy by delegating all Root of Trust (RoT) operations to a **Microchip ATECC608A** cryptographic co-processor.


## Core Security Architecture

**Hardware-Locked Master Key (Provisioning):** During the initial setup, the ESP32's True Random Number Generator (TRNG) creates a Master Secret ($K_m$). This key is securely injected into the ATECC608A's EEPROM and permanently hardware-locked. It is never exposed to the ESP32's volatile memory again, neutralizing physical extraction attacks.
  
**Ephemeral Session Keys (Perfect Forward Secrecy):** Static keys are never used for data transmission. For each payload, the ESP32 generates a 32-byte dynamic Initialization Vector (IV). The ATECC608A uses its HMAC-SHA256 engine to derive a unique 128-bit Session Key ($K_s$) from the $K_m$ and the IV.

**Hybrid AES-128-GCM Encryption:** To balance security and IoT power constraints, the system uses a hybrid approach. The ESP32's hardware accelerator processes the AES-128 encryption (Ciphertext), while a software-based Galois/Counter Mode (GHASH) computes the 16-byte Authentication Tag (MAC) to prove data integrity.

**Replay Attack Mitigation:** The Python backend server maintains an O(1) lookup set (`seen_ivs`) of all incoming Initialization Vectors. Any UDP packet attempting to reuse an IV is instantly flagged as a replay attack and dropped before cryptographic processing.


## Custom Binary UDP Protocol

To minimize latency and avoid TCP handshake overhead, the encrypted payload is serialized into a strict Byte-Offset binary frame before UDP transmission:

* **Bytes [0:32]:** Initialization Vector (IV)
* **Bytes [32:48]:** GCM Authentication Tag (MAC)
* **Bytes [48:end]:** AES-128 Ciphertext (Sensor Data)


## Hardware Stack

* **Microcontroller:** ESP32 (Dual-core Tensilica LX6)
* **Secure Element:** Microchip ATECC608A (Interfaced via I2C at 100kHz)
* **Sensor:** DHT11 (Temperature & Humidity)


Hardware Datasheets

Microchip ATECC608A: CryptoAuthentication™ Device Summary Datasheet

Espressif ESP32: ESP32 Technical Reference Manual

DHT11 Sensor: Temperature and Humidity Module Specifications

Software & Frameworks

ESP-IDF: Espressif IoT Development Framework Programming Guide

Microchip CryptoAuthLib: Official Secure Element Library

Mbed TLS: Cryptographic Library for ESP32 Hardware Acceleration

