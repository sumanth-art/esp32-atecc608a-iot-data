#include <stdio.h>
#include <string.h>
#include <unistd.h>

// ESP-IDF Core, Networking & Timers
#include "esp_system.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "lwip/sockets.h"
#include "esp_rom_sys.h"
#include "driver/gpio.h"

// Crypto & ATECC608A
#include "cryptoauthlib.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"

// DHT sensor 
#include "dht.h"   
#define DHT_GPIO 4

// 1. Network Credentials
#define WIFI_SSID "POCO M3"
#define WIFI_PASS "11223344"
#define DEST_IP "255.255.255.255"
#define DEST_PORT 8080

// ATECC Pins
#define SDA_PIN 21
#define SCL_PIN 22

// Global buffers
uint8_t session_key[32] = {0}; 
uint8_t shared_iv[32] = {0}; 
volatile bool wifi_connected = false;

// --- WIFI EVENT HANDLER (Exactly from your working code) ---
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_connected = false;
        esp_wifi_connect(); 
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        wifi_connected = true;
    }
}

// --- CONNECT WIFI (Exactly from your working code) ---
void connect_wifi() {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL);

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();

    while (!wifi_connected) {
        usleep(500000);
        printf(".");
        fflush(stdout);
    }
    printf("\nWiFi Connected.\n");
}

// --- ATECC608A LOGIC ---
void atecc_manual_wake() {
    gpio_reset_pin(SDA_PIN);
    gpio_set_direction(SDA_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(SDA_PIN, 0);
    esp_rom_delay_us(80); 
    gpio_set_direction(SDA_PIN, GPIO_MODE_INPUT);
    esp_rom_delay_us(1500); 
}

// session key derivation from atecc608a

ATCA_STATUS derive_session_key(void) {
    // SHA_MODE_TARGET_OUT_ONLY executes HMAC-SHA256(Slot 5, shared_iv)
    // and sends the result directly to the output_key buffer.
    ATCA_STATUS status = atcab_sha_hmac(shared_iv, 32, 5, session_key, SHA_MODE_TARGET_OUT_ONLY);

    if (status != ATCA_SUCCESS) {
        printf("CRITICAL: Hardware HMAC Derivation Failed (0x%02X)\n", status);
        // Ensure the output key is wiped if derivation fails for security
        memset(session_key, 0, 32); 
    }

    return status;
}

// --- MAIN APP ---
void app_main() {
    // 1. Setup Wi-Fi First (Your working sequence)
    connect_wifi();

    // 2. Setup Hardware Security
    atecc_manual_wake();

    ATCAIfaceCfg cfg = {
        .iface_type = ATCA_I2C_IFACE, 
        .devtype = ATECC608A, 
        .atcai2c.bus = 0,
        .atcai2c.address = 0xC0, 
        .atcai2c.baud = 100000, 
        .wake_delay = 1500, 
        .rx_retries = 20
    };
    atcab_init(&cfg);

    // 3. Setup UDP Socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    int broadcast_enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DEST_PORT);
    inet_pton(AF_INET, DEST_IP, &dest_addr.sin_addr);
    
    sleep(5);

    while (1) {
        int16_t temperature = 0;
        int16_t humidity = 0;

        // 1. Read DHT11 Sensor
        // 1. Read DHT11 Sensor (Keep it silent)
        esp_err_t sensor_ret = dht_read_data(DHT_TYPE_DHT11, DHT_GPIO, &humidity, &temperature);

        if (sensor_ret == ESP_OK) {
            // STEP A: Prepare the dynamic payload
            char payload[100];
            float temp_c = temperature / 10.0;
            float hum_rel = humidity / 10.0;
            float temp_f = (temp_c * 1.8) + 32; // Celsius to Fahrenheit formula

            snprintf(payload, sizeof(payload), 
                     "Temperature:%.1fC,%.1fF | Humidity:%.1f%%", 
                         temp_c, temp_f, hum_rel);
            int p_len = strlen(payload);
            unsigned char ciphertext[64];
            unsigned char tag[16];
            // Start Latency Timer
            uint64_t start = esp_timer_get_time();

            // STEP A: Generate ONE random source (32 bytes)
            esp_fill_random(shared_iv, 32);

            // STEP B: Derive the Session Key
            if (derive_session_key() == ATCA_SUCCESS) {

                // STEP C: Encrypt
                mbedtls_gcm_context gcm;
                mbedtls_gcm_init(&gcm);
                mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, p_len, shared_iv, 12, NULL, 0, 
                                          (unsigned char*)payload, ciphertext, 16, tag);

                // STEP D: Build Packet [32-byte IV] + [16-byte TAG] + [Ciphertext]
                int packet_len = 32 + 16 + p_len;
                unsigned char udp_packet[packet_len];
                memcpy(udp_packet, shared_iv, 32);
                memcpy(udp_packet + 32, tag, 16);
                memcpy(udp_packet + 48, ciphertext, p_len);

                sendto(sock, udp_packet, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            
                uint64_t end = esp_timer_get_time();
                // --- DIAGNOSTIC PRINTS ---
                printf("\n==================================================\n");
                printf("\n[MODE] : AES-128-GCM (Authenticated)\n");

                printf("\nSECURE DATA TRANSMITTED SUCCESSFULLY\n");

                printf("\nSensor Data : %s\n", payload); 
            
                printf("\n[IV] : ");
                for(int i=0; i<32; i++) printf("%02X", shared_iv[i]);

                printf("\n[TAG] : ");
                for(int i=0; i<16; i++) printf("%02X", tag[i]);

                printf("\nEncrypted Data : "); 
                for(int i=0; i<p_len; i++) printf("%02X", ciphertext[i]);
            
                printf("\n[TIME] : Latency %llu ms", (end - start) / 1000);
                printf("\n");
                printf("\n==================================================\n");
                printf("\n");
                mbedtls_gcm_free(&gcm);
            } else {
                printf("Hardware Derivation Failed!\n");
            }
        } else {
        printf("Sensor Read Failed (0x%X). Skipping this round.\n", sensor_ret);
        }

        sleep(10); 
    }
}