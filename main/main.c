/* mbedtls encryption/decryption examples

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_spi_flash.h"

#include "crypto/includes.h"

#include "crypto/common.h"
#include "crypto/aes.h"
#include "crypto/aes_wrap.h"
#include "mbedtls/aes.h"

// only CBC requires that input length shall be multiple of 16
#define INPUT_LENGTH 16

mbedtls_aes_context aes;

// key length 32 bytes for 256 bit encrypting, it can be 16 or 24 bytes for 128 and 192 bits encrypting mode
unsigned char key[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

unsigned char input[INPUT_LENGTH] = {0};

static void cfb8()
{
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    unsigned char iv[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char iv1[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char encrypt_output[INPUT_LENGTH] = {0};
    unsigned char decrypt_output[INPUT_LENGTH] = {0};
    mbedtls_aes_crypt_cfb8(&aes, MBEDTLS_AES_ENCRYPT, INPUT_LENGTH, iv, input, encrypt_output);
    mbedtls_aes_crypt_cfb8(&aes, MBEDTLS_AES_DECRYPT, INPUT_LENGTH, iv1, encrypt_output, decrypt_output);
    ESP_LOG_BUFFER_HEX("cfb8", encrypt_output, INPUT_LENGTH);
    ESP_LOG_BUFFER_HEX("cfb8", decrypt_output, INPUT_LENGTH);
    ESP_LOGI("cfb8", "%s", decrypt_output);
#endif
}

static void ctr()
{
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    size_t nc_off = 0;
    size_t nc_off1 = 0;
    unsigned char nonce_counter[16] = {0};
    unsigned char stream_block[16] = {0};
    unsigned char nonce_counter1[16] = {0};
    unsigned char stream_block1[16] = {0};
    unsigned char encrypt_output[INPUT_LENGTH] = {0};
    unsigned char decrypt_output[INPUT_LENGTH] = {0};
    size_t iv_offset = 0;
    size_t iv_offset1 = 0;
    mbedtls_aes_crypt_ctr(&aes, INPUT_LENGTH, &nc_off, nonce_counter, stream_block, input, encrypt_output);
    mbedtls_aes_crypt_ctr(&aes, INPUT_LENGTH, &nc_off1, nonce_counter1, stream_block1, encrypt_output, decrypt_output);
    ESP_LOG_BUFFER_HEX("ctr", encrypt_output, INPUT_LENGTH);
    ESP_LOG_BUFFER_HEX("ctr", decrypt_output, INPUT_LENGTH);
    ESP_LOGI("ctr", "%s", decrypt_output);
#endif
}

static void ecb()
{
    unsigned char encrypt_output[INPUT_LENGTH] = {0};
    unsigned char decrypt_output[INPUT_LENGTH] = {0};
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, encrypt_output);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, encrypt_output, decrypt_output);
    ESP_LOG_BUFFER_HEX("ecb", encrypt_output, INPUT_LENGTH);
    ESP_LOG_BUFFER_HEX("ecb", decrypt_output, INPUT_LENGTH);
    ESP_LOGI("ecb", "%s", decrypt_output);
}

static void ofb()
{
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    unsigned char iv[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char iv1[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char encrypt_output[INPUT_LENGTH] = {0};
    unsigned char decrypt_output[INPUT_LENGTH] = {0};
    size_t iv_offset = 0;
    size_t iv_offset1 = 0;
    mbedtls_aes_crypt_ofb(&aes, INPUT_LENGTH, &iv_offset, iv, input, encrypt_output);
    mbedtls_aes_crypt_ofb(&aes, INPUT_LENGTH, &iv_offset1, iv1, encrypt_output, decrypt_output);
    ESP_LOG_BUFFER_HEX("ofb", encrypt_output, INPUT_LENGTH);
    ESP_LOG_BUFFER_HEX("ofb", decrypt_output, INPUT_LENGTH);
    ESP_LOGI("ofb", "%s", decrypt_output);
#endif
}

static void xts()
{
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    unsigned char encrypt_output[INPUT_LENGTH] = {0};
    unsigned char decrypt_output[INPUT_LENGTH] = {0};
    const unsigned char data_unit[16] = {0};
    mbedtls_aes_xts_context ctx_xts;
    mbedtls_aes_xts_init(&ctx_xts);
    mbedtls_aes_xts_setkey_enc( &ctx_xts, key, 256 );
    mbedtls_aes_crypt_xts( &ctx_xts, MBEDTLS_AES_ENCRYPT, INPUT_LENGTH, data_unit, input, encrypt_output );
    mbedtls_aes_crypt_xts( &ctx_xts, MBEDTLS_AES_DECRYPT, INPUT_LENGTH, data_unit, encrypt_output, decrypt_output );
    mbedtls_aes_xts_free( &ctx_xts );
    ESP_LOG_BUFFER_HEX("xts", encrypt_output, INPUT_LENGTH);
    ESP_LOG_BUFFER_HEX("xts", decrypt_output, INPUT_LENGTH);
    ESP_LOGI("xts", "%s", decrypt_output);
#endif
}

/**
 * This function operates on full blocks, that is, the input size must be a multiple of the AES block size of 16 Bytes.
 */
static void cfb128()
{
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    unsigned char iv[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char iv1[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char encrypt_output[INPUT_LENGTH] = {0};
    unsigned char decrypt_output[INPUT_LENGTH] = {0};
    size_t iv_offset = 0;
    size_t iv_offset1 = 0;
    mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, INPUT_LENGTH, &iv_offset, iv, input, encrypt_output);
    mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, INPUT_LENGTH, &iv_offset1, iv1, encrypt_output, decrypt_output);
    ESP_LOG_BUFFER_HEX("cfb128", encrypt_output, INPUT_LENGTH);
    ESP_LOG_BUFFER_HEX("cfb128", decrypt_output, INPUT_LENGTH);
    ESP_LOGI("cfb128", "%s", decrypt_output);
#endif
}

static void cbc()
{
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    unsigned char iv[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char iv1[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char encrypt_output[INPUT_LENGTH] = {0};
    unsigned char decrypt_output[INPUT_LENGTH] = {0};
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, INPUT_LENGTH, iv, input, encrypt_output);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, INPUT_LENGTH, iv1, encrypt_output, decrypt_output);
    ESP_LOG_BUFFER_HEX("cbc", encrypt_output, INPUT_LENGTH);
    ESP_LOG_BUFFER_HEX("cbc", decrypt_output, INPUT_LENGTH);
    ESP_LOGI("cbc", "%s", decrypt_output);
#endif
}

void task(void* p)
{
    sprintf((char*)input, "%s","Hello Testing");
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    ecb();
    cbc();
    cfb8();
    cfb128();
    ofb();
    ctr();
    xts();
    mbedtls_aes_free(&aes);
    vTaskDelete(NULL);
}

void app_main()
{
    xTaskCreate(task, "task", 1024*10, NULL, 5, NULL);
}
