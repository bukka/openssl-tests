#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define TAG_LEN 16
#define KEY_LEN 16
#define IV_LEN 12

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to encrypt plaintext using OCB mode
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    if (!ctx)
        handleErrors();

    // Initialize encryption operation for AES-128-OCB
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ocb(), NULL, NULL, NULL))
        handleErrors();

    // Set IV
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    // Encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag))
        handleErrors();

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Function to decrypt ciphertext using OCB mode
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len, ret;

    if (!ctx)
        handleErrors();

    // Initialize decryption operation for AES-128-OCB
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ocb(), NULL, NULL, NULL))
        handleErrors();

    // Set IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    // Set expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag))
        handleErrors();

    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    // Finalize decryption
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len; // Success
    } else {
        return -1; // Decryption failed
    }
}

int main() {
    // Key and IV
    unsigned char key[KEY_LEN], iv[IV_LEN];

    // Generate a random key and IV
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        handleErrors();
    }

    // Example plaintext
    unsigned char *plaintext = (unsigned char *)"This is the message to encrypt!";
    unsigned char ciphertext[128], decryptedtext[128], tag[TAG_LEN];
    int ciphertext_len, decryptedtext_len;

    printf("Plaintext: %s\n", plaintext);

    // Encrypt the plaintext
    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext, tag);

    printf("Ciphertext is:\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decrypt the ciphertext
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, tag, key, iv, decryptedtext);

    if (decryptedtext_len < 0) {
        printf("Decryption failed\n");
    } else {
        decryptedtext[decryptedtext_len] = '\0';
        printf("Decrypted text: %s\n", decryptedtext);
    }

    return 0;
}