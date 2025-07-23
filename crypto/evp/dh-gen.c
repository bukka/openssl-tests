#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Simple ByteString structure for demonstration */
typedef struct {
    unsigned char* data;
    size_t length;
} ByteString;

/* Error handling macro */
#define ERROR_MSG(msg, ...) fprintf(stderr, "Error: " msg "\n", ##__VA_ARGS__)

/* Initialize ByteString */
void bytestring_init(ByteString* bs, size_t len) {
    bs->length = len;
    bs->data = (unsigned char*)malloc(len);
    memset(bs->data, 0, len);
}

/* Free ByteString */
void bytestring_free(ByteString* bs) {
    if (bs->data) {
        free(bs->data);
        bs->data = NULL;
    }
    bs->length = 0;
}

/* Count the number of bits (similar to SoftHSM's bits() method) */
size_t bytestring_bits(const ByteString* bs) {
    if (bs->length == 0) return 0;
    
    size_t totalBits = bs->length * 8;
    
    /* Find the most significant bit */
    for (size_t i = 0; i < bs->length; i++) {
        if (bs->data[i] != 0) {
            /* Count leading zeros in the first non-zero byte */
            unsigned char byte = bs->data[i];
            int leadingZeros = 0;
            for (int bit = 7; bit >= 0; bit--) {
                if (byte & (1 << bit)) break;
                leadingZeros++;
            }
            return totalBits - (i * 8) - leadingZeros;
        }
    }
    return 0; /* All zeros */
}

/* Print hex dump */
void bytestring_print_hex(const ByteString* bs, const char* label) {
    printf("%s (%zu bytes, %zu bits): ", label, bs->length, bytestring_bits(bs));
    for (size_t i = 0; i < bs->length && i < 32; i++) {
        printf("%02x", bs->data[i]);
    }
    if (bs->length > 32) printf("...");
    printf("\n");
}

/* Convert BIGNUM to ByteString (similar to OSSL::bn2ByteString) */
int bn2ByteString(const BIGNUM* bn, ByteString* result) {
    if (!bn) return 0;
    
    int len = BN_num_bytes(bn);
    bytestring_init(result, len);
    BN_bn2bin(bn, result->data);
    return 1;
}

/* Convert ByteString to BIGNUM (similar to OSSL::byteString2bn) */
BIGNUM* byteString2bn(const ByteString* bs) {
    if (bs->length == 0) return NULL;
    return BN_bin2bn(bs->data, bs->length, NULL);
}

int generate_dh_keypair_with_x_length(EVP_PKEY** dh_keypair, unsigned int x_bit_length) {
    /* Use well-known 1024-bit DH parameters */
    const char* p_hex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
                        "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
                        "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
                        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
                        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
                        "DF1FB2BC2E4A4371";
    
    const char* g_hex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
                        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
                        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
                        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
                        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
                        "855E6EEB22B3B2E5";

    BIGNUM* bn_p = NULL;
    BIGNUM* bn_g = NULL;
    
    if (!BN_hex2bn(&bn_p, p_hex) || !BN_hex2bn(&bn_g, g_hex)) {
        ERROR_MSG("Failed to create BIGNUM from hex strings");
        BN_free(bn_p);
        BN_free(bn_g);
        return 0;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!ctx) {
        ERROR_MSG("Failed to create EVP_PKEY_CTX");
        BN_free(bn_p);
        BN_free(bn_g);
        return 0;
    }

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        ERROR_MSG("Failed to create OSSL_PARAM_BLD");
        BN_free(bn_p);
        BN_free(bn_g);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Set DH parameters */
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g);
    
    /* THIS IS THE KEY PART: Set private key length */
    if (x_bit_length > 0) {
        printf("Setting DH private key length to: %u bits\n", x_bit_length);
        OSSL_PARAM_BLD_push_uint(bld, OSSL_PKEY_PARAM_DH_PRIV_LEN, x_bit_length);
    }

    OSSL_PARAM* params_built = OSSL_PARAM_BLD_to_param(bld);
    if (!params_built) {
        ERROR_MSG("Failed to build OSSL_PARAM");
        BN_free(bn_p);
        BN_free(bn_g);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Create EVP_PKEY from parameters */
    EVP_PKEY* dh = NULL;
    if (EVP_PKEY_fromdata_init(ctx) <= 0 || 
        EVP_PKEY_fromdata(ctx, &dh, EVP_PKEY_KEYPAIR, params_built) <= 0) {
        ERROR_MSG("EVP_PKEY_fromdata failed");
        BN_free(bn_p);
        BN_free(bn_g);
        OSSL_PARAM_free(params_built);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Create new context for key generation */
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new(dh, NULL);
    if (!ctx) {
        ERROR_MSG("Failed to create new EVP_PKEY_CTX");
        BN_free(bn_p);
        BN_free(bn_g);
        OSSL_PARAM_free(params_built);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_free(dh);
        return 0;
    }

    /* Generate the key pair */
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &dh) <= 0) {
        ERROR_MSG("DH key generation failed");
        BN_free(bn_p);
        BN_free(bn_g);
        OSSL_PARAM_free(params_built);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dh);
        return 0;
    }

    /* Clean up intermediate resources */
    BN_free(bn_p);
    BN_free(bn_g);
    OSSL_PARAM_free(params_built);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);

    *dh_keypair = dh;
    return 1;
}

void debug_private_key_length(EVP_PKEY* dh_key) {
    BIGNUM* bn_priv_key = NULL;
    
    printf("\n=== Private Key Length Debug ===\n");
    
    /* Extract private key using the same method as SoftHSM */
    if (EVP_PKEY_get_bn_param(dh_key, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv_key)) {
        /* Convert to ByteString like SoftHSM does */
        ByteString x_bytes;
        if (bn2ByteString(bn_priv_key, &x_bytes)) {
            printf("Private key (X) extracted:\n");
            bytestring_print_hex(&x_bytes, "X");
            
            printf("BN_num_bits(bn_priv_key): %d\n", BN_num_bits(bn_priv_key));
            printf("ByteString.bits(): %zu (this is what SoftHSM reports)\n", bytestring_bits(&x_bytes));
            
            bytestring_free(&x_bytes);
        }
        
        /* Also try to get the DH_PRIV_LEN parameter to see what OpenSSL thinks */
        size_t priv_len = 0;
        if (EVP_PKEY_get_size_t_param(dh_key, OSSL_PKEY_PARAM_DH_PRIV_LEN, &priv_len)) {
            printf("OSSL_PKEY_PARAM_DH_PRIV_LEN: %zu bits\n", priv_len);
        } else {
            printf("OSSL_PKEY_PARAM_DH_PRIV_LEN: not available\n");
        }
        
        BN_free(bn_priv_key);
    } else {
        printf("Failed to extract private key!\n");
        unsigned long err = ERR_get_error();
        if (err) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            printf("OpenSSL error: %s\n", err_buf);
        }
    }
    
    printf("================================\n\n");
}

void test_softhsm_scenario(void) {
    printf("=== SoftHSM Test Scenario Reproduction ===\n");
    printf("This mimics the failing test: p->setXBitLength(128)\n");
    printf("Expected: priv->getX().bits() == 128\n\n");
    
    EVP_PKEY* dh_keypair = NULL;
    
    if (!generate_dh_keypair_with_x_length(&dh_keypair, 128)) {
        ERROR_MSG("Failed to generate DH key pair with X length 128");
        return;
    }
    
    debug_private_key_length(dh_keypair);
    
    /* Extract and check like SoftHSM test does */
    BIGNUM* bn_priv_key = NULL;
    if (EVP_PKEY_get_bn_param(dh_keypair, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv_key)) {
        ByteString x_bytes;
        if (bn2ByteString(bn_priv_key, &x_bytes)) {
            size_t actual_bits = bytestring_bits(&x_bytes);
            printf("TEST RESULT:\n");
            printf("Expected X bits: 128\n");
            printf("Actual X bits:   %zu\n", actual_bits);
            printf("Test %s\n", (actual_bits == 128) ? "PASSED" : "FAILED");
            printf("\n");
            
            bytestring_free(&x_bytes);
        }
        BN_free(bn_priv_key);
    }
    
    EVP_PKEY_free(dh_keypair);
}

int main(void) {
    printf("DH Private Key Length Debugging (Pure C)\n");
    printf("========================================\n\n");

    /* Initialize OpenSSL */
    if (!RAND_poll()) {
        ERROR_MSG("Failed to seed random number generator");
        return 1;
    }

    /* First, reproduce the exact SoftHSM test scenario */
    test_softhsm_scenario();

    /* Test different private key lengths */
    unsigned int test_lengths[] = {128, 160, 224, 256};
    int num_tests = sizeof(test_lengths) / sizeof(test_lengths[0]);
    
    for (int i = 0; i < num_tests; i++) {
        unsigned int x_bit_length = test_lengths[i];
        
        printf("Testing with X bit length: %u\n", x_bit_length);
        printf("========================================\n");
        
        EVP_PKEY* dh_keypair = NULL;
        
        if (!generate_dh_keypair_with_x_length(&dh_keypair, x_bit_length)) {
            ERROR_MSG("Failed to generate DH key pair with X length %u", x_bit_length);
            continue;
        }
        
        debug_private_key_length(dh_keypair);
        
        EVP_PKEY_free(dh_keypair);
    }
    
    /* Also test without setting private key length (default behavior) */
    printf("Testing with default private key length (no OSSL_PKEY_PARAM_DH_PRIV_LEN set)\n");
    printf("=========================================================================\n");
    
    EVP_PKEY* dh_keypair = NULL;
    if (generate_dh_keypair_with_x_length(&dh_keypair, 0)) {  /* 0 means don't set the parameter */
        debug_private_key_length(dh_keypair);
        EVP_PKEY_free(dh_keypair);
    }
    
    printf("Done!\n");
    return 0;
}
