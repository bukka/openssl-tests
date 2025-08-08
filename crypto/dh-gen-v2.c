#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Simple ByteString structure */
typedef struct {
    unsigned char* data;
    size_t length;
} ByteString;

#define ERROR_MSG(msg, ...) fprintf(stderr, "Error: " msg "\n", ##__VA_ARGS__)

void bytestring_init(ByteString* bs, size_t len) {
    bs->length = len;
    bs->data = (unsigned char*)malloc(len);
    memset(bs->data, 0, len);
}

void bytestring_free(ByteString* bs) {
    if (bs->data) {
        free(bs->data);
        bs->data = NULL;
    }
    bs->length = 0;
}

/* Exact copy of SoftHSM's ByteString::bits() method */
size_t bytestring_bits(const ByteString* bs) {
    size_t bits = bs->length * 8;

    if (bits == 0) return 0;

    for (size_t i = 0; i < bs->length; i++) {
        unsigned char byte = bs->data[i];

        for (unsigned char mask = 0x80; mask > 0; mask >>= 1) {
            if ((byte & mask) == 0) {
                bits--;
            } else {
                return bits;
            }
        }
    }

    return bits;
}

void bytestring_print_hex(const ByteString* bs, const char* label) {
    printf("%s (%zu bytes, %zu bits): ", label, bs->length, bytestring_bits(bs));
    for (size_t i = 0; i < bs->length && i < 32; i++) {
        printf("%02x", bs->data[i]);
    }
    if (bs->length > 32) printf("...");
    printf("\n");
}

/* Test if OSSL::bn2ByteString might be doing something different */
int ossl_bn2ByteString(const BIGNUM* bn, ByteString* result) {
    if (!bn) return 0;
    
    int len = BN_num_bytes(bn);
    bytestring_init(result, len);
    BN_bn2bin(bn, result->data);
    return 1;
}

/* Simulate potential different ByteString creation methods */
int create_fixed_size_bytestring(const BIGNUM* bn, ByteString* result, size_t fixed_size) {
    if (!bn) return 0;
    
    int bn_bytes = BN_num_bytes(bn);
    
    /* Create ByteString with fixed size (might be what SoftHSM is doing?) */
    bytestring_init(result, fixed_size);
    
    if (bn_bytes <= (int)fixed_size) {
        /* Right-align the BIGNUM data (big-endian) */
        size_t offset = fixed_size - bn_bytes;
        memset(result->data, 0, offset); /* Fill with leading zeros */
        BN_bn2bin(bn, result->data + offset);
    } else {
        /* Truncate if too large */
        BN_bn2bin(bn, result->data);
    }
    
    return 1;
}

/* Test if SoftHSM might be storing the prime instead of private key */
void test_parameter_confusion(EVP_PKEY* dh_key) {
    printf("=== Testing Parameter Confusion Hypothesis ===\n");
    printf("Could SoftHSM be accidentally storing the prime (p) instead of private key (x)?\n\n");
    
    BIGNUM *bn_p = NULL, *bn_g = NULL, *bn_priv_key = NULL, *bn_pub_key = NULL;
    
    /* Extract all parameters */
    EVP_PKEY_get_bn_param(dh_key, OSSL_PKEY_PARAM_FFC_P, &bn_p);
    EVP_PKEY_get_bn_param(dh_key, OSSL_PKEY_PARAM_FFC_G, &bn_g);
    EVP_PKEY_get_bn_param(dh_key, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv_key);
    EVP_PKEY_get_bn_param(dh_key, OSSL_PKEY_PARAM_PUB_KEY, &bn_pub_key);
    
    if (bn_p && bn_g && bn_priv_key && bn_pub_key) {
        ByteString p_bytes, g_bytes, priv_bytes, pub_bytes;
        
        ossl_bn2ByteString(bn_p, &p_bytes);
        ossl_bn2ByteString(bn_g, &g_bytes);
        ossl_bn2ByteString(bn_priv_key, &priv_bytes);
        ossl_bn2ByteString(bn_pub_key, &pub_bytes);
        
        printf("All DH parameters converted to ByteString:\n");
        bytestring_print_hex(&p_bytes, "Prime (p)");
        bytestring_print_hex(&g_bytes, "Generator (g)");
        bytestring_print_hex(&priv_bytes, "Private key (x)");
        bytestring_print_hex(&pub_bytes, "Public key (y)");
        
        printf("\nChecking if any parameter has 1024 bits:\n");
        printf("  Prime (p) bits: %zu %s\n", bytestring_bits(&p_bytes), 
               (bytestring_bits(&p_bytes) == 1024) ? "← MATCHES!" : "");
        printf("  Generator (g) bits: %zu %s\n", bytestring_bits(&g_bytes),
               (bytestring_bits(&g_bytes) == 1024) ? "← MATCHES!" : "");
        printf("  Private key (x) bits: %zu %s\n", bytestring_bits(&priv_bytes),
               (bytestring_bits(&priv_bytes) == 1024) ? "← MATCHES!" : "");
        printf("  Public key (y) bits: %zu %s\n", bytestring_bits(&pub_bytes),
               (bytestring_bits(&pub_bytes) == 1024) ? "← MATCHES!" : "");
        
        bytestring_free(&p_bytes);
        bytestring_free(&g_bytes);
        bytestring_free(&priv_bytes);
        bytestring_free(&pub_bytes);
    }
    
    /* Clean up */
    if (bn_p) BN_free(bn_p);
    if (bn_g) BN_free(bn_g);
    if (bn_priv_key) BN_free(bn_priv_key);
    if (bn_pub_key) BN_free(bn_pub_key);
    
    printf("===============================================\n\n");
}

/* Test different ByteString creation scenarios */
void test_bytestring_scenarios(EVP_PKEY* dh_key) {
    printf("=== Testing ByteString Creation Scenarios ===\n");
    
    BIGNUM* bn_priv_key = NULL;
    if (!EVP_PKEY_get_bn_param(dh_key, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv_key)) {
        printf("Failed to get private key\n");
        return;
    }
    
    printf("Original BIGNUM: %d bits\n\n", BN_num_bits(bn_priv_key));
    
    /* Scenario 1: Normal OSSL::bn2ByteString */
    ByteString normal;
    ossl_bn2ByteString(bn_priv_key, &normal);
    bytestring_print_hex(&normal, "Scenario 1 - Normal");
    
    /* Scenario 2: Fixed 128-byte (1024-bit) ByteString */
    ByteString fixed_1024;
    create_fixed_size_bytestring(bn_priv_key, &fixed_1024, 128); /* 128 bytes = 1024 bits */
    bytestring_print_hex(&fixed_1024, "Scenario 2 - 1024-bit fixed");
    
    /* Scenario 3: Fixed 64-byte (512-bit) ByteString */
    ByteString fixed_512;
    create_fixed_size_bytestring(bn_priv_key, &fixed_512, 64); /* 64 bytes = 512 bits */
    bytestring_print_hex(&fixed_512, "Scenario 3 - 512-bit fixed");
    
    /* Scenario 4: Fixed 20-byte but with leading zeros */
    ByteString padded_20;
    create_fixed_size_bytestring(bn_priv_key, &padded_20, 20);
    bytestring_print_hex(&padded_20, "Scenario 4 - 20-byte padded");
    
    printf("\nAnalysis:\n");
    printf("- If SoftHSM reports 1024 bits, it might be using Scenario 2\n");
    printf("- This could happen if there's a bug in the ByteString creation\n");
    printf("- Or if the wrong parameter is being stored\n");
    
    /* Clean up */
    bytestring_free(&normal);
    bytestring_free(&fixed_1024);
    bytestring_free(&fixed_512);
    bytestring_free(&padded_20);
    BN_free(bn_priv_key);
    
    printf("==============================================\n\n");
}

/* Simulate potential SoftHSM bugs */
void test_potential_softhsm_bugs(EVP_PKEY* dh_key) {
    printf("=== Testing Potential SoftHSM Bugs ===\n");
    
    /* Bug hypothesis 1: Wrong parameter extraction */
    printf("Bug Test 1: What if SoftHSM extracts wrong parameter?\n");
    BIGNUM* bn_p = NULL;
    if (EVP_PKEY_get_bn_param(dh_key, OSSL_PKEY_PARAM_FFC_P, &bn_p)) {
        ByteString wrong_param;
        ossl_bn2ByteString(bn_p, &wrong_param);
        bytestring_print_hex(&wrong_param, "If storing prime as private key");
        bytestring_free(&wrong_param);
        BN_free(bn_p);
    }
    
    /* Bug hypothesis 2: Memory corruption or uninitialized data */
    printf("\nBug Test 2: Uninitialized 1024-bit ByteString\n");
    ByteString uninitialized;
    bytestring_init(&uninitialized, 128); /* 1024 bits */
    /* Fill with pattern that would give 1024 bits */
    memset(uninitialized.data, 0xFF, 128);
    bytestring_print_hex(&uninitialized, "1024-bit all-ones pattern");
    bytestring_free(&uninitialized);
    
    /* Bug hypothesis 3: Bit counting error */
    printf("\nBug Test 3: What if bits() method is broken?\n");
    ByteString test_bits;
    bytestring_init(&test_bits, 20);
    /* Create a pattern that should give ~160 bits */
    test_bits.data[0] = 0x80; /* MSB set */
    for (int i = 1; i < 20; i++) {
        test_bits.data[i] = 0x00;
    }
    bytestring_print_hex(&test_bits, "Pattern that should give 1 bit");
    
    /* Now fill it to actually use all bits */
    memset(test_bits.data, 0xFF, 20);
    bytestring_print_hex(&test_bits, "Pattern that should give 160 bits");
    bytestring_free(&test_bits);
    
    printf("===================================\n\n");
}

int main(void) {
    printf("ByteString Implementation Investigation\n");
    printf("======================================\n\n");
    printf("You're absolutely right! The issue is likely in data handling, not OpenSSL.\n");
    printf("Let's investigate how the ByteString could report 1024 bits for a 160-bit key.\n\n");

    if (!RAND_poll()) {
        ERROR_MSG("Failed to seed random number generator");
        return 1;
    }

    /* Generate a test key using our known method */
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
    BN_hex2bn(&bn_p, p_hex);
    BN_hex2bn(&bn_g, g_hex);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g);
    OSSL_PARAM_BLD_push_uint(bld, OSSL_PKEY_PARAM_DH_PRIV_LEN, 128);
    
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY* dh = NULL;
    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY_fromdata(ctx, &dh, EVP_PKEY_KEYPAIR, params);
    
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new(dh, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &dh);
    
    /* Now run our tests */
    test_parameter_confusion(dh);
    test_bytestring_scenarios(dh);
    test_potential_softhsm_bugs(dh);
    
    printf("CONCLUSION:\n");
    printf("===========\n");
    printf("The most likely explanations for SoftHSM reporting 1024 bits:\n\n");
    printf("1. **Wrong Parameter**: SoftHSM is storing the prime (p) instead of private key (x)\n");
    printf("2. **Fixed-size ByteString**: SoftHSM creates a 1024-bit ByteString and fills it\n");
    printf("3. **Memory corruption**: Uninitialized or corrupted data\n");
    printf("4. **Different code path**: SoftHSM is using a completely different method\n\n");
    printf("To debug further, add printf statements in SoftHSM's:\n");
    printf("- OSSLDHPrivateKey::setFromOSSL()\n");
    printf("- DHPrivateKey::setX() \n");
    printf("- ByteString constructor/assignment\n");
    
    /* Clean up */
    EVP_PKEY_free(dh);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn_p);
    BN_free(bn_g);
    
    return 0;
}
