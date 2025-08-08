#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdio>

// Mock SoftHSM ByteString class - exact implementation from SoftHSM
class ByteString {
private:
    std::vector<unsigned char> byteString;

public:
    // Constructors (simplified for debugging)
    ByteString() {}
    
    ByteString(const unsigned char* bytes, const size_t bytesLen) {
        byteString.resize(bytesLen);
        if (bytesLen > 0)
            memcpy(&byteString[0], bytes, bytesLen);
    }
    
    ByteString(const ByteString& in) {
        this->byteString = in.byteString;
    }
    
    // Assignment
    ByteString& operator=(const ByteString& in) {
        this->byteString = in.byteString;
        return *this;
    }
    
    // Array operator
    unsigned char& operator[](size_t pos) {
        return byteString[pos];
    }
    
    // Return the byte string data (simplified sentinel logic)
    unsigned char* byte_str() {
        if (byteString.size() != 0) {
            return &byteString[0];
        } else {
            static unsigned char sentinel[1];
            return sentinel;
        }
    }
    
    // Return the const byte string
    const unsigned char* const_byte_str() const {
        if (byteString.size() != 0) {
            return (const unsigned char*) &byteString[0];
        } else {
            static unsigned char sentinel[1];
            return sentinel;
        }
    }
    
    // The size of the byte string in bits - EXACT SoftHSM implementation
    size_t bits() const {
        size_t bits = byteString.size() * 8;

        if (bits == 0) return 0;

        for (size_t i = 0; i < byteString.size(); i++) {
            unsigned char byte = byteString[i];

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
    
    // The size of the byte string in bytes
    size_t size() const {
        return byteString.size();
    }
    
    void resize(const size_t newSize) {
        byteString.resize(newSize);
    }
    
    // Hex representation for debugging
    std::string hex_str() const {
        std::string rv;
        char hex[3];

        for (size_t i = 0; i < byteString.size(); i++) {
            snprintf(hex, sizeof(hex), "%02X", byteString[i]);
            rv += hex;
        }

        return rv;
    }
    
    void print_debug(const char* label) const {
        printf("%s (%zu bytes, %zu bits): %s\n", 
               label, size(), bits(), 
               hex_str().substr(0, 64).c_str());
        if (hex_str().length() > 64) printf("  (truncated...)\n");
    }
};

// Mock OSSL namespace - exact implementation from SoftHSM
namespace OSSL {
    // Convert an OpenSSL BIGNUM to a ByteString - EXACT SoftHSM implementation
    ByteString bn2ByteString(const BIGNUM* bn) {
        ByteString rv;

        if (bn != NULL) {
            rv.resize(BN_num_bytes(bn));
            BN_bn2bin(bn, &rv[0]);
        }

        return rv;
    }

    // Convert a ByteString to an OpenSSL BIGNUM - EXACT SoftHSM implementation  
    BIGNUM* byteString2bn(const ByteString& byteString) {
        if (byteString.size() == 0) return NULL;

        return BN_bin2bn(byteString.const_byte_str(), byteString.size(), NULL);
    }
}

// Mock DHParameters class
class DHParameters {
private:
    ByteString p;
    ByteString g;
    unsigned int xBitLength;
    
public:
    DHParameters() : xBitLength(0) {}
    
    void setP(const ByteString& inP) { p = inP; }
    void setG(const ByteString& inG) { g = inG; }
    void setXBitLength(unsigned int bitLen) { 
        printf("DEBUG: DHParameters::setXBitLength(%u) called\n", bitLen);
        xBitLength = bitLen; 
    }
    
    const ByteString& getP() const { return p; }
    const ByteString& getG() const { return g; }
    unsigned int getXBitLength() const { return xBitLength; }
    
    void print_debug(const char* label) const {
        printf("%s:\n", label);
        p.print_debug("  P");
        g.print_debug("  G");
        printf("  XBitLength: %u\n", xBitLength);
    }
};

// Mock DHPrivateKey base class
class DHPrivateKey {
protected:
    ByteString p; // DH prime
    ByteString g; // DH generator  
    ByteString x; // Private key
    
public:
    virtual ~DHPrivateKey() {}
    
    // Setters
    virtual void setP(const ByteString& inP) { p = inP; }
    virtual void setG(const ByteString& inG) { g = inG; }
    virtual void setX(const ByteString& inX) { 
        printf("DEBUG: DHPrivateKey::setX() called\n");
        printf("DEBUG: Input ByteString: %zu bytes, %zu bits\n", inX.size(), inX.bits());
        x = inX; 
        printf("DEBUG: Stored ByteString: %zu bytes, %zu bits\n", x.size(), x.bits());
    }
    
    // Getters
    virtual const ByteString& getP() const { return p; }
    virtual const ByteString& getG() const { return g; }
    virtual const ByteString& getX() const { return x; }
    
    virtual size_t getBitLength() const {
        return p.bits();
    }
};

// Mock OSSLDHPrivateKey - simplified version focusing on the key parts
class OSSLDHPrivateKey : public DHPrivateKey {
private:
    EVP_PKEY* dh;
    
public:
    OSSLDHPrivateKey() : dh(NULL) {}
    
    OSSLDHPrivateKey(const EVP_PKEY* inDH) : dh(NULL) {
        setFromOSSL(inDH);
    }
    
    virtual ~OSSLDHPrivateKey() {
        if (dh) {
            EVP_PKEY_free(dh);
            dh = NULL;
        }
    }
    
    // EXACT implementation from SoftHSM OSSLDHPrivateKey.cpp
    void setFromOSSL(const EVP_PKEY* inDH) {
        printf("\n=== OSSLDHPrivateKey::setFromOSSL() DEBUG ===\n");
        
        BIGNUM *bn_p = NULL, *bn_g = NULL, *bn_priv_key = NULL;
        
        // Extract parameters - EXACT SoftHSM code
        int p_result = EVP_PKEY_get_bn_param(inDH, OSSL_PKEY_PARAM_FFC_P, &bn_p);
        int g_result = EVP_PKEY_get_bn_param(inDH, OSSL_PKEY_PARAM_FFC_G, &bn_g);
        int priv_result = EVP_PKEY_get_bn_param(inDH, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv_key);
        
        printf("Parameter extraction results:\n");
        printf("  EVP_PKEY_get_bn_param(OSSL_PKEY_PARAM_FFC_P): %s\n", p_result ? "SUCCESS" : "FAILED");
        printf("  EVP_PKEY_get_bn_param(OSSL_PKEY_PARAM_FFC_G): %s\n", g_result ? "SUCCESS" : "FAILED");
        printf("  EVP_PKEY_get_bn_param(OSSL_PKEY_PARAM_PRIV_KEY): %s\n", priv_result ? "SUCCESS" : "FAILED");

        if (bn_p) {
            printf("  bn_p bits: %d, bytes: %d\n", BN_num_bits(bn_p), BN_num_bytes(bn_p));
            ByteString inP = OSSL::bn2ByteString(bn_p);
            printf("  After OSSL::bn2ByteString(bn_p):\n");
            inP.print_debug("    inP");
            setP(inP);
            BN_free(bn_p);
        }
        
        if (bn_g) {
            printf("  bn_g bits: %d, bytes: %d\n", BN_num_bits(bn_g), BN_num_bytes(bn_g));
            ByteString inG = OSSL::bn2ByteString(bn_g);
            printf("  After OSSL::bn2ByteString(bn_g):\n");
            inG.print_debug("    inG");
            setG(inG);
            BN_free(bn_g);
        }
        
        if (bn_priv_key) {
            printf("  bn_priv_key bits: %d, bytes: %d\n", BN_num_bits(bn_priv_key), BN_num_bytes(bn_priv_key));
            ByteString inX = OSSL::bn2ByteString(bn_priv_key);
            printf("  After OSSL::bn2ByteString(bn_priv_key):\n");
            inX.print_debug("    inX");
            printf("  About to call setX(inX)...\n");
            setX(inX);
            printf("  setX(inX) completed.\n");
            BN_free(bn_priv_key);
        }
        
        printf("=== setFromOSSL() Complete ===\n");
        printf("Final stored values:\n");
        getP().print_debug("  Stored P");
        getG().print_debug("  Stored G"); 
        getX().print_debug("  Stored X");
        printf("getX().bits() = %zu (this is what the test checks)\n", getX().bits());
        printf("=========================================\n\n");
    }
    
    // Override setters to add debug output
    virtual void setX(const ByteString& inX) override {
        printf("    OSSLDHPrivateKey::setX() called\n");
        DHPrivateKey::setX(inX);
    }
    
    virtual void setP(const ByteString& inP) override {
        printf("    OSSLDHPrivateKey::setP() called\n");
        DHPrivateKey::setP(inP);
    }
    
    virtual void setG(const ByteString& inG) override {
        printf("    OSSLDHPrivateKey::setG() called\n");
        DHPrivateKey::setG(inG);
    }
};

// Mock KeyPair class
class OSSLDHKeyPair {
private:
    OSSLDHPrivateKey* privateKey;
    
public:
    OSSLDHKeyPair() {
        privateKey = new OSSLDHPrivateKey();
    }
    
    ~OSSLDHKeyPair() {
        delete privateKey;
    }
    
    DHPrivateKey* getPrivateKey() {
        return (DHPrivateKey*)privateKey;
    }
};

// Simulate the exact SoftHSM generateParameters() function
DHParameters* simulate_generateParameters(size_t bitLen) {
    printf("=== Simulating OSSLDH::generateParameters(%zu) ===\n", bitLen);
    
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    printf("Using OpenSSL 3.0+ code path for parameter generation\n");
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!ctx) {
        printf("Failed to create EVP_PKEY_CTX\n");
        return NULL;
    }

    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        printf("EVP_PKEY_paramgen_init failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, bitLen) <= 0) {
        printf("EVP_PKEY_CTX_set_dh_paramgen_prime_len failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, 2) <= 0) {
        printf("EVP_PKEY_CTX_set_dh_paramgen_generator failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY* dh_params = NULL;
    if (EVP_PKEY_paramgen(ctx, &dh_params) <= 0) {
        printf("Failed to generate DH parameters\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    BIGNUM* bn_p = NULL;
    BIGNUM* bn_g = NULL;

    EVP_PKEY_get_bn_param(dh_params, OSSL_PKEY_PARAM_FFC_P, &bn_p);
    EVP_PKEY_get_bn_param(dh_params, OSSL_PKEY_PARAM_FFC_G, &bn_g);
    
    printf("Generated parameters:\n");
    printf("  P bits: %d\n", BN_num_bits(bn_p));
    printf("  G bits: %d\n", BN_num_bits(bn_g));
    
    // Store the DH parameters exactly like SoftHSM
    DHParameters* params = new DHParameters();
    ByteString p = OSSL::bn2ByteString(bn_p); 
    ByteString g = OSSL::bn2ByteString(bn_g);
    
    params->setP(p);
    params->setG(g);
    
    EVP_PKEY_free(dh_params);
    BN_free(bn_p);
    BN_free(bn_g);
    
    printf("Parameter generation complete\n");
    params->print_debug("Generated Parameters");
    printf("===============================================\n\n");
    
    return params;
#else
    printf("ERROR: This test requires OpenSSL 3.0+ to match SoftHSM behavior\n");
    return NULL;
#endif
}

// Simulate the exact SoftHSM generateKeyPair() function 
EVP_PKEY* simulate_generateKeyPair(DHParameters* parameters) {
    printf("=== Simulating OSSLDH::generateKeyPair() ===\n");
    parameters->print_debug("Input Parameters");

    BIGNUM* bn_p = OSSL::byteString2bn(parameters->getP());
    BIGNUM* bn_g = OSSL::byteString2bn(parameters->getG());
    
    if (!bn_p || !bn_g) {
        printf("Failed to convert parameters to BIGNUM\n");
        return NULL;
    }
    
    printf("Converted parameters to BIGNUM:\n");
    printf("  bn_p bits: %d\n", BN_num_bits(bn_p));
    printf("  bn_g bits: %d\n", BN_num_bits(bn_g));

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    printf("Using OpenSSL 3.0+ code path for key generation\n");
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!ctx) {
        printf("Failed to create EVP_PKEY_CTX\n");
        BN_free(bn_p);
        BN_free(bn_g);
        return NULL;
    }

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        printf("Failed to create OSSL_PARAM_BLD\n");
        BN_free(bn_p);
        BN_free(bn_g);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g);
    
    if (parameters->getXBitLength() > 0) {
        printf("Setting OSSL_PKEY_PARAM_DH_PRIV_LEN to %u\n", parameters->getXBitLength());
        OSSL_PARAM_BLD_push_uint(bld, OSSL_PKEY_PARAM_DH_PRIV_LEN, parameters->getXBitLength());
    } else {
        printf("No private key length specified\n");
    }

    OSSL_PARAM* params_built = OSSL_PARAM_BLD_to_param(bld);
    if (!params_built) {
        printf("Failed to build OSSL_PARAM\n");
        BN_free(bn_p);
        BN_free(bn_g);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY* dh = NULL;
    if (EVP_PKEY_fromdata_init(ctx) <= 0 || 
        EVP_PKEY_fromdata(ctx, &dh, EVP_PKEY_KEYPAIR, params_built) <= 0) {
        printf("EVP_PKEY_fromdata failed\n");
        BN_free(bn_p);
        BN_free(bn_g);
        OSSL_PARAM_free(params_built);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dh);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new(dh, NULL);
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &dh) <= 0) {
        printf("DH key generation failed\n");
        BN_free(bn_p);
        BN_free(bn_g);
        OSSL_PARAM_free(params_built);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dh);
        return NULL;
    }

    BN_free(bn_p);
    BN_free(bn_g);
    OSSL_PARAM_free(params_built);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);

    printf("Key generation successful\n");
    printf("======================================\n\n");
    return dh;
#else
    printf("ERROR: This test requires OpenSSL 3.0+ to match SoftHSM behavior\n");
    return NULL;
#endif
}

// Test exactly like SoftHSM DHTests::testKeyGeneration()
void test_exact_softhsm_flow() {
    printf("\n=== EXACT SoftHSM DHTests::testKeyGeneration() Flow ===\n");
    
    // Step 1: Generate parameters like SoftHSM test (bitLen = 1024)
    size_t bitLen = 1024;
    printf("Step 1: Generating DH parameters with %zu bits\n", bitLen);
    DHParameters* p = simulate_generateParameters(bitLen);
    if (!p) {
        printf("Parameter generation failed\n");
        return;
    }
    
    // Step 2: Generate key-pair like SoftHSM test  
    printf("Step 2: Generating key pair\n");
    EVP_PKEY* dh = simulate_generateKeyPair(p);
    if (!dh) {
        printf("Key generation failed\n");
        delete p;
        return;
    }
    
    // Step 3: Create key objects like SoftHSM test
    printf("Step 3: Creating key objects\n");
    OSSLDHKeyPair* kp = new OSSLDHKeyPair();
    
    printf("Step 4: Calling setFromOSSL() like SoftHSM test\n");
    ((OSSLDHPrivateKey*)kp->getPrivateKey())->setFromOSSL(dh);
    
    DHPrivateKey* priv = kp->getPrivateKey();
    
    // First assertion like SoftHSM test
    printf("\n=== First Test: getBitLength() ===\n");
    printf("Expected: priv->getBitLength() == %zu\n", bitLen);
    printf("Actual:   priv->getBitLength() == %zu\n", priv->getBitLength());
    printf("Test %s\n", (priv->getBitLength() == bitLen) ? "PASSED" : "FAILED");
    
    // Step 5: Set XBitLength like SoftHSM test
    printf("\nStep 5: Setting XBitLength to 128 and regenerating\n");
    p->setXBitLength(128);
    
    // Generate new key pair with fixed private value length
    EVP_PKEY_free(dh);
    dh = simulate_generateKeyPair(p);
    if (!dh) {
        printf("Second key generation failed\n");
        delete kp;
        delete p;
        return;
    }
    
    delete kp; // Clean up old key pair
    kp = new OSSLDHKeyPair();
    ((OSSLDHPrivateKey*)kp->getPrivateKey())->setFromOSSL(dh);
    priv = kp->getPrivateKey();
    
    // Critical test like SoftHSM
    printf("\n=== CRITICAL TEST: priv->getX().bits() ===\n");
    printf("Expected: priv->getX().bits() == 128\n");
    printf("Actual:   priv->getX().bits() == %zu\n", priv->getX().bits());
    printf("Test %s\n", (priv->getX().bits() == 128) ? "PASSED" : "FAILED");
    
    if (priv->getX().bits() != 128) {
        printf("\nDEBUG: Why did the critical test fail?\n");
        printf("This is the exact test that's failing in SoftHSM!\n");
        printf("- Generated DH parameters have P with %zu bits\n", p->getP().bits());
        printf("- Set XBitLength to 128\n");
        printf("- But private key X has %zu bits instead of 128\n", priv->getX().bits());
        
        if (priv->getX().bits() == 1024) {
            printf("ERROR: Private key has 1024 bits - same as prime! Bug confirmed!\n");
        } else if (priv->getX().bits() > 150 && priv->getX().bits() < 170) {
            printf("ERROR: OpenSSL 3.0+ is ignoring OSSL_PKEY_PARAM_DH_PRIV_LEN parameter!\n");
        }
    }
    
    printf("================================================\n");
    
    // Clean up
    delete kp;
    delete p;
    EVP_PKEY_free(dh);
}

int main() {
    printf("SoftHSMv2 Exact Test Flow - Using Generated Parameters\n");
    printf("======================================================\n");
    printf("This reproduces the EXACT SoftHSM DHTests::testKeyGeneration() flow\n");
    printf("using generated DH parameters, not hardcoded RFC parameters.\n\n");

    if (!RAND_poll()) {
        printf("Failed to seed random number generator\n");
        return 1;
    }

    test_exact_softhsm_flow();
    
    printf("\nSUMMARY:\n");
    printf("========\n");
    printf("This test reproduces the exact SoftHSM test failure.\n");
    printf("The critical difference is using GENERATED DH parameters vs hardcoded ones.\n");
    printf("If this still shows ~160 bits instead of 128, then the OpenSSL 3.0+\n");
    printf("provider is definitely ignoring the OSSL_PKEY_PARAM_DH_PRIV_LEN parameter.\n");

    return 0;
}
