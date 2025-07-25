#include <string>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/cms.h>

CMS_ContentInfo* create_cms(const std::string& message)
{
        BIO* msgBio = BIO_new(BIO_s_mem());
        BIO_write(msgBio, message.c_str(), static_cast<int>(message.size()));

        CMS_ContentInfo* cms = CMS_ContentInfo_new();

        if (!PEM_read_bio_CMS(msgBio, &cms, nullptr, nullptr))
        {
                BIO_vfree(msgBio);
                return nullptr;
        }

        BIO_vfree(msgBio);
        return cms;
}

std::string encrypt_message(const std::string& message, X509* cert)
{
        BIO* inBio = BIO_new(BIO_s_mem());
        BIO_write(inBio, message.c_str(), static_cast<int>(message.size()));

        STACK_OF(X509)* recipients = sk_X509_new_null();
        sk_X509_push(recipients, cert);

        CMS_ContentInfo* cms(
                CMS_encrypt(recipients, inBio, EVP_aes_256_cbc(), 0));

        sk_X509_free(recipients);

        if (!cms)
        {
                std::cout << "EncryptMessage() Failed to encrypt" << std::endl;
                CMS_ContentInfo_free(cms);
                BIO_vfree(inBio);
                return {};
        }

        BIO* outBio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_CMS_stream(outBio, cms, inBio, 0))
        {
                std::cout << "EncryptMessage() Failed to write cms" << std::endl;
                CMS_ContentInfo_free(cms);
                BIO_vfree(inBio);
                BIO_vfree(outBio);
                return {};
        }

        BUF_MEM* bio_buf;
        BIO_get_mem_ptr(outBio, &bio_buf);

        auto result =
                std::string(reinterpret_cast<const char*>(bio_buf->data), bio_buf->length);

        CMS_ContentInfo_free(cms);
        BIO_vfree(inBio);
        BIO_vfree(outBio);

        return result;
}

void test_cms_decrypt(CMS_ContentInfo* cms, EVP_PKEY* pkey, X509* cert)
{
        for (int i=0; i<1000; ++i)
        {
                BIO* outBio = BIO_new(BIO_s_mem());
                if (CMS_decrypt(cms, pkey, cert, NULL, outBio, 0) == 1) // no issues when CMS_DEBUG_DECRYPT is set
                {
                        std::cout << "Problem detected. This shouldn't happen! Iteration: " << i << std::endl;
                        BIO_vfree(outBio);
                        break;
                }
                BIO_vfree(outBio);
        }
}

int main()
{
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        const std::string message = "Hello world!";

        // Please add your own implementation here. Load cert/keys from file or generate them.
        //EVP_PKEY* pkeyA = PEM_read_PrivateKey(fopen("server.pem", "r"), NULL, NULL, NULL);
        EVP_PKEY* pkeyB = PEM_read_PrivateKey(fopen("client.pem", "r"), NULL, NULL, NULL);
        X509* certA = PEM_read_X509(fopen("server.pem", "r"), NULL, NULL, NULL);
        //X509* certB = PEM_read_X509(fopen("client.pem", "r"), NULL, NULL, NULL);

        const std::string encryptedMessage = encrypt_message(message, certA);
        CMS_ContentInfo* cms = create_cms(encryptedMessage);

        test_cms_decrypt(cms, pkeyB, certA);

        CMS_ContentInfo_free(cms);
        return 0;
}
