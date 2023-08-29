#include <jni.h>
#include <string>
#include "include/openssl/ssl.h"
#include <android/log.h>

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_static_1test_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_example_static_1test_MainActivity_cryptoTest(JNIEnv *env, jobject /*this*/) {
    SSL_library_init();
    int nid= EC_curve_nist2nid("P-256");
    return nid;
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_example_static_1test_MainActivity_eckeyTest(JNIEnv *env, jobject /*this*/) {
    CRYPTO_library_init();
    int nid = EC_curve_nist2nid("P-256");
    EC_KEY *testkey= EC_KEY_new_by_curve_name(nid);
    if(EC_KEY_generate_key(testkey)){
        const EC_GROUP *group = EC_KEY_get0_group(testkey);
        EC_POINT *pub_key_point = EC_POINT_new(group);
        if(!EC_POINT_copy(pub_key_point, EC_KEY_get0_public_key(testkey))){
            EC_KEY_free(testkey);
            return 0;
        }
        const auto *message = (const unsigned char *)"Test Message!";
        size_t message_len = strlen((const char *)message);
        EVP_PKEY *pub_key = EVP_PKEY_new();
        if(pub_key== nullptr){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(testkey);
            return 0;
        }
        //EVP_PKEY_assign_EC_KEY(pub_key,testkey);
        if(EVP_PKEY_set1_EC_KEY(pub_key,testkey)!=1){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(testkey);
            return 0;
        }
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
        if (ctx==nullptr){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(testkey);
            return 0;
        }
        if(EVP_PKEY_encrypt_init(ctx)<=0){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(testkey);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
        size_t encrypted_len;
        if(EVP_PKEY_encrypt(ctx, nullptr,&encrypted_len,message,message_len)<=0){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(testkey);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
        auto *encrypted_message = static_cast<unsigned char *>(OPENSSL_malloc(encrypted_len));
        if(encrypted_message== nullptr){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(testkey);
            EVP_PKEY_CTX_free(ctx);
            OPENSSL_free(encrypted_message);
            return 0;
        }
        if(EVP_PKEY_encrypt(ctx,encrypted_message,&encrypted_len,message,message_len)<=0){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(testkey);
            EVP_PKEY_CTX_free(ctx);
            OPENSSL_free(encrypted_message);
            return 0;
        }
        EC_POINT_free(pub_key_point);
        EC_KEY_free(testkey);
        EVP_PKEY_CTX_free(ctx);
        OPENSSL_free(encrypted_message);
        return 1;
    }
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_example_static_1test_MainActivity_ECDSATest(JNIEnv *env, jobject /*this*/) {
    //EC鍵を使ったメッセージ署名と検証
    //署名
    CRYPTO_library_init();
    int nid = EC_curve_nist2nid("P-256");
    EC_KEY *test_key= EC_KEY_new_by_curve_name(nid);
    if(EC_KEY_generate_key(test_key)){
        const EC_GROUP *group = EC_KEY_get0_group(test_key);
        EC_POINT *pub_key_point = EC_POINT_new(group);
        if(!EC_POINT_copy(pub_key_point, EC_KEY_get0_public_key(test_key))){
            EC_KEY_free(test_key);
            return 0;
        }
        const auto *message = (const unsigned char *)"Test Message!";
        size_t message_len = strlen((const char *)message);
        EVP_PKEY *pub_key = EVP_PKEY_new();
        if(pub_key== nullptr){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(test_key);
            return 0;
        }
        //EVP_PKEY_assign_EC_KEY(pub_key,testkey);
        if(EVP_PKEY_set1_EC_KEY(pub_key,test_key)!=1){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(test_key);
            return 0;
        }
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
        if (ctx==nullptr){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(test_key);
            return 0;
        }
        if(EVP_PKEY_sign_init(ctx)<=0){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(test_key);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
        size_t sig_len;
        if(EVP_PKEY_sign(ctx, nullptr,&sig_len,message,message_len)<=0){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(test_key);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
        auto *sig_message = static_cast<unsigned char *>(OPENSSL_malloc(sig_len));
        if(sig_message== nullptr){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(test_key);
            EVP_PKEY_CTX_free(ctx);
            OPENSSL_free(sig_message);
            return 0;
        }
        if(EVP_PKEY_sign(ctx,sig_message,&sig_len,message,message_len)<=0){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(test_key);
            EVP_PKEY_CTX_free(ctx);
            OPENSSL_free(sig_message);
            return 0;
        }

        //検証
        if(EVP_PKEY_verify_init(ctx)<=0){
            EC_POINT_free(pub_key_point);
            EC_KEY_free(test_key);
            EVP_PKEY_CTX_free(ctx);
            OPENSSL_free(sig_message);
            return 0;
        }
        if (EVP_PKEY_verify(ctx,sig_message,sig_len,message,message_len)==0){
            //検証失敗時
            __android_log_print(ANDROID_LOG_DEBUG,"cpp","verify failed!");
            EC_POINT_free(pub_key_point);
            EC_KEY_free(test_key);
            EVP_PKEY_CTX_free(ctx);
            OPENSSL_free(sig_message);
            return 0;
        }
        __android_log_print(ANDROID_LOG_DEBUG,"cpp","sign and verify success!");
        EC_POINT_free(pub_key_point);
        EC_KEY_free(test_key);
        EVP_PKEY_CTX_free(ctx);
        OPENSSL_free(sig_message);
        return 1;
    }
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_example_static_1test_MainActivity_RSATest(JNIEnv *env, jobject /*this*/) {
    CRYPTO_library_init();

    // Initialize BoringSSL
    OPENSSL_init_crypto(0, nullptr);

    // Generate RSA key pair
    RSA *rsa_key = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4); // RSA_F4 is a commonly used exponent value
    RSA_generate_key_ex(rsa_key, 2048, bn, nullptr);

    // Print public key
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa_key);
    char *pub_key;
    size_t pub_key_len = BIO_get_mem_data(bio, &pub_key);
    __android_log_print(ANDROID_LOG_DEBUG,"cpp","Public Key:\n%s\n", pub_key);

    // Encrypt a message
    const char *message = "Hello, BoringSSL!";
    unsigned char ciphertext[RSA_size(rsa_key)];
    int encrypted_size = RSA_public_encrypt(strlen(message), (const unsigned char *)message, ciphertext, rsa_key, RSA_PKCS1_OAEP_PADDING);

    // Print encrypted message
    __android_log_print(ANDROID_LOG_DEBUG,"cpp","Encrypted Message:");
    for (int i = 0; i < encrypted_size; ++i) {
        __android_log_print(ANDROID_LOG_DEBUG,"cpp","%02X", ciphertext[i]);
    }


    //Decrypt a message
    int ciphertext_size = sizeof(ciphertext);
    unsigned char decrypted[RSA_size(rsa_key)];
    int decrypted_size = RSA_private_decrypt(ciphertext_size,ciphertext,decrypted,rsa_key,RSA_PKCS1_OAEP_PADDING);

    if(decrypted_size==-1){
        __android_log_print(ANDROID_LOG_DEBUG,"cpp","decrypt error");
        RSA_free(rsa_key);
        BN_free(bn);
        BIO_free(bio);
        return 0;
    }

    __android_log_print(ANDROID_LOG_DEBUG,"cpp","decrypted message: %.*s\n",decrypted_size,decrypted);

    // Clean up
    RSA_free(rsa_key);
    BN_free(bn);
    BIO_free(bio);
    return 1;
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_example_static_1test_MainActivity_SHATest(JNIEnv *env, jobject /*this*/) {
    const char *test = "SHA256 Test!!";

//    SHA256_CTX *sha256Ctx;
//    SHA256_Init(sha256Ctx);
//

    const auto *data=(const unsigned char *)test;
    size_t len = strlen(test);
    uint8_t out[SHA256_DIGEST_LENGTH];
    SHA256(data,len,out);

    for (unsigned char i : out){
        __android_log_print(ANDROID_LOG_DEBUG,"cpp","%u",i);
    }


    return 1;
}
extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_static_1test_MainActivity_CastTest(JNIEnv *env, jobject /*this*/) {
    char *test = "Test Message!";

    const auto *data=(const unsigned char *)test;
    size_t len = strlen(test);
    uint8_t out[SHA256_DIGEST_LENGTH];
    SHA256(data,len,out);

    jintArray Test;
    Test= reinterpret_cast<jintArray>(out);


    for (unsigned char i : out){
        __android_log_print(ANDROID_LOG_DEBUG,"cpp","%u",i);
    }

    return Test;
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_example_static_1test_MainActivity_SHATest2(JNIEnv *env, jobject /*this*/) {
    char *test1="ABCDEFg";
    //char *test2="ABCDEFg";
    char *test2="AbdcEzg";
//
//    const auto *data1=(const unsigned char *)test1;
//    size_t len1 = strlen(test1);
//    uint8_t out1[SHA256_DIGEST_LENGTH];
//    SHA256(data1,len1,out1);
//
//    const auto *data2=(const unsigned char *)test2;
//    size_t len2 = strlen(test2);
//    uint8_t out2[SHA256_DIGEST_LENGTH];
//    SHA256(data2,len2,out2);
//
//    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
//        if (out1[i]!=out2[i]){
//            __android_log_print(ANDROID_LOG_DEBUG,"cpp","test1とtest2は違うもの");
//            return 0;
//        }
//    }
//    __android_log_print(ANDROID_LOG_DEBUG,"cpp","test1とtest2は同じもの");

    __android_log_print(ANDROID_LOG_DEBUG,"cpp","%cと%cと%cが出たら正解",test1[0],test1[4],test1[6]);

    int test[strlen(test1)];
    const auto *data1= (const unsigned char*)test1;
    const auto *data2=(const unsigned char*)test2;

    for (int i=0;i<strlen(test1);i++){
        size_t len=1;
        uint8_t out1[SHA256_DIGEST_LENGTH];
        uint8_t out2[SHA256_DIGEST_LENGTH];
        SHA256(data1, len, out1);
        SHA256(data2,len,out2);
        for(int j=0;j<SHA256_DIGEST_LENGTH;j++){
            if(out1[j]!=out2[j]){
                test[i]=0;
                break;
            }
            test[i]=1;
        }
        data1++;
        data2++;
    }

    for(int i=0;i< strlen(test1);i++){
        if(test[i]==1){
            __android_log_print(ANDROID_LOG_DEBUG,"cpp","%c",test1[i]);
        }
    }

    return 1;
}