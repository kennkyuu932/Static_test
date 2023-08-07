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