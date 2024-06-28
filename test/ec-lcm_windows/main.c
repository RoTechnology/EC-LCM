#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <util.h>
#include <encrypt.h>
#include <decrypt.h>

#include "LCM.h"


//#########################################################################################################################
//#############################SIGNATURE SECTION BEGIN#####################################################################
//#########################################################################################################################

#include "mbedtls/build_info.h"
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_ECDSA_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

#include <string.h>
#endif

/*
 * Uncomment to show key and signature details
 */
//#define VERBOSE

 /*
  * Uncomment to force use of a specific curve
  */
#define ECPARAMS    MBEDTLS_ECP_DP_SECP192R1
//#if !defined(ECPARAMS)
//#define ECPARAMS    mbedtls_ecp_curve_list()->grp_id
//#endif
//
//#if !defined(MBEDTLS_ECDSA_C) || !defined(MBEDTLS_SHA256_C) || \
//    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
//int main(void)
//{
//    mbedtls_printf("MBEDTLS_ECDSA_C and/or MBEDTLS_SHA256_C and/or "
//        "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C not defined\n");
//    mbedtls_exit(0);
//}
//#else

//#if defined(VERBOSE)
static void dump_buf(const char* title, unsigned char* buf, size_t len)
{
    size_t i;

    mbedtls_printf("%s", title);
    for (i = 0; i < len; i++)
        mbedtls_printf("%c%c", "0123456789ABCDEF"[buf[i] / 16],
            "0123456789ABCDEF"[buf[i] % 16]);
    mbedtls_printf("\n");
}

static void dump_pubkey(const char* title, mbedtls_ecdsa_context* key)
{
    unsigned char buf[300];
    size_t len;

    if (mbedtls_ecp_point_write_binary(&key->MBEDTLS_PRIVATE(grp), &key->MBEDTLS_PRIVATE(Q),
        MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf) != 0)
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf(title, buf, len);
}

void funtion1( void ) 
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;


    const char* pers = "ecdsa";
    //((void)argv);

    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /*
     * Generate a key pair for signing
     */
    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*)pers,
        strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Generating key pair...");
    fflush(stdout);

    if ((ret = mbedtls_ecdsa_genkey(&ctx_sign, ECPARAMS,
        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok (key size: %d bits)\n", (int)ctx_sign.MBEDTLS_PRIVATE(grp).pbits);

    dump_pubkey("  + Public key: ", &ctx_sign);

//Exit phase...
exit:

    mbedtls_printf("  + Press Enter to exit this program.\n");
    fflush(stdout); getchar();

    mbedtls_ecdsa_free(&ctx_verify);
    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(exit_code);
}

void ComputeMessageToHash(void) 
{
    unsigned char message[100];
    unsigned char message2[100];
    unsigned char hash[32];
    unsigned char hash2[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char sig_origin[MBEDTLS_ECDSA_MAX_LEN];

    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t sig_len;
    size_t sig_origin_len;

    mbedtls_ecdsa_context ctx_sign, ctx_verify; //To pass
    mbedtls_ctr_drbg_context ctr_drbg; //To pass
    mbedtls_entropy_context entropy; // To Pass


    memset(sig, 0, sizeof(sig));
    memset(sig_origin, 0, sizeof(sig_origin));

    sprintf(message, "SiLeccaLaFiga");
    sprintf(message2, "SiLeccaLAFiga");

    int ret = 1;
    /*
     * Compute message to hash...
     */
    mbedtls_printf("  . Computing message hash of: %s\n", message);
    fflush(stdout);

    if ((ret = mbedtls_sha256(message, sizeof(message), hash, 0)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_sha256 returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    //dump_buf( "  + Hash: ", hash, sizeof( hash ) );

    /*
     * Sign message hash
     */
    mbedtls_printf("  . Signing message hash...");
    fflush(stdout);

    if ((ret = mbedtls_ecdsa_write_signature(&ctx_sign, MBEDTLS_MD_SHA256,
        hash, sizeof(hash),
        sig, sizeof(sig), &sig_len,
        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdsa_write_signature returned %d\n", ret);
        goto exit;
    }
    mbedtls_printf(" ok (signature length = %u)\n\n", (unsigned int)sig_len);

    mbedtls_printf("  + Hash of '%s' is: ", message); dump_buf("", hash, sizeof(hash));
    mbedtls_printf("  + Signature of '%s' is: ", message); dump_buf("", sig, sig_len);


    memcpy(sig_origin, sig, sig_len);
    sig_origin_len = sig_len;
    //dump_buf( "  + Signature: ", sig, sig_len );

//Exit phase...
exit:

    mbedtls_printf("  + Press Enter to exit this program.\n");
    fflush(stdout); getchar();

    mbedtls_ecdsa_free(&ctx_verify);
    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(exit_code);
}
//#########################################################################################################################
//#############################SIGNATURE SECTION END#######################################################################
//#########################################################################################################################


//LCM Encryption Section
message_t temp;
char decrypted[TAKS_PAYLOAD_LEN];

//EC-LCM Section -- Begin
static const lecies_curve25519_key TEST_CURVE25519_PUBLIC_KEY = { .hexstring = "87981c92ede838b434e5fcd9eec9cd45ceaade59f3b72bb9e2088927c50dee07" };
static const lecies_curve25519_key TEST_CURVE25519_PRIVATE_KEY = { .hexstring = "72dcda48cacaf2969d4faecdbdf1e080a269ccc3c4ce16238050fa95052ad110" };
//EC-LCM Section -- End

static int LCM_Encryption(int argumentNumber, char** str) {
    //message_t temp;
    //char decrypted[TAKS_PAYLOAD_LEN];

    if (argumentNumber < 2) {
        printf("\n\nINPUT MESSAGE ERROR - Provide an input message to encrypt");
        return -1;
    }

    if (strlen(str[1]) > TAKS_PAYLOAD_LEN) {
        printf("\n\nMESSAGE LENGTH TOO LONG (MAX 16 chars)");
        return -1;
    }

    //LCM Encryption
    int r = encryptMessage(&temp, str[1]);
    
    if (r == -1) {
        printf("\n\n    ENCRYPT ERROR");
        printf("\n||---------------------------------------------------------------------------------------||\n\n\n\n\n\n\n\n");
        return 0;
    }
    
    printf("\n\n    Message Encrypted \n");
    printf("\nRESULT: %d", r);

    printf("\n\nINPUT MESSAGE - PLAIN TEXT: %s \n", str[1]);
    return r;
}

static int LCM_Decrypt(char* output, message_t* msg){
    int r = 0;
    r = decryptMessage(output, msg);

    if (r == -1) {
        printf("\n\n    DECRYPT ERROR");
        printf("\n||---------------------------------------------------------------------------------------||\n\n\n\n\n\n\n\n");
        return 0;
    }

    printf("\n\n    Message Decrypted \n");
    printf("\nRESULT: %d\n\n", r);
    return r;
}

int EC_LCM_Encrypt(char** strToEncrypt,             //Input parameter
                   
                   uint8_t** _encrypted_string,     //Output encrypted string
                   size_t* _encrypted_string_length) //Output string length
{

    int s = 1;

    // sizeof(TEST_STRING) instead of strlen(TEST_STRING) because we also want to encrypt the NUL-terminator character along. Never forget the NUL-terminator in C-strings!
    const size_t strToEncryptLength = strlen(strToEncrypt[1])+1;

    printf("Encrypting the following string: %s\n\n", strToEncrypt[1]);

    s = lecies_curve25519_encrypt((uint8_t*)strToEncrypt[1], strToEncryptLength, 0, TEST_CURVE25519_PUBLIC_KEY, _encrypted_string, _encrypted_string_length, 0);

    if (s != 0)
    {
        printf("Encryption failed! \"EC-LCM curve448_encrypt\" returned: %d\n", s);
        return s;
    }

    printf("Encrypted string >>> base64:\n\n%s\n\nNum chars: %d\n\n", *_encrypted_string, (int)*_encrypted_string_length);

    return s;
}

int EC_LCM_Decrypt( uint8_t* _encrypted_string,      //Input encrypted string
                    size_t* _encrypted_string_length,//Input string length

                    uint8_t** _decrypted_string,     //Output decrypted string
                    size_t* _decrypted_string_length) //Output decrypted string length
{

    int s = 1;

    s = lecies_curve25519_decrypt(_encrypted_string, _encrypted_string_length, 0, TEST_CURVE25519_PRIVATE_KEY, _decrypted_string, _decrypted_string_length);

    //if (memcmp(strToCheck, _decrypted_string, _decrypted_string_length) != 0) {
    printf("Decrypted string: %s\n Decrypted string length: %d\nStatus code: %d\n\n", *_decrypted_string, (int)*_decrypted_string_length, s);
    //}
    //else {
    //    printf("ERROR!!!");
    //}
 
    return s;
}



int main(int argc, char **strToEncrypt){
    //Encryption
    uint8_t* encrypted_string;
    size_t encrypted_string_length;

    //Decryption
    uint8_t* decrypted_string;
    size_t decrypted_string_length;

    int result = 0;
  

    //LCM ENCRYPT/DECRYPT Begin
    initNodes();
    printf("\########### LCM ALGORITHM STARTED #######################\n");
    result = LCM_Encryption(argc, strToEncrypt);
    printf("\LCM_Encryption RESULT CODE: %d\n\n", result);

    result = LCM_Decrypt(decrypted, &temp);
    printf("\########### LCM ALGORITHM TERMINATED ################## %d\n\n\n\n", result);
    //LCM ENCRYPT/DECRYPT End


//########################################################################################################
//########################################################################################################
//########################################################################################################
//########################################################################################################

//EC-LCM ENCRYPT/DECRYPT Begin ---------------------------------------------------------------------------

    printf("\########### EC_LCM ALGORITHM STARTED ##################\n");
    
    //EC-LCM ENCRYPTING...
    result = EC_LCM_Encrypt(strToEncrypt,              //Input parameter
                            &encrypted_string,         //Output parameter
                            &encrypted_string_length); //Output parameter

    printf("Outside EC_LCM_Encrypt-->Length encrypted string: %d\n\n", (int)encrypted_string_length);
    printf("Outside EC_LCM_Encrypt-->Content encrypted string :\n\n%s\n\n", encrypted_string);
    printf("EC_LCM_Encrypt function returned: %d code!!\n\n", result);

    //EC-LCM DECRYPTING...
    result = EC_LCM_Decrypt(encrypted_string,           //Input encrypted parameter
                            encrypted_string_length,    //Input encrypted parameter
                            &decrypted_string,          //Output decrypted parameter
                            &decrypted_string_length);  //Output decrypted parameter

    printf("Outside EC_LCM_Decrypt-->Length decrypted string: %d\n\n", (int)decrypted_string_length);
    printf("Outside EC_LCM_Decrypt-->Content decrypted string:\n\n%s\n\n\n", decrypted_string);
    printf("EC_LCM_Decrypt function returned: %d code!!\n\n", result);

    //Please don't forget to free up the memory!
    lecies_free(encrypted_string);
    lecies_free(decrypted_string);
    printf("########### EC_LCM ALGORITHM FINISHED###################\n\n");
//EC-LCM ENCRYPT/DECRYPT End ----------------------------------------------------------------------------

    return 0;
}