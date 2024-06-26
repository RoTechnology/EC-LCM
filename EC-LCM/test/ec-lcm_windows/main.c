#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <util.h>
#include <encrypt.h>
#include <decrypt.h>

#include "LCM.h"

//LCM Encryption Section
message_t temp;
char decrypted[TAKS_PAYLOAD_LEN];

//EC-LCM Section -- Begin
static const lecies_curve448_key TEST_PUBLIC_KEY = { .hexstring = "55a9b9d87a26c1add2f61a89f52de9a77fe80178a639a484a07bc7f17c3c1f5930082869f4d7eae98be394db2851fa44b6f8ce95127d9e86" };
static const lecies_curve448_key TEST_PRIVATE_KEY = { .hexstring = "92898bcfddf14e33d48ab16f46d8ad0290af234edfe3754a0f80528ecaafa6bb769a0f4c2601d48ee24ae38d0316103d8cf932a87df58844" };
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

int EC_LCM_Encrypt(
    char** strToEncrypt,             //Input parameter
    uint8_t** _encrypted_string,     //Output encrypted string
    size_t* _encrypted_string_length //Output string length
){

    int s = 1;

    // sizeof(TEST_STRING) instead of strlen(TEST_STRING) because we also want to encrypt the NUL-terminator character along. Never forget the NUL-terminator in C-strings!
    const size_t strToEncryptLength = strlen(strToEncrypt[1])+1;

    printf("Encrypting the following string: %s\n\n", strToEncrypt[1]);

    s = lecies_curve448_encrypt((uint8_t*)strToEncrypt[1], strToEncryptLength, 0, TEST_PUBLIC_KEY, _encrypted_string, _encrypted_string_length, 1);

    if (s != 0)
    {
        printf("Encryption failed! \"EC-LCM curve448_encrypt\" returned: %d\n", s);
        return s;
    }

    printf("Encrypted string >>> base64:\n\n%s\n\nNum chars: %d\n\n", *_encrypted_string, (int)*_encrypted_string_length);

    return s;
}

int EC_LCM_Decrypt( 
    uint8_t* _encrypted_string,      //Input encrypted string
    size_t* _encrypted_string_length,//Input string length

    uint8_t** _decrypted_string,     //Output decrypted string
    size_t* _decrypted_string_length //Output decrypted string length
) {

    int s = 1;

    s = lecies_curve448_decrypt(_encrypted_string, _encrypted_string_length, 1, TEST_PRIVATE_KEY, _decrypted_string, _decrypted_string_length);

    printf("Decrypted string: %s\n Decrypted string length: %d\nStatus code: %d\n\n", *_decrypted_string, (int)*_decrypted_string_length, s);


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