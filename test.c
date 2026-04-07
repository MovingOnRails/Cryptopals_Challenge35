#include <stdio.h>

#include <gmp.h>
#include <sys/random.h>
#include <openssl/sha.h>

#include "../../set2/Challenge10/aes.c"


void getKeyFromSecret(mpz_t s, unsigned char result[]){

    unsigned char secret[128];
    size_t count;
    memset(secret,0,128);
    mpz_export(secret, &count, 1, 1, 1, 0, s);

    unsigned char secret_hash[SHA_DIGEST_LENGTH];
    SHA1(secret, 128, secret_hash);
    memcpy(result, secret_hash, 16);
    return;
}

int main(){

    mpz_t g1, gp1, gp, p, a, b, A, B, sA, sB, sA_byM_g1, sB_byM_g1, sA_byM_gp1, sB_byM_gp1, sA_byM_gp, sB_byM_gp;
    gmp_randstate_t state;

    mpz_inits(g1, gp1, gp, p, a, b, A, B, sA, sB, sA_byM_g1, sB_byM_g1, sA_byM_gp1, sB_byM_gp1, sA_byM_gp, sB_byM_gp, NULL);

    const char* nist_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
                     "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
                     "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
                     "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
                     "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
                     "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
                     "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
                     "fffffffffffff";

    mpz_set_str(p, nist_p, 16);

    // -------------------MITM With g = 1-------------------
    // g and p have been negotiated before Alice sends their public key
    mpz_set_ui(g1, 1);
    mpz_set(gp, p);
    mpz_sub_ui(gp1, p, 1);

    gmp_randinit_default(state);
    gmp_randseed_ui(state, 12345);

    mpz_set_ui(a, 0);
    while(mpz_cmp_ui(a, 0) == 0){
        mpz_urandomm(a,state,p);
    }

    mpz_set_ui(b, 0);
    while(mpz_cmp_ui(b, 0) == 0){
        mpz_urandomm(b,state,p);
    }

    // A --> M
    // A = g**a % p == 1**a % p == 1
    mpz_powm(A, g1, a, p);

    // M --> B
    // A = 1

    // B --> M
    // B = g**b % p = 1
    mpz_powm(B, g1, b, p);
    // B computes sB = 1
    mpz_powm(sB, A, b, p);

    // M --> A
    // B = 1
    // A computes sA = 1
    mpz_powm(sA, B, a, p);


    // A --> M msg

    unsigned char IV_A_g1[16];
    getrandom(IV_A_g1, 16, 0);
    unsigned char keyA_g1[16];
    getKeyFromSecret(sA, keyA_g1);
    unsigned char aliceMessage[11] = "Hello Bob!";
    unsigned char* aliceCiphertext_g1 = aes_cbc_encrypt_evp(aliceMessage, 10, IV_A_g1, keyA_g1);

    // M intercepts the message and decrypts it
    // M knows sA to be 1, so they derive their own key from sA=1
    mpz_set_ui(sA_byM_g1, 1) ;
    unsigned char keyA_byM_g1[16];
    getKeyFromSecret(sA_byM_g1, keyA_byM_g1);
    unsigned char* aliceCiphertextDeciphered_g1 = aes_cbc_decrypt_evp(aliceCiphertext_g1,16,IV_A_g1,keyA_byM_g1);
    // everything ok until now
    // M --> B

    // B --> M
    unsigned char IV_B_g1[16];
    getrandom(IV_B_g1, 16, 0);
    unsigned char keyB_g1[16];
    getKeyFromSecret(sB, keyB_g1);
    unsigned char bobMessage[13] = "Hello Alice!";
    unsigned char* bobCiphertext_g1 = aes_cbc_encrypt_evp(bobMessage, 12, IV_B_g1, keyB_g1);

    // M intercepts the message and decrypts it
    // M knows sB to be 1, so they derive their own key from sB=1
    mpz_set_ui(sB_byM_g1, 1) ;
    unsigned char keyB_byM_g1[16];
    getKeyFromSecret(sB_byM_g1, keyB_byM_g1);
    unsigned char* bobCiphertextDeciphered_g1 = aes_cbc_decrypt_evp(bobCiphertext_g1,16,IV_B_g1,keyB_byM_g1);
    // everyting ok till now

    // ------------------------Using g = p------------------------

    // A --> M, A
    mpz_powm(A, gp, a, p);

    // B --> M
    mpz_powm(B, gp, b, p);

    // A computes sA
    mpz_powm(sA, B, a, p);
    // B computes SB
    mpz_powm(sB, A, b, p);

    // A --> M, msg

    unsigned char IV_A_gp[16];
    getrandom(IV_A_gp, 16, 0);
    unsigned char keyA_gp[16];
    getKeyFromSecret(sA, keyA_gp);
    unsigned char* aliceCiphertext_gp = aes_cbc_encrypt_evp(aliceMessage, 10, IV_A_gp, keyA_gp);

    // M intercepts the message and decrypts it
    // M knows sA to be 0, so they derive their own key from sA=0
    mpz_set_ui(sA_byM_gp, 0) ;
    unsigned char keyA_byM_gp[16];
    getKeyFromSecret(sA_byM_gp, keyA_byM_gp);
    unsigned char* aliceCiphertextDeciphered_gp = aes_cbc_decrypt_evp(aliceCiphertext_gp,16,IV_A_gp,keyA_byM_gp);



    return 0;
}