
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "sgx_tseal.h"
#include "sgx_tae_service.h"
//FROM PREVIOUS PROJECT
#include "sgx_trts.h"
//#include "user_types.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h> 
//#include "C:\Program Files (x86)\IntelSWTools\compilers_and_libraries_2017.0.109\windows\tbb\include\tbb\atomic.h"
//#include <algorithm.h> 
#include <string>
#include <vector>
#include <bitset>
#include <map>
#include "BigIntegerLibrary.h"
#include <math.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <memory>
//#include <fstream>
//#include <stdbool.h>
//#include <wchar.h>
//#include "seal.h"
/*#include "biguint.h"
#include "bigpoly.h"
#include "encryptionparams.h"
#include "keygenerator.h"
#include "encryptor.h"
#include "evaluator.h"
#include "decryptor.h"
#include "encoder.h"
#include "chooser.h"
#include "utilities.h"*/
//#include <stdatomic.h>
//#include "decryptor.h"
//using namespace seal::util;
//#include <cstdint>
//#include "fet.cpp"
#include <cstdlib>
//#include "atomic.h"
#include <vector>
#include <stdint.h>
//#include "../Eigen/Core"
//#include "malloc.h"
//using namespace seal;
//#include "biguint.h"
//#include "bigpoly.h"
//#include "bigpolyarray.h"
//#include "encryptionparams.h"
//not #include "keygenerator.h"
// not #include "encryptor.h"
// not #include "evaluator.h"
//not #include "decryptor.h"
//#include "encoder.h"
//not #include "chooser.h"
//not #include "utilities.h"
// not #include "polycrt.h"
#include "matrix.h"
#include "./SEAL/seal.h"
using namespace seal;

//feature counts
#define M 270
#define N 4
#define FEATURE_COUNT 9
#define FEATURE_COUNT_DOUBLE 18

QSMatrix<double> X(N, N, 1.0);
QSMatrix<double> Y(N, 1, 1.0);

int a;
BigPoly a11;
EncryptionParameters params;
string receivedSK;
int featCount = FEATURE_COUNT;
double XtXarr[N][N];
double XtXInvArr[FEATURE_COUNT][FEATURE_COUNT];
double XtYarr[N][1];
//float Beta[FEATURE_COUNT][1];
QSMatrix<double> Beta(N, 1, 0.0);
double beta_array[N];
//Encryptor(params);
//Decryptor(params);
//string array[2][3];// = new string[][];
vector<double> XtX;
vector<double> XtY;

//uint64_t* backingArray;

QSMatrix<double> matTest(10, 10, 1.0);

long double testDataType;



/* --------for Fisher Exact Test function from : https://github.com/chrchang/stats/blob/master/fisher.c  --------*/
#define SMALLISH_EPSILON 0.00000000003
#define SMALL_EPSILON 0.0000000000001

// This helps us avoid premature floating point overflow.
#define EXACT_TEST_BIAS 0.00000000000000000000000010339757656912845935892608650874535669572651386260986328125



#ifdef _MSC_VER
#pragma warning(push)
#pragma warning ( disable:4127 )
#endif


int maxIterations = 25;
double epsilon = 0.01; // stop if all new beta values change less than epsilon (algorithm has converged?)
double jumpFactor = 1000.0; // stop if any new beta jumps too much (algorithm spinning out of control?)
//QSMatrix<long double> ComputeXtilde(QSMatrix<long double> pVector, QSMatrix<long double> xMatrix);
//QSMatrix<long double> ConstructProbVector(QSMatrix<long double> xMatrix, QSMatrix<long double> bVector);
//long double MeanSquaredError(QSMatrix<long double> pVector, QSMatrix<long double> yVector);
//QSMatrix<long double> ConstructNewBetaVector(QSMatrix<long double> oldBetaVector, QSMatrix<long double> xMatrix, QSMatrix<long double> yVector, QSMatrix<long double> oldProbVector);
//QSMatrix<long double> ComputeBestBeta(QSMatrix<long double> xMatrix, QSMatrix<long double> yVector, int maxIterations, long double epsilon, long double jumpFactor);
//bool NoChange(QSMatrix<long double> oldBvector, QSMatrix<long double> newBvector, long double epsilon);
//bool OutOfControl(QSMatrix<long double> oldBvector, QSMatrix<long double> newBvector, long double jumpFactor);


void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

// Used to store the secret passed by the SP in the sample code. The
// size is forced to be 8 bytes. Expected value is
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
uint8_t g_secret[8] = {0};
char* mysecret = new char[15000];
string g, lambda;
//uint8_t sealed_data[930];
sgx_sealed_data_t* sealed_data;


#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t
{
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// Derive two keys from shared key and key id.
bool derive_key(
    const sgx_ec256_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sgx_ec_key_128bit_t *first_derived_key,
    sgx_ec_key_128bit_t *second_derived_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++)
    {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s)-1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    static_assert(sizeof(sgx_ec_key_128bit_t)* 2 == sizeof(sgx_sha256_hash_t), "structure size mismatch.");
    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

    return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t
{
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
	uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    bool derive_ret = false;

    if (NULL == shared_key)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

	if (ISV_KDF_ID != kdf_id)
    {
        //fprintf(stderr, "\nError, key derivation id mismatch in [%s].", __FUNCTION__);
		return SGX_ERROR_KDF_MISMATCH;
	}

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,
        smk_key, sk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,
        mk_key, vk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse)
    {
        int busy_retry_times = 2;
        do{
            ret = sgx_create_pse_session();
        }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    if(b_pse)
    {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    }
    while(0);

    return ret;
}


// Generate a secret information for the SP encrypted with SK.
// Input pointers aren't checked since the trusted stubs copy
// them into EPC memory.
//
// @param context The trusted KE library key context.
// @param p_secret Message containing the secret.
// @param secret_size Size in bytes of the secret message.
// @param p_gcm_mac The pointer the the AESGCM MAC for the
//                 message.
//
// @return SGX_ERROR_INVALID_PARAMETER - secret size if
//         incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESGCM function.
// @return SGX_ERROR_UNEXPECTED - the secret doesn't match the
//         expected value.

sgx_status_t put_secret_data(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do {
        if(secret_size != 8)
        {
            //ret = SGX_ERROR_INVALID_PARAMETER;
            //break;
        }

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }

        uint8_t aes_gcm_iv[12] = {0};
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
			                             (uint8_t*)mysecret,//&g_secret[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (sgx_aes_gcm_128bit_tag_t *)
										 (p_gcm_mac))
										 //(const sgx_aes_gcm_128bit_tag_t *)
								          //p_secret + secret_size)
										   ;

        uint32_t i;
        bool secret_match = true;
        for(i=0;i<secret_size;i++)
        {
            if(g_secret[i] != i)
            {
                //secret_match = false;
            }
        }

        if(!secret_match)
        {
            ret = SGX_ERROR_UNEXPECTED;
        }

        // Once the server has the shared secret, it should be sealed to
        // persistent storage for future use. This will prevents having to
        // perform remote attestation until the secret goes stale. Once the
        // enclave is created again, the secret can be unsealed.
		//sgx_sealed_data_t* 
		/*
		sgx_status_t sealStatus;

		sealStatus = sgx_seal_data(0, NULL, 930, (uint8_t*)mysecret,
            930, sealed_data);

		uint8_t enclaveSealedSecret[930];
		uint8_t unsealed_data[930];
		//memcpy(enclaveSealedSecret, sealed_data, 930);
		uint32_t unsealedLength =930;
	
		sealStatus = sgx_unseal_data(sealed_data, NULL, 0, (uint8_t*)&unsealed_data, &unsealedLength);

		/*char* unsealedDecrypt = new char[930];
		sealStatus = sgx_rijndael128GCM_decrypt(&sk_key,
			                             unsealed_data,
                                         930,
                                         (uint8_t*)unsealedDecrypt,//&g_secret[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (sgx_aes_gcm_128bit_tag_t *)
										 (p_gcm_mac))
										 //(const sgx_aes_gcm_128bit_tag_t *)
								          //p_secret + secret_size)
										   ;
		 
		 if (sealStatus != SGX_SUCCESS)
		 {
			 printf("\n could not seal %d \n", sealStatus);
			 printf("unsealed data %s \n",unsealed_data);
		 }
		 */

    } while(0);

	//printf("Shared secret %d %d %d %d %d %d %d %d \n",g_secret[0], g_secret[1], g_secret[2], g_secret[3], g_secret[4], g_secret[5], g_secret[6], g_secret[7]);
	//printf("Secret size %d \n", secret_size);
	string privateKeys(mysecret);
	printf("RA received secret key %d \n", strlen(mysecret));
	receivedSK = privateKeys;
	printf("mysecret %s \n", mysecret);
	//BigPoly ss = BigPoly(1025, 91, backingArray);

	//int pos = privateKeys.find("1");
	//g = privateKeys.substr(0, pos);
	//lambda = privateKeys.substr(pos+1, strlen(mysecret)+1);

	//printf("mysecret %s \n", mysecret);
	//printf("g is %s \n", g.c_str());
	//printf("lambda is %s \n", lambda.c_str());

    return ret;
}




void computeBeta()
{
	QSMatrix<double> C(X.inverse());
	if (isnan(C(0, 0)))                                            // computing the inverse can blow up easily
		printf("inversion failed");
	QSMatrix<double> D(C*Y);
	Beta = Beta + D;

	printf("bestbeta first entry %f \n", Beta(0, 0));

	for (int i = 0; i < Beta.get_rows(); i++)
	{
		//cout << myBestBeta(i, 0) << endl;
		beta_array[i] = Beta(i, 0);
		printf("%f \n", Beta(i, 0));

	}

		
}

void processXtX()
{
	vector<double>::iterator vIt;
	for (vIt = XtX.begin(); vIt != XtX.end(); ++vIt)
	{

		printf("XtX %f \n", (*vIt));

	}

	int i, j, k, m;
	double t;
	for (i = 0; i < N; i++)
	{
		for (j = 0; j < N; j++)
		{
			XtXarr[i][j] = XtX.front()*1.0;
			X(i, j) = XtX.front()*1.0;
			XtX.erase(XtX.begin());
			//printf("%f ", XtXarr[i][j]);

		}

		printf("\n");

	}
}

void transferMatrix(char* input, char* Result, int len_matrix, int len_Result)
{
	//printf("inside transfer matrix enclave %d \n", strlen(input));

	EncryptionParameters parms;
	parms.poly_modulus() = "1x^1024 + 1";// printf("%d \n", 673);
	parms.coeff_modulus() = BigUInt("7FFFFFFFFFFFFFFFFFFF001"); //printf("%d \n", 674);
	//parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().find(2048)->first;
	parms.plain_modulus() = 1 << 8;// printf("%d \n", 676);

	parms.decomposition_bit_count() = 32;// printf("%d \n", 678);

	parms.noise_standard_deviation() = 3.19;// printf("%d \n", 680);//= ChooserEvaluator::default_noise_standard_deviation(); printf("%d \n", 673);

	parms.noise_max_deviation() = 15.95;// printf("%d \n", 682);//5 * parms.noise_standard_deviation();


	//BalancedEncoder encoder(parms.plain_modulus()); //printf("%d \n", 685);
	BalancedFractionalEncoder encoder(parms.plain_modulus(), parms.poly_modulus(), 128, 64);


	KeyGenerator generator(parms); //printf("%d \n", 687);

	BigPoly secretKey = BigPoly(1025, 91, receivedSK);// printf("forming secret key \n");
	Decryptor decryptor(parms, secretKey); //printf("forming decryptor \n");
	//printf("secret coefficient count %d \n", generator.secret_key().coeff_count());  printf("%d \n", 691);
	//printf("secret coefficient bit count %d \n", generator.secret_key().coeff_bit_count());  printf("%d \n", 692);
	//printf("TM secret key");
	//printf(input);

	//printf("VVVVVVVV decrypt inside enclave %f \n", encoder.decode(decryptor.decrypt(BigPoly(1025, 91, std::string(input))))); //printf("%d \n", 700);

	XtX.push_back(encoder.decode(decryptor.decrypt(BigPoly(1025, 91, std::string(input)))));


	memcpy(Result, "1", 2); //printf("%d \n", 704);
	//printf("XtX size is %d \n", XtX.size());

	if (XtX.size() == N*N)
	{
		processXtX();
	}


}

void processXtY()
{
	vector<double>::iterator vIt;
	for (vIt = XtY.begin(); vIt != XtY.end(); ++vIt)
	{

		printf("XtY  %f \n", (*vIt));

	}

	int i, j;
	for (i = 0; i < N; i++)
	{
		for (j = 0; j < 1; j++)
		{
			XtYarr[i][j] = XtY.front()*1.0;
			Y(i, 0) = XtY.front()*1.0;
			XtY.erase(XtY.begin());
			//printf("%f ", XtYarr[i][j]);

		}

		printf("\n");
	}
}

void transferMatrixXtY(char* input, double Result[], int len_matrix)
{
	//printf("inside transfer matrix XtY enclave %d \n", strlen(input));

	EncryptionParameters parms;
	parms.poly_modulus() = "1x^1024 + 1"; //printf("%d \n", 673);
	parms.coeff_modulus() = BigUInt("7FFFFFFFFFFFFFFFFFFF001"); //printf("%d \n", 674);
	//parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().find(2048)->first;
	parms.plain_modulus() = 1 << 8; //printf("%d \n", 676);

	parms.decomposition_bit_count() = 32; //printf("%d \n", 678);

	parms.noise_standard_deviation() = 3.19; //printf("%d \n", 680);//= ChooserEvaluator::default_noise_standard_deviation(); printf("%d \n", 673);

	parms.noise_max_deviation() = 15.95; //printf("%d \n", 682);//5 * parms.noise_standard_deviation();


	//BalancedEncoder encoder(parms.plain_modulus()); //printf("%d \n", 685);
	BalancedFractionalEncoder encoder(parms.plain_modulus(), parms.poly_modulus(), 128, 64);


	KeyGenerator generator(parms); //printf("%d \n", 687);

	BigPoly secretKey = BigPoly(1025, 91, receivedSK); //printf("forming secret key \n");
	Decryptor decryptor(parms, secretKey); //printf("forming decryptor \n");
	//printf("secret coefficient count %d \n", generator.secret_key().coeff_count());  printf("%d \n", 691);
	//printf("secret coefficient bit count %d \n", generator.secret_key().coeff_bit_count());  printf("%d \n", 692);
	//printf("TM secret key");
	//printf(input);

	//printf("VVVVVVVV decrypt inside enclave %d \n", encoder.decode_int32(decryptor.decrypt(BigPoly(1025, 91, std::string(input))))); printf("%d \n", 700);

	XtY.push_back(encoder.decode(decryptor.decrypt(BigPoly(1025, 91, std::string(input)))));


	//memcpy(Result, "1", 2); //printf("%d \n", 704);
	//printf("XtY size is %d \n", XtY.size());

	if (XtY.size() == N) //feature count
	{
		processXtY();
		computeBeta();
	}

	for (int i = 0; i < Beta.get_rows(); i++)
	{
		//cout << myBestBeta(i, 0) << endl;
		Result[i] = Beta(i, 0);
		//printf("%e \n", Beta(i, 0));

	}




}

#ifdef _MSC_VER
    #pragma warning(pop)
#endif
