
#pragma warning(disable: 4996)
#include <stdio.h>
#include <iostream>
#include <limits.h>
#include <ctime>
#include <time.h>
#include <chrono>
#include <sstream>
#include <fstream>
#include "seal.h"
#include "../Eigen/Dense"
#include "../Eigen/Core"
#include <atomic>
#include <vector>
#include "Site.h"
//#include "../gsl-2.3/matrix/gsl_matrix.h"
#include "seal.h"

// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"

#include "isv_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
#include "network_ra.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "service_provider.h"

using namespace std;
using namespace seal;


#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

// In addition to generating and sending messages, this application
// can use pre-generated messages to verify the generation of
// messages and the information flow.
#include "sample_messages.h"



#ifdef _MSC_VER
#define ENCLAVE_PATH "isv_enclave.signed.dll"
#else
#define ENCLAVE_PATH "isv_enclave.signed.so"
#endif

uint8_t* msg1_samples[] = { msg1_sample1, msg1_sample2 };
uint8_t* msg2_samples[] = { msg2_sample1, msg2_sample2 };
uint8_t* msg3_samples[MSG3_BODY_SIZE] = { msg3_sample1, msg3_sample2 };
uint8_t* attestation_msg_samples[] =
    { attestation_msg_sample1, attestation_msg_sample2};

//OCALL from our previous project
void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate 
	* the input string to prevent buffer overflow. 
	*/
	printf("%s", str);
}

bool NoChange(Eigen::MatrixXd oldBvector, Eigen::MatrixXd newBvector, double epsilon)
{
	printf(" in nochange\n");
	for (int i = 0; i < oldBvector.rows(); ++i)
	{
		if (abs(oldBvector(i, 0) - newBvector(i, 0)) > epsilon) // we have at least one change
			return false;
	}
	return true;
}
bool OutOfControl(Eigen::MatrixXd oldBvector, Eigen::MatrixXd newBvector, double jumpFactor)
{
	// true if any new b is jumpFactor times greater than old b
	printf(" in outofcontrol\n");
	for (int i = 0; i < oldBvector.rows(); ++i)
	{
		if (oldBvector(i, 0) == 0.0) return false; // if old is 0.0 anything goes for the new value

		if (abs(oldBvector(i, 0) - newBvector(i, 0)) / abs(oldBvector(i, 0)) > jumpFactor) // too big a change.
		{
			printf("out of control change %f \n", abs(oldBvector(i, 0) - newBvector(i, 0)) / abs(oldBvector(i, 0)));
			return true;
		}

	}
	return false;
}




// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        //fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    //fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        //fprintf(file, "0x%x, ", array[i]);
        //if(i % 8 == 7) fprintf(file, "\n");
    }
    //fprintf(file, "0x%x ", array[i]);
    //fprintf(file, "\n}\n");
}


void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if(!response)
    {
        //fprintf(file, "\t\n( null )\n");
        return;
    }

    //fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    //fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            //response->status[1]);
    //fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        //fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        //fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        //fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        //fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        //fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        //fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        //fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        //fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        //fprintf(file, "ATTESTATION RESULT MSG mac - ");
        //PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        //fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                //p_att_result->secret.payload_size);

        //fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
    }
    else
    {
        //fprintf(file, "\nERROR in printing out the response. "
                      // "Response of type not supported %d\n", response->type);
    }
}

//Matrix operations transpose and multiplication
typedef vector<BigPoly> Row; // One row of the matrix
typedef vector<Row> Matrix; // Matrix: a vector of rows
void swap(BigPoly &a, BigPoly &b) {
	BigPoly c = a;
	a = b;
	b = c;
}

void Transpose(Matrix& m) {
	int n = m.size();
	for (int i = 0; i < n - 1; ++i) {
		for (int j = i + 1; j < n; ++j) {
			swap(m[i][j], m[j][i]);
		}
	}
}
/*
Matrix multiply(const Matrix& a, const Matrix& b) {
int n = a.size();
int m = a[0].size();
int p = b[0].size();
Matrix c(n, vector<BigPoly>(p));
for (int i = 0; i < n; ++i) {
for (int j = 0; j < p; ++j) {
BigPoly sum;
for (int k = 0; k < m; ++k) {
sum = sum + a[i][k] * b[k][j];// to do, use evaluator to perform FHE
}
c[i][j] = sum;
}
}
return c;
}
*/

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
	}
	return str;
}

// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#ifdef _MSC_VER
#include "stdafx.h"
int main(int argc, char* argv[])
#else
#define _T(x) x
int main(int argc, char* argv[])
#endif
{

	

    int ret = 0;
    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;
    sgx_enclave_id_t enclave_id = 0;
    int enclave_lost_retry_time = 1;
    int busy_retry_time = 4;
    sgx_ra_context_t context = INT_MAX;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t* p_msg3_full = NULL;

    int32_t verify_index = -1;
    int32_t verification_samples = sizeof(msg1_samples)/sizeof(msg1_samples[0]);

    FILE* OUTPUT = stdout;

#define VERIFICATION_INDEX_IS_VALID() (verify_index > 0 && \
                                       verify_index <= verification_samples)
#define GET_VERIFICATION_ARRAY_INDEX() (verify_index-1)

    if(argc > 1)
    {

#ifdef _MSC_VER
        //verify_index = _ttoi(argv[1]);
		//verify_index = atoi(argv[1]);
#else
        //verify_index = atoi(argv[1]);
#endif

        if( VERIFICATION_INDEX_IS_VALID())
        {
            //fprintf(OUTPUT, "\nVerifying precomputed attestation messages "
                           // "using precomputed values# %d\n", verify_index);
        }
        else
        {/*
            fprintf(OUTPUT, "\nValid invocations are:\n");
            fprintf(OUTPUT, "\n\tisv_app\n");
            fprintf(OUTPUT, "\n\tisv_app <verification index>\n");
            fprintf(OUTPUT, "\nValid indices are [1 - %d]\n",
                    verification_samples);
            fprintf(OUTPUT, "\nUsing a verification index uses precomputed "
                    "messages to assist debugging the remote attestation "
                    "service provider.\n");*/
            //return -1;
        }
    }
 
	time_t beforeLD;
	time(&beforeLD); 



	




	std::chrono::system_clock::time_point beforeRA = std::chrono::system_clock::now();

    // Preparation for remote attestation by configuring extended epid group id.
    {
        uint32_t extended_epid_group_id = 0;
        ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
        if (SGX_SUCCESS != ret)
        {
            ret = -1;
            //fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].",
                //__FUNCTION__);
            return ret;
        }
        //fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.");

        p_msg0_full = (ra_samp_request_header_t*)
            malloc(sizeof(ra_samp_request_header_t)
            +sizeof(uint32_t));
        if (NULL == p_msg0_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg0_full->type = TYPE_RA_MSG0;
        p_msg0_full->size = sizeof(uint32_t);

        *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t)) = extended_epid_group_id;
        {

            //fprintf(OUTPUT, "\nMSG0 body generated -\n");

            PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);

        }
        // The ISV application sends msg0 to the SP.
        // The ISV decides whether to support this extended epid group id.
        //fprintf(OUTPUT, "\nSending msg0 to remote attestation service provider.\n");

        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
            p_msg0_full,
            &p_msg0_resp_full);
        if (ret != 0)
        {
            fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed "
                "[%s].", __FUNCTION__);
            goto CLEANUP;
        }
        //fprintf(OUTPUT, "\nSent MSG0 to remote attestation service.\n");
    }
    // Remote attestation will be initiated the ISV server challenges the ISV
    // app or if the ISV app detects it doesn't have the credentials
    // (shared secret) from a previous attestation required for secure
    // communication with the server.
	//if(false)
    {
        // ISV application creates the ISV enclave.
        int launch_token_update = 0;
        sgx_launch_token_t launch_token = {0};
        memset(&launch_token, 0, sizeof(sgx_launch_token_t));
        do
        {
            ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                                     SGX_DEBUG_FLAG,
                                     &launch_token,
                                     &launch_token_update,
                                     &enclave_id, NULL);
            if(SGX_SUCCESS != ret)
            {
                ret = -1;
                fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
                        __FUNCTION__);
                goto CLEANUP;
            }
            //fprintf(OUTPUT, "\nCall sgx_create_enclave success.");

            ret = enclave_init_ra(enclave_id,
                                  &status,
                                  false,
                                  &context);
        //Ideally, this check would be around the full attestation flow.
        } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

        if(SGX_SUCCESS != ret || status)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call enclave_init_ra fail [%s].",
                    __FUNCTION__);
            goto CLEANUP;
        }
        //fprintf(OUTPUT, "\nCall enclave_init_ra success.");

        // isv application call uke sgx_ra_get_msg1
        p_msg1_full = (ra_samp_request_header_t*)
                      malloc(sizeof(ra_samp_request_header_t)
                             + sizeof(sgx_ra_msg1_t));
        if(NULL == p_msg1_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg1_full->type = TYPE_RA_MSG1;
        p_msg1_full->size = sizeof(sgx_ra_msg1_t);
        do
        {
            ret = sgx_ra_get_msg1(context, enclave_id, sgx_ra_get_ga,
                                  (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full
                                  + sizeof(ra_samp_request_header_t)));
            Sleep(3 * 1000); // Wait 3s between retries
        } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
        if(SGX_SUCCESS != ret)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1 fail [%s].",
                    __FUNCTION__);
            goto CLEANUP;
        }
        else
        {
            //fprintf(OUTPUT, "\nCall sgx_ra_get_msg1 success.\n");

            //fprintf(OUTPUT, "\nMSG1 body generated -\n");

            PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);

        }

        if(VERIFICATION_INDEX_IS_VALID())
        {

            memcpy_s(p_msg1_full->body, p_msg1_full->size,
                     msg1_samples[GET_VERIFICATION_ARRAY_INDEX()],
                     p_msg1_full->size);

            //fprintf(OUTPUT, "\nInstead of using the recently generated MSG1, "
                           // "we will use the following precomputed MSG1 -\n");

            PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
        }


        // The ISV application sends msg1 to the SP to get msg2,
        // msg2 needs to be freed when no longer needed.
        // The ISV decides whether to use linkable or unlinkable signatures.
        //fprintf(OUTPUT, "\nSending msg1 to remote attestation service provider."
                        //"Expecting msg2 back.\n");


        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
                                      p_msg1_full,
                                      &p_msg2_full);

        if(ret != 0 || !p_msg2_full)
        {
            fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed "
                            "[%s].", __FUNCTION__);
            if(VERIFICATION_INDEX_IS_VALID())
            {
                //fprintf(OUTPUT, "\nBecause we are in verification mode we will "
                               // "ignore this error.\n");
                //fprintf(OUTPUT, "\nInstead, we will pretend we received the "
                               // "following MSG2 - \n");

                SAFE_FREE(p_msg2_full);
                ra_samp_response_header_t* precomputed_msg2 =
                    (ra_samp_response_header_t*)msg2_samples[
                        GET_VERIFICATION_ARRAY_INDEX()];
                const size_t msg2_full_size = sizeof(ra_samp_response_header_t)
                                              +  precomputed_msg2->size;
                p_msg2_full =
                    (ra_samp_response_header_t*)malloc(msg2_full_size);
                if(NULL == p_msg2_full)
                {
                    ret = -1;
                    goto CLEANUP;
                }
                memcpy_s(p_msg2_full, msg2_full_size, precomputed_msg2,
                         msg2_full_size);

                PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
                                 sizeof(ra_samp_response_header_t)
                                 + p_msg2_full->size);
            }
            else
            {
                goto CLEANUP;
            }
        }
        else
        {
            // Successfully sent msg1 and received a msg2 back.
            // Time now to check msg2.
            if(TYPE_RA_MSG2 != p_msg2_full->type)
            {

                fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. "
                                "[%s].", __FUNCTION__);

                if(VERIFICATION_INDEX_IS_VALID())
                {
                    //fprintf(OUTPUT, "\nBecause we are in verification mode we "
                                    //"will ignore this error.");
                }
                else
                {
                    goto CLEANUP;
                }
            }

           // fprintf(OUTPUT, "\nSent MSG1 to remote attestation service "
                         //   "provider. Received the following MSG2:\n");
            PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
                             sizeof(ra_samp_response_header_t)
                             + p_msg2_full->size);

            //fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
            PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);

            if( VERIFICATION_INDEX_IS_VALID() )
            {
                // The response should match the precomputed MSG2:
                ra_samp_response_header_t* precomputed_msg2 =
                    (ra_samp_response_header_t *)
                    msg2_samples[GET_VERIFICATION_ARRAY_INDEX()];
                if(memcmp( precomputed_msg2, p_msg2_full,
                   sizeof(ra_samp_response_header_t) + p_msg2_full->size))
                {
                    fprintf(OUTPUT, "\nVerification ERROR. Our precomputed "
                                    "value for MSG2 does NOT match.\n");
                    fprintf(OUTPUT, "\nPrecomputed value for MSG2:\n");
                    PRINT_BYTE_ARRAY(OUTPUT, precomputed_msg2,
                                     sizeof(ra_samp_response_header_t)
                                     + precomputed_msg2->size);
                    fprintf(OUTPUT, "\nA more descriptive representation "
                                    "of precomputed value for MSG2:\n");
                    PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT,
                                                       precomputed_msg2);
                }
                else
                {
                    //fprintf(OUTPUT, "\nVerification COMPLETE. Remote "
                                  //  "attestation service provider generated a "
                                  //  "matching MSG2.\n");
                }
            }

        }

        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full
                                      + sizeof(ra_samp_response_header_t));


        uint32_t msg3_size = 0;
        if( VERIFICATION_INDEX_IS_VALID())
        {
            // We cannot generate a valid MSG3 using the precomputed messages
            // we have been using. We will use the precomputed msg3 instead.
            msg3_size = MSG3_BODY_SIZE;
            p_msg3 = (sgx_ra_msg3_t*)malloc(msg3_size);
            if(NULL == p_msg3)
            {
                ret = -1;
                goto CLEANUP;
            }
            memcpy_s(p_msg3, msg3_size,
                     msg3_samples[GET_VERIFICATION_ARRAY_INDEX()], msg3_size);
            //fprintf(OUTPUT, "\nBecause MSG1 was a precomputed value, the MSG3 "
                           // "we use will also be. PRECOMPUTED MSG3 - \n");
        }
        else
        {
            busy_retry_time = 2;
            // The ISV app now calls uKE sgx_ra_proc_msg2,
            // The ISV app is responsible for freeing the returned p_msg3!!
            do
            {
                ret = sgx_ra_proc_msg2(context,
                                   enclave_id,
                                   sgx_ra_proc_msg2_trusted,
                                   sgx_ra_get_msg3_trusted,
                                   p_msg2_body,
                                   p_msg2_full->size,
                                   &p_msg3,
                                   &msg3_size);
            } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
            if(!p_msg3)
            {
                fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
                                "p_msg3 = 0x%p [%s].", p_msg3, __FUNCTION__);
                ret = -1;
                goto CLEANUP;
            }
            if(SGX_SUCCESS != (sgx_status_t)ret)
            {
                fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
                                "ret = 0x%08x [%s].", ret, __FUNCTION__);
                ret = -1;
                goto CLEANUP;
            }
            else
            {
                //fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2 success.\n");
                //fprintf(OUTPUT, "\nMSG3 - \n");
            }
        }

        PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

        p_msg3_full = (ra_samp_request_header_t*)malloc(
                       sizeof(ra_samp_request_header_t) + msg3_size);
        if(NULL == p_msg3_full)
        {
            ret = -1;
            goto CLEANUP;
        }
		
        p_msg3_full->type = TYPE_RA_MSG3;
        p_msg3_full->size = msg3_size;
        if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size))
        {
            fprintf(OUTPUT,"\nError: INTERNAL ERROR - memcpy failed in [%s].",
                    __FUNCTION__);
            ret = -1;
            goto CLEANUP;
        }
		
        // The ISV application sends msg3 to the SP to get the attestation
        // result message, attestation result message needs to be freed when
        // no longer needed. The ISV service provider decides whether to use
        // linkable or unlinkable signatures. The format of the attestation
        // result is up to the service provider. This format is used for
        // demonstration.  Note that the attestation result message makes use
        // of both the MK for the MAC and the SK for the secret. These keys are
        // established from the SIGMA secure channel binding.
        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
                                      p_msg3_full,
                                      &p_att_result_msg_full);
        if(ret || !p_att_result_msg_full)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
            goto CLEANUP;
        }

		


        sample_ra_att_result_msg_t * p_att_result_msg_body =
            (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                                           + sizeof(ra_samp_response_header_t));
        if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
                            "received was NOT of type att_msg_result. Type = "
                            "%d. [%s].", p_att_result_msg_full->type,
                             __FUNCTION__);
            goto CLEANUP;
        }
        else
        {
            //fprintf(OUTPUT, "\nSent MSG3 successfully. Received an attestation "
                           // "result message back\n.");
            if( VERIFICATION_INDEX_IS_VALID() )
            {
                if(memcmp(p_att_result_msg_full->body,
                        attestation_msg_samples[GET_VERIFICATION_ARRAY_INDEX()],
                        p_att_result_msg_full->size) )
                {
                    fprintf(OUTPUT, "\nSent MSG3 successfully. Received an "
                                    "attestation result message back that did "
                                    "NOT match the expected value.\n");
                    fprintf(OUTPUT, "\nEXPECTED ATTESTATION RESULT -");
                    PRINT_BYTE_ARRAY(OUTPUT,
                        attestation_msg_samples[GET_VERIFICATION_ARRAY_INDEX()],
                        p_att_result_msg_full->size);
                }
            }
        }

        //fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED - ");
        PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body,
                         p_att_result_msg_full->size);


        if( VERIFICATION_INDEX_IS_VALID() )
        {
            //fprintf(OUTPUT, "\nBecause we used precomputed values for the "
                           // "messages, the attestation result message will "
                           // "not pass further verification tests, so we will "
                            //"skip them.\n");
            goto CLEANUP;
        }

        // Check the MAC using MK on the attestation result message.
        // The format of the attestation result message is ISV specific.
        // This is a simple form for demonstration. In a real product,
        // the ISV may want to communicate more information.
        ret = verify_att_result_mac(enclave_id,
                &status,
                context,
                (uint8_t*)&p_att_result_msg_body->platform_info_blob,
                sizeof(ias_platform_info_blob_t),
                (uint8_t*)&p_att_result_msg_body->mac,
                sizeof(sgx_mac_t));
        if((SGX_SUCCESS != ret) ||
           (SGX_SUCCESS != status))
        {
            ret = -1;
            fprintf(OUTPUT, "\nError: INTEGRITY FAILED - attestation result "
                            "message MK based cmac failed in [%s].",
                            __FUNCTION__);
            goto CLEANUP;
        }

        bool attestation_passed = true;
        // Check the attestation result for pass or fail.
        // Whether attestation passes or fails is a decision made by the ISV Server.
        // When the ISV server decides to trust the enclave, then it will return success.
        // When the ISV server decided to not trust the enclave, then it will return failure.
        if(0 != p_att_result_msg_full->status[0]
           || 0 != p_att_result_msg_full->status[1])
        {
            fprintf(OUTPUT, "\nError, attestation result message MK based cmac "
                            "failed in [%s].", __FUNCTION__);
            attestation_passed = false;
        }

        // The attestation result message should contain a field for the Platform
        // Info Blob (PIB).  The PIB is returned by the IAS in the attestation report.
        // It is not returned in all cases, but when it is, the ISV app
        // should pass it to the blob analysis API called sgx_report_attestation_status()
        // along with the trust decision from the ISV server.
        // The ISV application will take action based on the update_info.
        // returned in update_info by the API.  
        // This call is stubbed out for the sample.
        // 
        // sgx_update_info_bit_t update_info;
        // ret = sgx_report_attestation_status(
        //     &p_att_result_msg_body->platform_info_blob,
        //     attestation_passed ? 0 : 1, &update_info);

        // Get the shared secret sent by the server using SK (if attestation
        // passed)
        if(attestation_passed)
        {
            ret = put_secret_data(enclave_id,
                                  &status,
                                  context,
                                  p_att_result_msg_body->secret.payload,
                                  p_att_result_msg_body->secret.payload_size,
                                  p_att_result_msg_body->secret.payload_tag);
            if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status))
            {
                fprintf(OUTPUT, "\nError, attestation result message secret "
                                "using SK based AESGCM failed in [%s]. ret = "
                                "0x%0x. status = 0x%0x", __FUNCTION__, ret,
                                 status);

				//SEAL TEST
				//EncryptionParameters params;
				//params.poly_modulus() = "1x^2048 + 1";
				//params.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
				//params.plain_modulus() = 1 << 8;
				//IntegerEncoder encoder(params.plain_modulus());
				// Encode two integers as polynomials.
				//const int value1 = 5;
				//const int value2 = -7;
				//BigPoly encoded1 = encoder.encode(value1);
				//BigPoly encoded2 = encoder.encode(value2);
				//cout << "Encoded " << value1 << " as polynomial " << encoded1.to_string() << endl;
				//cout << "Encoded " << value2 << " as polynomial " << encoded2.to_string() << endl;
                goto CLEANUP;
            }

			// In this example we demonstrate using some of the basic arithmetic operations on integers.	
        }
        //fprintf(OUTPUT, "\nSecret successfully received from server.");
       // fprintf(OUTPUT, "\nRemote attestation success!\n");

		//cout<<"Size of ciphertxt payload"<<sizeof(p_att_result_msg_body->secret.payload)<<"\n";

		//cout<<p_att_result_msg_body->secret.payload_size;

		//cout<<"Remote success \n";


		//SEAL TEST

		//Crypto settings
		EncryptionParameters parms;
		parms.poly_modulus() = "1x^1024 + 1";
		parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
		parms.plain_modulus() = 1 << 8;

		parms.decomposition_bit_count() = 32;

		parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();

		parms.noise_max_deviation() = 5 * parms.noise_standard_deviation();


		//BalancedEncoder encoder(parms.plain_modulus());
		BalancedFractionalEncoder encoder(parms.plain_modulus(), parms.poly_modulus(), 128, 64);


		KeyGenerator generator(parms);

		generator.generate();

		
		EvaluationKeys evaluation_keys = generator.evaluation_keys();
		Evaluator evaluator(parms, evaluation_keys);
		

		cout << "secret key coeff count" << generator.secret_key().coeff_count() << endl;
		cout << "secret key coeff bit count" << generator.secret_key().coeff_bit_count() << endl;
		cout << "secret Key Length" << strlen(generator.secret_key().to_string().c_str()) << endl;


		std::ifstream in2("aa");
		std::string line;
		const int nrows = 270;
		const int ncols = 4;

		clock_t beginLR = clock();

		//Matrix features(270, Row(3));
		//Matrix predictor(270, Row(1));
		vector<vector<BigPoly>> features;
		vector<BigPoly> predictor;
		
		//BigPoly features[270][3];
		//BigPoly predictor[270][1];
		vector<BigPoly> row;

		/*
		if (in2.is_open()) {
			cout << "Opened \n";
			for (int row1 = 0; row1 < nrows; row1++)
			{
				row.push_back(BigPoly(encryptor.encrypt(encoder.encode(1))));
				for (int col1 = 0; col1 < ncols; col1++)
				{
					std::string str_item = "";
					in2 >> str_item;
					//printf("str_item \n");
					if (col1 == ncols-1)
					{
						BigPoly predPoly = BigPoly(1025, 91, ReplaceAll(str_item, std::string("+"), std::string(" + ")));
						//cout << "Created Poly coeff count" << predPoly.coeff_count() << endl;
						predictor.push_back(predPoly);
						//cout << "vector poly coeff count" << predictor.back().coeff_count();
						//cout << "col " << col1;
						
					}
					else
					{
						BigPoly featPoly = BigPoly(1025, 91, ReplaceAll(str_item, std::string("+"), std::string(" + ")));
						//cout << "Created Poly coeff count"<< featPoly.coeff_count() << endl;
						row.push_back(featPoly);
						
					}

				}
				features.push_back(row);
				cout << " Row size" << row.size() << endl;

				row.clear();
				//printf("*");
				cout << row1 << " ";

			}
			in2.close();
		}
		else {
			cout << "could not open \n";
		}
		*/
		int maxIterations = 25;
		double epsilon = 0.01; // stop if all new beta values change less than epsilon (algorithm has converged?)
		double jumpFactor = 1000.0; // stop if any new beta jumps too much (algorithm spinning out of control?)
		vector<vector<BigPoly>>::iterator fIt;
		vector<BigPoly>::iterator frowIt;
		//Beta
		double oldBeta[ncols] = {0};
		Eigen::MatrixXd oldBetaM(ncols, 1);
		oldBetaM.fill(0);

		double Beta[ncols];
		Eigen::MatrixXd BetaM(ncols, 1);
		BetaM.fill(0);

		Site site1, site2;
		site1 = Site(135, 4, generator.public_key(), 1);
		site2 = Site(135, 4, generator.public_key(), 2);

		vector<vector<BigPoly>> Xt_Xtilde_vector_site1;
		vector<vector<BigPoly>> Xt_Xtilde_vector_site2;
		vector<vector<BigPoly>> Xt_Xtilde_vector_HE_sum;

		vector<BigPoly> Xt_Y_P_vector_site1;
		vector<BigPoly> Xt_Y_P_vector_site2;
		vector<BigPoly> Xt_Y_P_vector_HE_sum;
	


		for (size_t m = 0; m < maxIterations; m++)
		{
			printf("In iteration of isv_app \n");
			Xt_Xtilde_vector_site1 = site1.GetEncrptedXt_Xtilde();
			Xt_Xtilde_vector_site2 = site2.GetEncrptedXt_Xtilde();

			Xt_Y_P_vector_site1 = site1.GetEncrptedXt_Y_P();
			Xt_Y_P_vector_site2 = site2.GetEncrptedXt_Y_P();

			//HE sum
			row.clear();
			for (size_t i = 0; i < ncols; i++)
			{
				//printf("inside xt_Xtilde HE sum \n");
				for (size_t j = 0; j < ncols; j++)
				{
					row.push_back(evaluator.add(Xt_Xtilde_vector_site1[i].at(j), Xt_Xtilde_vector_site2[i].at(j)));
					//printf("Xt Xtilde HE 1st %f \n", encoder.decode(decryptor.decrypt(Xt_Xtilde_vector_site1[i].at(j))));
					//printf("Xt Xtilde HE 2nd %f \n", encoder.decode(decryptor.decrypt(Xt_Xtilde_vector_site2[i].at(j))));
					//printf("Xt Xtilde HE sum %f \n", encoder.decode(decryptor.decrypt(evaluator.add(Xt_Xtilde_vector_site1[i].at(j), Xt_Xtilde_vector_site2[i].at(j)))));
				}
				Xt_Xtilde_vector_HE_sum.push_back(row);
				row.clear();
			}


			for (size_t i = 0; i < ncols; i++)
			{
				Xt_Y_P_vector_HE_sum.push_back(evaluator.add(Xt_Y_P_vector_site1.at(i), Xt_Y_P_vector_site2.at(i)));
			}

			//transfer both sum matrixes to the enclave
			for (fIt = Xt_Xtilde_vector_HE_sum.begin(); fIt != Xt_Xtilde_vector_HE_sum.end(); ++fIt)
			{
				for (frowIt = (*fIt).begin(); frowIt != (*fIt).end(); ++frowIt)
				{
					char* matrixEntry = new char[strlen((*frowIt).to_string().c_str()) + 1];
					matrixEntry = (char*)malloc(strlen((*frowIt).to_string().c_str()) + 1);
					strcpy(matrixEntry, (*frowIt).to_string().c_str());
					char* hweResult = new char[2];

					transferMatrix(enclave_id, matrixEntry, hweResult, strlen((*frowIt).to_string().c_str()) + 1, 2);
					cout << hweResult << endl;

					cout << "Back from  hwe enclave " << hweResult << endl;
					free(matrixEntry);
					free(hweResult);
				}

			}

			for (frowIt = Xt_Y_P_vector_HE_sum.begin(); frowIt != Xt_Y_P_vector_HE_sum.end(); ++frowIt)
			{

				char* XtYmatrixEntry = new char[strlen((*frowIt).to_string().c_str()) + 1];
				XtYmatrixEntry = (char*)malloc(strlen((*frowIt).to_string().c_str()) + 1);
				strcpy(XtYmatrixEntry, (*frowIt).to_string().c_str());
				//char* XtYResult = new char[2];

				transferMatrixXtY(enclave_id, XtYmatrixEntry, Beta, strlen((*frowIt).to_string().c_str()) + 1);
				//cout << XtYResult << endl;

				cout << "Back from  XtYmAtrixTransfer enclave " << endl;
				free(XtYmatrixEntry);
				//free(XtYResult);

			}

			
			//load Beta Matrix
			for (size_t k = 0; k < ncols; k++)
			{
				printf("in beta load \n");
				BetaM(k, 0) = Beta[k];

			}
			//check conditions for NoChange and OutofControl
			if (NoChange(oldBetaM, BetaM, epsilon) || OutOfControl(oldBetaM, BetaM, jumpFactor))
			{
				printf("in condition check \n");
				break;
			}

			//store Beta to oldBeta for later use
			printf(" assigning beta to oldbeta\n");
			oldBetaM = BetaM;

			printf(" call 1 st update beta\n");
			site1.updateBeta(Beta);

			printf("call 2nd update beta \n");
			site2.updateBeta(Beta);

			printf("%d th iteration \n", m);

			Xt_Xtilde_vector_site1.clear();
			Xt_Xtilde_vector_site2.clear();
			Xt_Xtilde_vector_HE_sum.clear();

			Xt_Y_P_vector_site1.clear();
			Xt_Y_P_vector_site2.clear();
			Xt_Y_P_vector_HE_sum.clear();

		}

		printf("printing output \n");
		for (size_t i = 0; i < oldBetaM.rows(); i++)
		{
			printf("%f \n", oldBetaM(i, 0));
		}
		


	clock_t endLR = clock();

	double elapsed_secs = double(endLR - beginLR) / CLOCKS_PER_SEC;
	cout << "time required for LR " << elapsed_secs << endl;

	

	

	//string strArray[2][3];



    /*
	//values for CATT calculation containing case control data
	char*** cattValues = new char**[2];
	cattValues[0] = new char*[2];
	cattValues[1] = new char*[2];
	cout << "initializing first row first column" << endl;
	//cattValues[0][0] = (char*)malloc(strlen(generator.secret_key().to_string().c_str()) + 1);
	//strcpy(cattValues[0][0], generator.secret_key().to_string().c_str());
	cattValues[0][0] = (char*)generator.secret_key().to_string().c_str();

	cout << "initializing first row second column" << endl;

	//cattValues[0][1] = (char*)malloc(strlen(XtY.front().to_string().c_str()) + 1);
	//strcpy(cattValues[0][1], XtY.front().to_string().c_str());
	cattValues[0][1] = (char*)XtY.front().to_string().c_str();

	cout << "initializing second row first column" << endl;

	//cattValues[1][0] = (char*)malloc(strlen(XtY.back().to_string().c_str()) + 1);
	//strcpy(cattValues[1][0], XtY.back().to_string().c_str());
	cattValues[1][0] = (char*)XtY.back().to_string().c_str();

	cout << "initializing second row second column" << endl;

	//cattValues[1][1] = (char*)malloc(strlen(XtY.back().to_string().c_str()) + 1);
	//strcpy(cattValues[1][1], XtY.back().to_string().c_str());
	cattValues[1][1] = (char*)XtY.back().to_string().c_str();

	int cattSize = strlen(generator.secret_key().to_string().c_str()) + 1 + strlen(XtY.front().to_string().c_str()) + 1
		+ strlen(XtY.back().to_string().c_str()) + 1 + strlen(XtY.back().to_string().c_str()) + 1;



	char* cattResult = new char[2];
	cout << "calling CATT encalve" << endl;
	catt(enclave_id, cattValues, cattResult, 111000, 2);
	cout << "Back from  catt enclave " << result << endl;

	*/


    }
    

CLEANUP:
    // Clean-up
    // Need to close the RA key state.
    if(INT_MAX != context)
    {
        int ret_save = ret;
        ret = enclave_ra_close(enclave_id, &status, context);
        if(SGX_SUCCESS != ret || status)
        {
            ret = -1;
            //fprintf(OUTPUT, "\nError, call enclave_ra_close fail [%s].",
                    //__FUNCTION__);
        }
        else
        {
            // enclave_ra_close was successful, let's restore the value that
            // led us to this point in the code.
            ret = ret_save;
        }
        //fprintf(OUTPUT, "\nCall enclave_ra_close success.");
    }

    //sgx_destroy_enclave(enclave_id);
	if(SGX_SUCCESS != sgx_destroy_enclave(enclave_id)){
		cout<<"Cannot destroy Enclave"<<endl;
		return -1;
	}
	

    ra_free_network_response_buffer(p_msg0_resp_full);
    ra_free_network_response_buffer(p_msg2_full);
    ra_free_network_response_buffer(p_att_result_msg_full);

    //p_msg3 is malloc'd by the untrusted KE library. App needs to free.
    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg0_full);


	//time_t afterLD;
	//time(&afterLD);

	//double seconds1 = difftime(afterLD , beforeLD);

	//printf("\n   %f \n", seconds1);

	//std::chrono::system_clock::time_point afterRA = std::chrono::system_clock::now();
	//std::chrono::milliseconds timeRA = std::chrono::duration_cast<std::chrono::milliseconds>(afterA - beforeA);
    //cout <<"Using chrono time required"<< (float)timeRA.count() << "ms\n";





    //printf("\nEnter a character before exit ...\n");
    //getchar();
    return ret;
}

