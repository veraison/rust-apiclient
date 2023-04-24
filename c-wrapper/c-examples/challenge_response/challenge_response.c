// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "veraison_client_wrapper.h"

int main(int argc, char *argv[])
{
    // Change the example below to the base URL for where the Veraison verifier is
    // running.
    const char *base_url = "http://localhost:8080";

    VeraisonVerificationApi *verification_api = NULL;
    char new_session_endpoint[PATH_MAX] = {0};
    ChallengeResponseSession *session = NULL;
    const unsigned char my_evidence[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    VeraisonResult status;
    size_t i;

    // Discover the verification API details from the service base URL.
    status = veraison_get_verification_api(base_url, &verification_api);

    if (status != Ok)
    {
        printf("Failed to discover the verification API from %s\n", base_url);
        goto cleanup;
    }

    // Display some useful details from the discovery step.
    printf("Discovered Veraison verification API at %s\n", base_url);
    printf("The public key for verification: %s\n", verification_api->public_key_pem);
    printf("The signature algorithm: %s\n", verification_api->algorithm);
    printf("The available API endpoints:\n");

    // Display the individual API endpoints, and capture the "newChallengeResponseSession"
    // endpoint, which will be used in the next step.
    for (i = 0; i < verification_api->endpoint_count; i++)
    {
        printf("    %s: %s\n",
               verification_api->endpoint_list[i].name,
               verification_api->endpoint_list[i].path);

        if (strcmp(verification_api->endpoint_list[i].name, "newChallengeResponseSession") == 0)
        {
            // This is the endpoint that we want to use to make a challenge-response session,
            // so concatenate this with the base_url.
            snprintf(new_session_endpoint,
                     sizeof(new_session_endpoint),
                     "%s%s",
                     base_url,
                     verification_api->endpoint_list[i].path);
        }
    }
    
    printf("The supported media types:\n");

    for (i = 0; i < verification_api->media_type_count; i++)
    {
        printf("    %s\n", verification_api->media_type_list[i]);
    }

    if (strlen(new_session_endpoint) == 0)
    {
        printf("Failed to locate a newChallengeResponseSession entry in the endpoint list.\n");
        goto cleanup;
    }

    // Now run the challenge response session, using the discovered endpoint.
    status = open_challenge_response_session(
        new_session_endpoint,
        32,
        NULL,
        &session);

    if (status != Ok)
    {
        printf("Failed to allocate Veraison client session.\n");
        goto cleanup;
    }

    printf("Opened new Veraison client session at %s\n", session->session_url);
    printf("Number of media types accepted: %d\n", (int)session->accept_type_count);
    for (i = 0; i < session->accept_type_count; i++)
    {
        printf("    %s\n", session->accept_type_list[i]);
    }
    printf("Nonce size: %d bytes\n", (int)session->nonce_size);
    printf("Nonce: [");
    for (i = 0; i < session->nonce_size; i++)
    {
        if (i > 0)
        {
            printf(", ");
        }
        printf("0x%x", session->nonce[i]);
    }
    printf("]\n");

    if (session->accept_type_count == 0)
    {
        printf("There are no accepted media types, hence not supplying evidence.\n");
        goto cleanup;
    }

    printf("Supplying evidence to server.\n");

    // Supply our evidence.
    status = challenge_response(
        session,
        sizeof(my_evidence),
        my_evidence,
        session->accept_type_list[0]);

    if (status != Ok)
    {
        printf("Failed to supply evidence to server.\n");
        goto cleanup;
    }

    // And, finally, display the server's response, which will be a JWT containing an EAR.
    printf("Raw attestation result string from server: %s\n", session->attestation_result);

cleanup:
    if (session != NULL)
    {
        if (session->message != NULL)
        {
            printf("Error/log message: %s\n", session->message);
        }
        printf("Disposing client session.\n");
        free_challenge_response_session(session);
    }

    if (verification_api != NULL)
    {
        veraison_free_verification_api(verification_api);
    }

    printf("Done!\n");
    return (int)status;
}
