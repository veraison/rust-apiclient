// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "veraison_client_wrapper.h"

int main(int argc, char *argv[])
{
    ChallengeResponseSession *session = NULL;
    const unsigned char my_evidence[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    VeraisonResult status;
    size_t i;

    status = open_challenge_response_session(
        "http://localhost:8080/challenge-response/v1/",
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
    printf("Done!\n");
    return (int)status;
}
