// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{c_void, CStr, CString};

use core::slice;

use veraison_apiclient::{ChallengeResponse, ChallengeResponseBuilder, Error, Nonce};

/// This structure represents an active challenge-response API session.
///
/// Instances of this structure are obtained from the [`open_challenge_response_session()`] function,
/// and must always be disposed using [`free_challenge_response_session()].
///
/// The fields in this structure are read-only. The pointers provide access to data that is being
/// made visible to C client code, but is managed internally with Rust data structures. The pointers
/// are safe for C code to dereference and read, but not to mutate or retain beyond the lifetime
/// of the client session.
#[repr(C)]
pub struct ChallengeResponseSession {
    /// Pointer to a NUL-terminated string containing the session URL.
    ///
    /// C client code would normally not need to use this string, except perhaps for logging
    /// purposes, since the [`challenge_response()`] function takes the entire structure as input,
    /// rather than just the URL.
    ///
    /// A typical example value of this string would be
    /// `http://veraison.example.com/challenge-response/v1/session/12345678`.
    ///
    /// If the session is not established successfully (in other words, if
    /// the [`open_challenge_response_session()`] function called returned an error code, then
    /// this pointer will be NULL.
    session_url: *const libc::c_char,

    /// The number of bytes in the nonce challenge.
    nonce_size: libc::size_t,

    /// A pointer to the data buffer containing the nonce challenge bytes. This data buffer will
    /// contain a copy of the bytes that were passed to [`open_challemge_response_session()`] if
    /// they were specified. Otherwise, it will contain the nonce challenge bytes that were issued
    /// by the Veraison service.
    ///
    /// If the session is not established successfully (in other words, if
    /// the [`open_challenge_response_session()`] function called returned an error code, then
    /// this pointer will be NULL.
    nonce: *const u8,

    /// The number of accepted media types for evidence.
    accept_type_count: libc::size_t,

    /// An array of NUL-terminated strings specifying the accepted media types. Each string will be
    /// a valid IANA media type string according to [RFC6838](https://www.rfc-editor.org/rfc/rfc6838.html).
    /// An example would be `application/psa-attestation-token`.
    ///
    /// If the session is not established successfully (in other words, if
    /// the [`open_challenge_response_session()`] function called returned an error code, then
    /// this pointer will be NULL.
    accept_type_list: *const *const libc::c_char,

    /// A pointer to a NUL-terminated string containing the raw attestation result evidence that was
    /// received from the server.
    ///
    /// This pointer is only valid following a successful call to [`challenge_response()`].
    attestation_result: *const libc::c_char,

    /// A pointer to a NUL-terminated text string containing a logging/error message from the most
    /// recent operation.
    ///
    /// This pointer can be NULL when operations succeed or otherwise do not issue any logging
    /// or error messages. Always check for NULL before dereferencing this pointer. Non-NULL pointers
    /// are always valid pointers to NUL-terminated strings.
    message: *const libc::c_char,

    /// This field is a reserved pointer to Rust-managed data and must not be used by C client
    /// code.
    session_wrapper: *mut c_void,
}

/// C-compatible enum representation of the error enum from the Rust client.
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum VeraisonResult {
    Ok = 0,
    ConfigError,
    ApiError,
    CallbackError,
    NotImplementedError,
}

/// This structure contains the Rust-managed objects that are behind the raw pointers sent back to C
/// world. This structure is not visible to C other than as an opaque (void*) pointer. Think of it as
/// being like the private part of a public/private interface.
struct ShimChallengeResponseSession {
    client: Box<Option<ChallengeResponse>>,
    session_url_cstring: CString,
    nonce_vec: Vec<u8>,
    accept_type_cstring_vec: Vec<CString>,
    accept_type_ptr_vec: Vec<*const libc::c_char>,
    attestation_result_cstring: CString,
    message_cstring: CString,
}

/// Establish a new challenge-response API session with the server at the given
/// base URL, using the supplied nonce configuration.
///
/// The base URL needs to be the URL of a challenge-response API endpoint, such as
/// `http://veraison.example.com/challenge-response/v1/`.
///
/// There are two valid nonce configurations. If the client wishes to specify
/// the nonce bytes, then it should allocate a memory buffer of the required
/// size, and set both `nonce_size` and `nonce` to the size and base pointer of
/// the buffer respectively. The alternative configuration is to instruct the server
/// to issue the nonce challenge instead. In this case, there is only a need to
/// specify `nonce_size` in this function call, and the `nonce` argument must be
/// a NULL pointer. To allow the server to choose the nonce size as well, then set
/// `nonce_size` to zero.
///
/// Upon return from this function, `out_session` receives a pointer to a
/// [`ChallengeResponseSession`] structure. If the function succeexs, this structure
/// will be populated with the enough information to run the [`challenge_response()`]
/// function. If the function fails, the structure will still be valid, but only
/// partially populated. In the failing case, it will not be possible to run the
/// [`challenge_response()`] function with this structure. Instead, the `message` field
/// can be used to obtain any logging/error message.
///
/// To avoid memory or resource leaks, the caller **must** dispose of the structure
/// by passing it to [`free_challenge_response_session()`] after it is no longer
/// needed.
///
/// # Safety
///
/// It is the caller's reponsibility to ensure that `base_url`:
///
/// - is not a null pointer
/// - points to valid, initialized data
/// - points to memory ending in a null byte
/// - won't be mutated for the duration of this function call
///
/// It is the caller's responsibility to ensure that `nonce` is:
///
/// - **EITHER** a null pointer (in which case the nonce challenge is issued on
/// the server side)
/// - **OR** a pointer to a valid buffer of initialized data of at
/// least `nonce_size` bytes, which will not be mutated for the duration
/// of this function call.
///
/// It is the caller's responsibility to ensure that `out_session` is
/// not a null pointer.
#[no_mangle]
pub unsafe extern "C" fn open_challenge_response_session(
    base_url: *const libc::c_char,
    nonce_size: libc::size_t,
    nonce: *const u8,
    out_session: *mut *mut ChallengeResponseSession,
) -> VeraisonResult {
    // We have to trust the caller's char* ptr.
    let url_str: &str = {
        let url_cstr = CStr::from_ptr(base_url);
        url_cstr.to_str().unwrap()
    };

    // Make a Nonce variant according to the given nonce_size and nonce arguments. If the nonce is null,
    // this implies the Nonce::Size() variant, otherwise it's the Nonce::Value() variant.
    let nonce_converted: Nonce = {
        if nonce.is_null() {
            // Null pointer implies a request for the server to generate the nonce
            // of the given size. The size is also permitted to be zero, in which case
            // the server will choose the size as well as generating the nonce.
            Nonce::Size(nonce_size)
        } else {
            // Non-null pointer means we are making a Nonce::Value variant of the
            // given size. We have to trust the caller's pointer here.
            let bytes = slice::from_raw_parts(nonce, nonce_size);
            Nonce::Value(Vec::from(bytes))
        }
    };

    // Establish the client session.
    let cr = ChallengeResponseBuilder::new()
        .with_base_url(String::from(url_str))
        .build();

    // Early return on error. The idiom here is slightly odd, and it arguably would be better to use
    // is_err() and expect_err(), but these require the underlying types to implement the Debug trait,
    // which they don't.
    match cr {
        Ok(_) => {}
        Err(e) => {
            // Early return with a stub session containing the error message.
            return stub_session_from_error(&e, out_session);
        }
    }

    // This now won't panic because we dealt with errors by early return above.
    let cr = cr.unwrap();

    let newsession = cr.new_session(&nonce_converted);

    match newsession {
        Ok(_) => {}
        Err(e) => {
            // Early return with a stub session containing the error message.
            return stub_session_from_error(&e, out_session);
        }
    }

    // This now won't panic because we dealt with errors by early return above.
    let (session_uri, session) = newsession.unwrap();

    let session_nonce = session.nonce().to_vec();
    let session_accept_types = session.accept().to_vec();

    // Map the Rust Strings to CString objects for the accept types.
    let media_type_cstrings = session_accept_types
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    // Make the ShimChallengeResponse session, which houses the Rust-compatible objects in order to manage
    // their memory in Rust world. This object is not visible to C world other than as an opaque pointer
    // that can be recovered later.
    let mut shim_session = ShimChallengeResponseSession {
        client: Box::new(Some(cr)),
        session_url_cstring: CString::new(session_uri.as_str()).unwrap(),
        nonce_vec: session_nonce,
        accept_type_cstring_vec: media_type_cstrings,
        accept_type_ptr_vec: Vec::with_capacity(session_accept_types.len()),
        attestation_result_cstring: CString::new("").unwrap(),
        message_cstring: CString::new("").unwrap(),
    };

    // Get the ptr (char*) for each CString and also store that in a Rust-managed Vec.
    for s in &shim_session.accept_type_cstring_vec {
        shim_session.accept_type_ptr_vec.push(s.as_ptr())
    }

    // Now make the ShimRawChallengeResponseSession, which houses the C-compatible types and is the structure
    // that C world sees. It is made out of interior pointers into the Rust data structure above.
    let raw_shim_session = Box::new(ChallengeResponseSession {
        session_url: shim_session.session_url_cstring.as_ptr(),
        nonce_size: shim_session.nonce_vec.len(),
        nonce: shim_session.nonce_vec.as_ptr(),
        accept_type_count: shim_session.accept_type_ptr_vec.len(),
        accept_type_list: shim_session.accept_type_ptr_vec.as_ptr(),
        // The attestation result is not known at this stage - it gets populated later.
        attestation_result: std::ptr::null(),
        // No message at this point
        message: std::ptr::null(),
        // Use Box::into_raw() to "release" the Rust memory so that the pointers all remain valid.
        session_wrapper: Box::into_raw(Box::new(shim_session)) as *mut c_void,
    });

    // Finally, use Box::into_raw() again for the raw session, so that Rust doesn't dispose it when it
    // drops out of scope.
    // C world will pass this pointer back to us in free_challenge_response_session(), at which point
    // we do Box::from_raw() to bring the memory back under Rust management.
    let session_ptr = Box::into_raw(raw_shim_session);
    *out_session = session_ptr;

    VeraisonResult::Ok
}

/// Execute a synchronous challenge-response operation using the given session and supplying evidence
/// of the given media type in order to obtain an attestation result from the server.
///
/// The `media_type` string must match one of the accepted media types as denoted by the list in
/// [`ChallengeResponseSession::accept_type_list`]. It is valid to directly use one of the string
/// pointers from that list if it is convenient to do so. However, it is also valid to pass a pointer
/// to a caller-allocated string, provided that its contents evaluates to one of the accepted types.
///
/// # Safety
///
/// The caller guarantees the following:
///
/// - The `session` parameter is a non-NULL pointer to a valid structure that was received from a prior
/// successful call to [`open_challenge_response_session()`]. Do not call this function with a NULL
/// pointer or a pointer to uninitialized data. Also do not call this function with a pointer to a
/// failed session.
/// - The `evidence` parameter is not NULL, and points to a valid data buffer of at least `evidence_size`
/// bytes that will not be mutated for the duration of this function call.
/// - The `media_type` parameter is a non-NULL pointer to a valid NUL-terminated character string that
/// will not be mutated for the duration of this function call.
#[no_mangle]
pub unsafe extern "C" fn challenge_response(
    session: *mut ChallengeResponseSession,
    evidence_size: libc::size_t,
    evidence: *const u8,
    media_type: *const libc::c_char,
) -> VeraisonResult {
    // Need to trust the caller's pointer
    let mut raw_session = Box::from_raw(session);

    let mut shim_session =
        Box::from_raw(raw_session.session_wrapper as *mut ShimChallengeResponseSession);

    // Need to trust the caller's pointer
    let media_type_str: &str = {
        let url_cstr = CStr::from_ptr(media_type);
        url_cstr.to_str().unwrap()
    };

    // Need to trust the caller's pointer and size
    let evidence_bytes = slice::from_raw_parts(evidence, evidence_size);

    // Actually call the client
    let client_result = match shim_session.client.as_ref() {
        Some(client) => client.challenge_response(
            evidence_bytes,
            media_type_str,
            shim_session.session_url_cstring.to_str().unwrap(),
        ),
        // If we have no client, it means that the session was never properly established in the first place.
        None => Err(Error::ConfigError(
            "Cannot supply evidence because there is no session endpoint.".to_string(),
        )),
    };

    let returncode = match client_result {
        Ok(attestation_result) => {
            shim_session.attestation_result_cstring = CString::new(attestation_result).unwrap();
            raw_session.attestation_result = shim_session.attestation_result_cstring.as_ptr();
            VeraisonResult::Ok
        }
        Err(e) => {
            let (shimresult, message) = translate_error(&e);
            // Move the message CString into the ShimSession, and its corresponding pointer into the raw
            // session so that C code can consume it.
            shim_session.message_cstring = message;
            raw_session.message = shim_session.message_cstring.as_ptr();
            shimresult
        }
    };

    // Release the raw pointers again
    let _ = Box::into_raw(shim_session);
    let _ = Box::into_raw(raw_session);

    returncode
}

/// Completely dispose of all client-side memory and resources associated with the given
/// challenge-response session.
///
/// Upon exit from this function, the given pointer should be assumed no longer valid.
///
/// Note: This is a client-side operation only. It does not close the session on the server. The server
/// is independently responsible for disposing of the session when it expires.
///
/// # Safety
/// The caller must guarantee that the `session` pointer is a non-NULL pointer to a valid session
/// that was previously output from a call to [`open_challenge_response_session()`].
#[no_mangle]
pub unsafe extern "C" fn free_challenge_response_session(session: *mut ChallengeResponseSession) {
    // Just re-box the session and let Rust drop it all automatically.
    let raw_session = Box::from_raw(session);
    let _ = Box::from_raw(raw_session.session_wrapper as *mut ShimChallengeResponseSession);
}

// This function is used when there is an error while attempting to create the session - either because the
// [ChallengeResponseBuilder::build()] method call failed, or because [ChallengeResponse::new_session()] failed.
// In either case, we stub out an empty session containing just the error message.
fn stub_session_from_error(
    e: &Error,
    out_session: *mut *mut ChallengeResponseSession,
) -> VeraisonResult {
    // Get the error code and message by matching on the error type
    let (returncode, message) = translate_error(e);

    // Create a degenerate/stub session object to represent the failure to establish the session. Most
    // values are none/empty degnerate (but safe) placeholders.
    let shim_session = ShimChallengeResponseSession {
        client: Box::new(None),
        session_url_cstring: CString::new("").unwrap(),
        nonce_vec: Vec::new(),
        accept_type_cstring_vec: Vec::new(),
        accept_type_ptr_vec: Vec::new(),
        attestation_result_cstring: CString::new("").unwrap(),
        // This is the only meaningful field, because we have gleaned an error message.
        message_cstring: message,
    };

    // Wrap to C-compatible structure
    let raw_shim_session = Box::new(ChallengeResponseSession {
        session_url: shim_session.session_url_cstring.as_ptr(),
        nonce_size: shim_session.nonce_vec.len(),
        nonce: shim_session.nonce_vec.as_ptr(),
        accept_type_count: shim_session.accept_type_ptr_vec.len(),
        accept_type_list: shim_session.accept_type_ptr_vec.as_ptr(),
        attestation_result: std::ptr::null(),
        message: shim_session.message_cstring.as_ptr(),
        // Use Box::into_raw() to "release" the Rust memory so that the pointers all remain valid.
        session_wrapper: Box::into_raw(Box::new(shim_session)) as *mut c_void,
    });

    // Finally, use Box::into_raw() again for the raw session, so that Rust doesn't dispose it when it
    // drops out of scope.
    // C world will pass this pointer back to us in free_challenge_response_session(), at which point
    // we do Box::from_raw() to bring the memory back under Rust management.
    let session_ptr = Box::into_raw(raw_shim_session);
    unsafe { *out_session = session_ptr };

    returncode
}

// Map a rust client Error variant to a pair of C-compatible ShimResult enum value plus error message as
// CString object.
fn translate_error(e: &Error) -> (VeraisonResult, CString) {
    match e {
        Error::ConfigError(s) => (
            VeraisonResult::ConfigError,
            CString::new(s.clone()).unwrap(),
        ),
        Error::ApiError(s) => (VeraisonResult::ApiError, CString::new(s.clone()).unwrap()),
        Error::CallbackError(s) => (
            VeraisonResult::CallbackError,
            CString::new(s.clone()).unwrap(),
        ),
        Error::NotImplementedError(s) => (
            VeraisonResult::NotImplementedError,
            CString::new(s.clone()).unwrap(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[async_std::test]
    async fn ffi_challenge_response_session_ok() {
        let mock_server = MockServer::start().await;
        let session_waiting = r#"
        {
            "nonce": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            "expiry": "2030-10-12T07:20:50.52Z",
            "accept": [
                "application/psa-attestation-token",
                "application/vnd.1",
                "application/vnd.2",
                "application/vnd.3"
            ],
            "status": "waiting"
        }"#;
        let session_complete = r#"
        {
            "nonce": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            "expiry": "2030-10-12T07:20:50.52Z",
            "accept": [
                "application/psa-attestation-token",
                "application/vnd.1",
                "application/vnd.2",
                "application/vnd.3"
            ],
            "status": "complete",
            "evidence": {
                "type": "application/psa-attestation-token",
                "value": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
            },
            "result": "a.b.c"
        }"#;

        let response = ResponseTemplate::new(201)
            .insert_header("Location", "/session/1234")
            .set_body_string(session_waiting)
            .insert_header(
                "Content-Type",
                "application/vnd.veraison.challenge-response-session+json",
            );

        Mock::given(method("POST"))
            .and(path("/newSession"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let mut session: *mut ChallengeResponseSession = std::ptr::null_mut();

        let base_uri = CString::new(mock_server.uri()).unwrap();

        // Call as if from C
        let result = unsafe {
            open_challenge_response_session(base_uri.as_ptr(), 32, std::ptr::null(), &mut session)
        };

        // We should have an Ok result
        assert_eq!(result, VeraisonResult::Ok);

        // Sanity-check session fields
        unsafe {
            assert_ne!((*session).session_url, std::ptr::null());
            assert_eq!((*session).nonce_size, 32);
            assert_ne!((*session).nonce, std::ptr::null());
            assert_eq!((*session).accept_type_count, 4);
            assert_ne!((*session).accept_type_list, std::ptr::null());
            assert_eq!((*session).attestation_result, std::ptr::null());
        }

        // Prepare the mock for the next call
        let response = ResponseTemplate::new(200)
            .set_body_string(session_complete)
            .insert_header(
                "Content-Type",
                "application/vnd.veraison.challenge-response-session+json",
            );
        Mock::given(method("POST"))
            .and(path("/session/1234"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let evidence_value: Vec<u8> = vec![0, 1];
        let media_type = CString::new("application/psa-attestation-token").unwrap();

        let result = unsafe {
            challenge_response(
                session,
                evidence_value.len(),
                evidence_value.as_ptr(),
                media_type.as_ptr(),
            )
        };

        // We should have an Ok result
        assert_eq!(result, VeraisonResult::Ok);

        // Dispose
        unsafe { free_challenge_response_session(session) };
    }
}
