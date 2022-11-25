# Copyright 2022 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

default: run

# If the header has not been generated, then we need to 'cargo build' the root workspace
../../veraison_client_wrapper.h:
	pushd ../../.. && cargo build && popd

challenge_response.o: challenge_response.c ../../veraison_client_wrapper.h
	$(CC) $(CFLAGS) -c -I../.. challenge_response.c

challenge-response: challenge_response.o
	$(CC) $(CFLAGS) -o challenge-response challenge_response.o  ../../../target/debug/libveraison_apiclient_ffi.a $(LDFLAGS) $(LDLIBS)

run: challenge-response
	RUST_LOG=info ./challenge-response

clean:
	rm -rf challenge-response challenge_response.o
