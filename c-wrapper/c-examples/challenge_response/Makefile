# Copyright 2022 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

default: run

# If the header has not been generated, then we need to 'cargo build' the root workspace
../../veraison_client_wrapper.h:
	pushd ../../.. && cargo build && popd

challenge_response.o: challenge_response.c ../../veraison_client_wrapper.h
	gcc -Wall -c -I../.. challenge_response.c

challenge-response: challenge_response.o
	gcc -Wall -o challenge-response challenge_response.o  ../../../target/debug/libveraison_apiclient_ffi.a -framework Security -framework CoreFoundation -liconv -lSystem -lresolv -lc -lm -liconv

run: challenge-response
	RUST_LOG=info ./challenge-response

clean:
	rm -rf challenge-response challenge_response.o
