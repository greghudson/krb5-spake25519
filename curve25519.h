/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_CURVE25519_H
#define OPENSSL_HEADER_CURVE25519_H

#include <stddef.h>
#include <stdint.h>
#define OPENSSL_EXPORT
typedef struct spake2_ctx_st SPAKE2_CTX;

#if defined(__cplusplus)
extern "C" {
#endif


/* Curve25519.
 *
 * Curve25519 is an elliptic curve. See https://tools.ietf.org/html/rfc7748. */


/* SPAKE2.
 *
 * SPAKE2 is a password-authenticated key-exchange. It allows two parties,
 * who share a low-entropy secret (i.e. password), to agree on a shared key.
 * An attacker can only make one guess of the password per execution of the
 * protocol.
 *
 * See https://tools.ietf.org/html/draft-irtf-cfrg-spake2-02. */

/* spake2_role_t enumerates the different “roles” in SPAKE2. The protocol
 * requires that the symmetry of the two parties be broken so one participant
 * must be “Alice” and the other be “Bob”. */
enum spake2_role_t {
  spake2_role_alice,
  spake2_role_bob,
};

/* SPAKE2_CTX_new creates a new |SPAKE2_CTX| (which can only be used for a
 * single execution of the protocol). SPAKE2 requires the symmetry of the two
 * parties to be broken which is indicated via |my_role| – each party must pass
 * a different value for this argument. */
OPENSSL_EXPORT SPAKE2_CTX *SPAKE2_CTX_new(enum spake2_role_t my_role);

/* SPAKE2_CTX_free frees |ctx| and all the resources that it has allocated. */
OPENSSL_EXPORT void SPAKE2_CTX_free(SPAKE2_CTX *ctx);

/* SPAKE2_MAX_MSG_SIZE is the maximum size of a SPAKE2 message. */
#define SPAKE2_MAX_MSG_SIZE 32

/* SPAKE2_generate_msg generates a SPAKE2 message given |password|, writes
 * it to |out| and sets |*out_len| to the number of bytes written.
 *
 * At most |max_out_len| bytes are written to |out| and, in order to ensure
 * success, |max_out_len| should be at least |SPAKE2_MAX_MSG_SIZE| bytes.
 *
 * This function can only be called once for a given |SPAKE2_CTX|.
 *
 * It returns one on success and zero on error. */
OPENSSL_EXPORT int SPAKE2_generate_msg(SPAKE2_CTX *ctx, uint8_t *out,
				       const uint8_t *w);

/* SPAKE2_MAX_KEY_SIZE is the maximum amount of key material that SPAKE2 will
 * produce. */
#define SPAKE2_MAX_KEY_SIZE 64

/* SPAKE2_process_msg completes the SPAKE2 exchange given the peer's message in
 * |their_msg|, writes at most |max_out_key_len| bytes to |out_key| and sets
 * |*out_key_len| to the number of bytes written.
 *
 * The resulting keying material is suitable for:
 *   a) Using directly in a key-confirmation step: i.e. each side could
 *      transmit a hash of their role, a channel-binding value and the key
 *      material to prove to the other side that they know the shared key.
 *   b) Using as input keying material to HKDF to generate a variety of subkeys
 *      for encryption etc.
 *
 * If |max_out_key_key| is smaller than the amount of key material generated
 * then the key is silently truncated. If you want to ensure that no truncation
 * occurs then |max_out_key| should be at least |SPAKE2_MAX_KEY_SIZE|.
 *
 * You must call |SPAKE2_generate_msg| on a given |SPAKE2_CTX| before calling
 * this function. On successful return, |ctx| is complete and calling
 * |SPAKE2_CTX_free| is the only acceptable operation on it.
 *
 * Returns one on success or zero on error. */
OPENSSL_EXPORT int SPAKE2_process_msg(SPAKE2_CTX *ctx, uint8_t *out,
                                      const uint8_t *their_msg);


#if defined(__cplusplus)
}  /* extern C */

extern "C++" {

namespace bssl {

BORINGSSL_MAKE_DELETER(SPAKE2_CTX, SPAKE2_CTX_free)

}  // namespace bssl

}  /* extern C++ */

#endif

#endif  /* OPENSSL_HEADER_CURVE25519_H */
