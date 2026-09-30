/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// Coverage for ML-DSA support in moz::pkix (bug 2068282).
//
// These drive the pkixc.h C entry point rather than building certificates
// with the mozpkix test infrastructure, because that infrastructure has no
// ML-DSA key support. The certificates are pre-minted DER blobs in
// mldsa_test_certs.h; see that file for how they were produced.

#include "pkixgtest.h"

#include "mldsa_test_certs.h"
#include "mozpkix/pkixc.h"
#include "mozpkix/pkixder.h"
#include "mozpkix/pkixnss.h"
#include "secerr.h"
#include "sslerr.h"

#include <vector>

using namespace mozilla::pkix;
using namespace mozilla::pkix::test;

namespace {

// Inside the validity period of every certificate in mldsa_test_certs.h
// (2026-09-11 through 2046-09-06). 2027-01-15.
const uint64_t kSecondsSinceEpoch = 1800000000;

const char* kHostname = "example.com";

// Runs a two-certificate chain through VerifyCodeSigningCertificateChain,
// trusting `root` by its SHA-256 digest. Returns the result and reports the
// error code out of band.
bool VerifyChain(const uint8_t* endEntity, size_t endEntityLen,
                 const uint8_t* root, size_t rootLen,
                 /*out*/ PRErrorCode& error) {
  const uint8_t* certificates[] = {endEntity, root};
  const uint16_t certificateLengths[] = {static_cast<uint16_t>(endEntityLen),
                                         static_cast<uint16_t>(rootLen)};

  uint8_t rootSHA256Digest[32] = {0};
  Input rootInput;
  EXPECT_EQ(rootInput.Init(root, rootLen), Success);
  EXPECT_EQ(DigestBufNSS(rootInput, DigestAlgorithm::sha256, rootSHA256Digest,
                         sizeof(rootSHA256Digest)),
            Success);

  error = 0;
  return VerifyCodeSigningCertificateChain(
      &certificates[0], &certificateLengths[0], 2, kSecondsSinceEpoch,
      &rootSHA256Digest[0], reinterpret_cast<const uint8_t*>(kHostname),
      strlen(kHostname), &error);
}

class pkixc_mldsa_tests : public ::testing::Test {};

// Sanity check: a classical chain still verifies. This is the control for the
// DigestAlgorithm -> std::optional<DigestAlgorithm> refactor, which touches
// every RSA and ECDSA code path.
TEST_F(pkixc_mldsa_tests, ECDSAChainStillVerifies) {
  PRErrorCode error = 0;
  ASSERT_TRUE(VerifyChain(eeec_der, sizeof(eeec_der), rootec_der,
                          sizeof(rootec_der), error))
      << "unexpected error " << error;
}

// A pure ML-DSA chain: ML-DSA subjectPublicKeyInfo and ML-DSA signature, at
// each of the three parameter sets.
TEST_F(pkixc_mldsa_tests, MLDSA44Chain) {
  PRErrorCode error = 0;
  ASSERT_TRUE(VerifyChain(ee44_der, sizeof(ee44_der), root44_der,
                          sizeof(root44_der), error))
      << "unexpected error " << error;
}

TEST_F(pkixc_mldsa_tests, MLDSA65Chain) {
  PRErrorCode error = 0;
  ASSERT_TRUE(VerifyChain(ee65_der, sizeof(ee65_der), root65_der,
                          sizeof(root65_der), error))
      << "unexpected error " << error;
}

TEST_F(pkixc_mldsa_tests, MLDSA87Chain) {
  PRErrorCode error = 0;
  ASSERT_TRUE(VerifyChain(ee87_der, sizeof(ee87_der), root87_der,
                          sizeof(root87_der), error))
      << "unexpected error " << error;
}

// An ML-DSA signature over an ECDSA subjectPublicKeyInfo. Exercises the new
// PublicKeyAlgorithm::MLDSA arm of CheckSignatureAlgorithm and the absent
// digest algorithm, without involving the new SPKI parsing.
TEST_F(pkixc_mldsa_tests, MLDSASignatureOverECDSASubjectPublicKeyInfo) {
  PRErrorCode error = 0;
  ASSERT_TRUE(VerifyChain(eemix_der, sizeof(eemix_der), rootmix_der,
                          sizeof(rootmix_der), error))
      << "unexpected error " << error;
}

// The converse, and the case that blocks ML-DSA TLS client authentication in
// Firefox: an ML-DSA subjectPublicKeyInfo in a chain signed classically.
// Before this patch CheckSubjectPublicKeyInfoContents rejects the ML-DSA SPKI
// with ERROR_UNSUPPORTED_KEYALG, regardless of who signed the certificate.
TEST_F(pkixc_mldsa_tests, MLDSASubjectPublicKeyInfoWithECDSASignature) {
  PRErrorCode error = 0;
  ASSERT_TRUE(VerifyChain(eemldsa_ecca_der, sizeof(eemldsa_ecca_der),
                          rootec_der, sizeof(rootec_der), error))
      << "unexpected error " << error;
}

// VerifyMLDSASignedData must actually verify. Flipping a bit in the end
// entity's signature has to be caught.
TEST_F(pkixc_mldsa_tests, MLDSA44CorruptedSignatureIsRejected) {
  std::vector<uint8_t> tampered(ee44_der, ee44_der + sizeof(ee44_der));
  tampered.back() ^= 0x01;

  PRErrorCode error = 0;
  ASSERT_FALSE(VerifyChain(tampered.data(), tampered.size(), root44_der,
                           sizeof(root44_der), error));
  EXPECT_EQ(error, SEC_ERROR_BAD_SIGNATURE);
}

// RFC 9881 section 2 requires the contents of the parameters component of the
// ML-DSA AlgorithmIdentifier to be absent. An explicit NULL must not be
// accepted.
//
// The mangled certificate has to be the trust anchor, not the end entity:
// BuildForward defers CheckIssuerIndependentProperties errors on a
// non-trust-anchor end entity, so a later error would take priority. The
// public key bytes are untouched, so nothing else about the chain changes.
TEST_F(pkixc_mldsa_tests, MLDSA44NullParametersInRootIsRejected) {
  PRErrorCode error = 0;
  ASSERT_FALSE(VerifyChain(ee44_der, sizeof(ee44_der), root44_nullparams_der,
                           sizeof(root44_nullparams_der), error));
  EXPECT_EQ(error, SEC_ERROR_BAD_DER);
}

// The same encoding in the end entity is also rejected, but because the
// mangling invalidates the signature over the TBSCertificate and end-entity
// CheckIssuerIndependentProperties errors are deferred, the reported error is
// the signature failure rather than the DER error.
TEST_F(pkixc_mldsa_tests, MLDSA44NullParametersInEndEntityIsRejected) {
  PRErrorCode error = 0;
  ASSERT_FALSE(VerifyChain(ee44_nullparams_der, sizeof(ee44_nullparams_der),
                           root44_der, sizeof(root44_der), error));
  EXPECT_EQ(error, SEC_ERROR_BAD_SIGNATURE);
}

}  // namespace
