// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSizesMatchTheSpec(t *testing.T) {
	// PLAN.md §2 quotes these; if crypto/mldsa ever disagrees, the netmap and
	// the handshake budget are both wrong and it should fail here first.
	if PublicKeySize != 1952 {
		t.Errorf("public key: got %d want 1952", PublicKeySize)
	}
	if SignatureSize != 3309 {
		t.Errorf("signature: got %d want 3309", SignatureSize)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("transcript")
	sig, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature length: got %d want %d", len(sig), SignatureSize)
	}
	if !Verify(k.Public(), []byte(ControlContext), msg, sig) {
		t.Fatal("valid signature did not verify")
	}
}

// The context string is the whole point of ControlContext: a signature made
// for the control channel must not verify anywhere else.
func TestContextSeparatesDomains(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("same bytes, different purpose")
	sig, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if Verify(k.Public(), []byte("karst-bedrock-v1"), msg, sig) {
		t.Fatal("a control-channel signature verified under a different context")
	}
	if Verify(k.Public(), nil, msg, sig) {
		t.Fatal("a control-channel signature verified with no context")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("m")
	sig, err := a.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if Verify(b.Public(), []byte(ControlContext), msg, sig) {
		t.Fatal("signature verified under the wrong public key")
	}
}

func TestTamperedMessageAndSignatureRejected(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("original")
	sig, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if Verify(k.Public(), []byte(ControlContext), []byte("tampered"), sig) {
		t.Fatal("signature verified over a different message")
	}
	bad := bytes.Clone(sig)
	bad[0] ^= 0xFF
	if Verify(k.Public(), []byte(ControlContext), msg, bad) {
		t.Fatal("tampered signature verified")
	}
}

// Verify must not panic or misbehave on attacker-supplied garbage: every call
// is in the middle of authenticating an unauthenticated message.
func TestVerifyRejectsMalformedInputs(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("m")
	sig, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	cases := []struct {
		name string
		pub  []byte
		sig  []byte
		ctx  []byte
	}{
		{"nil public key", nil, sig, []byte(ControlContext)},
		{"empty public key", []byte{}, sig, []byte(ControlContext)},
		{"short public key", k.Public()[:10], sig, []byte(ControlContext)},
		{"long public key", append(bytes.Clone(k.Public()), 0), sig, []byte(ControlContext)},
		{"nil signature", k.Public(), nil, []byte(ControlContext)},
		{"short signature", k.Public(), sig[:10], []byte(ControlContext)},
		{"oversized context", k.Public(), sig, bytes.Repeat([]byte{'x'}, 256)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if Verify(tc.pub, tc.ctx, msg, tc.sig) {
				t.Fatal("verified")
			}
		})
	}
}

func TestSeedDeterminism(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, SeedSize)
	a, err := FromSeed(seed)
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	b, err := FromSeed(seed)
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	if !bytes.Equal(a.Public(), b.Public()) {
		t.Fatal("the same seed produced two different identities")
	}

	other, err := FromSeed(bytes.Repeat([]byte{8}, SeedSize))
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	if bytes.Equal(a.Public(), other.Public()) {
		t.Fatal("different seeds produced the same identity")
	}
}

func TestFromSeedRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, SeedSize - 1, SeedSize + 1} {
		if _, err := FromSeed(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Fatalf("seed of %d bytes was accepted", n)
		}
	}
}

// Hedged signing means two signatures over the same message differ. Both must
// verify; a deterministic scheme would be a change worth noticing.
func TestSigningIsHedged(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("m")
	first, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	second, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two signatures over the same message were identical: signing is not hedged")
	}
	if !Verify(k.Public(), []byte(ControlContext), msg, first) ||
		!Verify(k.Public(), []byte(ControlContext), msg, second) {
		t.Fatal("a hedged signature failed to verify")
	}
}

func TestOversizedContextRefusedOnSign(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := k.Sign(bytes.Repeat([]byte{'x'}, 256), []byte("m")); err != ErrContext {
		t.Fatalf("got %v want %v", err, ErrContext)
	}
}

// TestSeedIsStableAcrossTheCirclMigration pins what the previous
// implementation produced.
//
// **This is the test the crypto/mldsa migration turned on.** Both libraries
// implement FIPS 204, which is a strong argument that a seed derives the same
// key under each — and not a proof. It matters more than usual here because a
// node's handle is a hash of its public key (package node), so a disagreement
// would not fail: it would silently re-identify every enrolled node, and the
// symptom would be a fleet that cannot authenticate for reasons no log line
// explains.
//
// The digest below was produced by cloudflare/circl before the swap.
func TestSeedIsStableAcrossTheCirclMigration(t *testing.T) {
	const circlPublicKeySHA256 = "d3a1e51ecf491b79ca7691bd269271f8d8e8d94313a6abcc6c8ae8bc34b5f9aa"

	k, err := FromSeed(bytes.Repeat([]byte{7}, SeedSize))
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	sum := sha256.Sum256(k.Public())
	if got := hex.EncodeToString(sum[:]); got != circlPublicKeySHA256 {
		t.Fatalf("seed derives a different key than before the migration:\n got %s\nwant %s",
			got, circlPublicKeySHA256)
	}
}

// And a signature the old library produced still verifies under the new one,
// which is the other half: a public key that matches would not help if the
// signature encoding had moved.
func TestACirclSignatureStillVerifies(t *testing.T) {
	sig, err := hex.DecodeString(
		"4f10dd0aff1c7a7fcc30916b1bcba50acd2634ea79cf1eadd7d8b67445dbd6d9dba400e6da2036b19b64d3153d462f75" +
			"465b22e6ec23a887db564abba8c21016e25ce169916225a4538f4534336685eb45c38dcd8123ffe24cfcf7f17f9981df" +
			"ab9a43fce7f019cdcb067a56b55a4e220d04148b9d5a8300addfa9b0f88a970bda2d598207dae80487251727f21ee221" +
			"a97f61f95b237818688af7b9f96a517fe54dac9ed1b841246199615ee1658beab72f7e5a37d71c41afb2802765c2b4a9" +
			"404d8cfb50ad1222507c802ccc938a591b292ac9ca863082fc737ccd9019d35748c25329825a97645ea2896d6b0de836" +
			"92641c79cbf4e498e44b1a09169b57406115bd91e4edff22338923d759d106bd8a363b86133c64e776ab6540fe9596af" +
			"6b98ff4dbc3c8ef412fe53c90566c8af85094c621137a8ac0059694aaa73f92843add0d0633cc9817499b76ab8a00283" +
			"edb780052f81e375d04397a9e6cf36edeeeb391e5abc6865152b27fbd6eb8a1882f0782c4045f4e6fa476fc00c898696" +
			"d20562ba8983a001e5f35a2df426c33bf7b4cb3f9b6aae1b300f8aecae7d2d019a43dd48ed79ed41a1fd2a6f81e67b89" +
			"d9ae9e054696e52fcea764788d8f6783f6a2eb4e6b3f3ee3aa545b8414c94d0af73a15432a1f0c42a0c17cc73e30e60e" +
			"4b97298ef6191a1059f9cf0766e210070381246e0369887bceca2de657b2f6ba628f4ea9d7cade4e677601153a059d83" +
			"579af10ab389db94c92183646ff6fd59b8d132fe5a43f782d57ebcdf185dda707f03b0a070565b6f42b73bcbf3b6432e" +
			"b33f59a85e9c376456da8ee088bdf99fdfca536f2277585a83b3a583b813fcd7b8b892fadf9d366b33f96ad985487c00" +
			"7f4871be6b5bc896e8ae33b4975c1f9095b71c29eb7347e653b5b97928572c80d5c6c8dc068ec5075b5a857305cf5d5e" +
			"4aee1f64be1c303bbdc49f2dfd4f3db28363159ac1bed6ccd48ff4728a828c52ea5e4f9fd3c8fc51052db53721d22004" +
			"739b45dd794b34353445b76553e18b0f06ce50e7e5eadc43d1b96e421614683a0f265b11e3a3a688c497f57d27fd1cee" +
			"e9c38b9d82180eb3bd7ddb271fd7043e391dd7e4175148330443dbfdff809cace11c91acf63bb556146de08688d39591" +
			"e05cdca70720e0afd2f28232fccb67f6d4c56b2d07f9bddccc2a97182ec65f595f601a6d1e41b664fc09016b2621c1ba" +
			"579f9cfd74f2119688f6dba968fff0c4d9dd3280938ca560c197777d9045245db01b1f0332a4549bb08a19be65a435d8" +
			"2bf8112ca4e0f003992af5c49cfac5701e563c0f0dcd1ed6432a5b78994a07e3ed5a9ae40c3412af5f012ccaf7890570" +
			"91d0c7097e43884ccf6c7ebf65ba728c725894a4f43fb80f4437c8881f5abbd27325e8adccd8e305ef22da240c3a29b3" +
			"8a0023b4787210d666d58ca07087fd3d4376a485d1781bb62b2cd21085fd8412a7970d8e0f42316284eb611b525d9ac1" +
			"11428638bf09c83085850e0d59dab58f53fbabb754234b4eba6c4c303dbaf419d4eb15089c7c293a8f86147c554182ae" +
			"666481f8a4f4c5f5fbf05f3cf67a9c31d19673b4789f4414ab056aa3cdcd5bfdcc9b938e0b6c56485c01f53467685b34" +
			"69f945b6136e70ac3e06c3805dabfd2fb2fe1890083c2a9f757f1dd562001bdc66a04dbecdb86ad5756c4eb39e45cc71" +
			"1638ebe444659796a441ee1df56400f8c296fe16b02ab90e41ed53443d95880b245306a1aaaa68c099882e5378951ae3" +
			"2c563ecfd5fbfee55f82f997def72fb5be6c01353565976286740aac1b8419414c13cdfa90b762f400771a974525d197" +
			"006464afd042b35371ee89ebc782505f3703a32e97d8ad61aa3c65ce0c31596d035ab3400dc0066c05cdef997221d0f7" +
			"f0a8c8c61aa2031fd80de1b04a5be9e5fd0eb939b0df3f74cbf3b7a967cd3ddc2c223005078a170eafff4fcb7e99d6f6" +
			"429eb6ebeaed2bc24df07c72df3507255af3eb3b9267d830be835b4e2b0079ce943e3d73d51b9ef35a7661d2cbb91074" +
			"b43e699d2abbe920ff7629792d99bcb14b6e7a12e3033b99aab701d12a281cc695dcd736b83eeb503b17c1ee42d3851a" +
			"b398f177d79a6a1c103367d76c4c49a8cf464e69c091722f042fa729885ddbe0578b0496aad61548c143adf025538c56" +
			"189b3a61ff139cd8b3a3d0d673545d78fc4b95c16433ab84fe32085efafa3f30afaa21146756d48c714825f99a6a647a" +
			"b6a5ae0b7e21d9dd4d7ad8d6e6962aa5bd8a7a0c49624115a34d4f74bf407330615b1328a982a1e9c2d89e32fc7433a0" +
			"246e62f2303c1559a8c134c5e2a0de11a4a08d5f3e4e9d6b03f1077e5890a9a9bcaa713cd7aa967f26e46018fe3f03d8" +
			"71e798c87002680b4bd9314b5890b55c113f327cb4ca24b41770678653333490e7256ea32ddd52e1cede9e4cf85cc1e8" +
			"8c61a5ab339a75d4f32e789d003e3616c0be84dd5d64fcdf3f79b5326b5507e4c179c685a343fb692b50d12632e7112e" +
			"b0782e22d8507daaf4edc4fd665ea181daa132d487d6b0ddb11bc1cff5ad33d841740a329ad2e2a9e4dfe7aa51313093" +
			"a694e8ec91f55d74e1b77dc9039c7bae4828d0f34927ab76ce233760bc28e7f7b071ee9040df47324152c974406398c8" +
			"8d79bb1c6c378681f834ab0de9b9ffed18f5d920b4cc36a3a9cb6248739bdd605304cb874db18fa8510435b914fd1eed" +
			"e5d4cea56b790459bafad5af5ff773e4c872187ae1cc35c101f7e1bf7ccb3789b72e09292c798547319d98186eafb9cc" +
			"a8bd0a175828c8d73ff8277b68120a43804a0f0d1f047beaea36bfa40c1adb21297347abe8cc56f6ef0544d0bd253a74" +
			"c17e19649370dc0850c350d35721659b2305b2123dc416faa17d7c8e07ce90d7d2692ddc7a3b0fdf980a4ad3f8831541" +
			"f99e1d2b81facf67f583c562eadeedfc0e59c66091e986e435776577e57275be6fd22b2c4a91da19eefc1018b505dfcd" +
			"a976017ff109dcee3a7c293ea292b621f1acb0296bf4288fc3b7e3fc908a186579bdaa4aeb6552e9cda9fd95ed701245" +
			"bb11a4409c40c477bc164e4e88a083d3174d63d496272691d456b7d069a9553caa39506d3b1f4bbc0d4e000d0254285e" +
			"39a71fe5b185c6782a4a3e94fdef978911d00b48ef6426309c07ce76d31c294d40c22bfb05a4c4d487bc69c1c4000648" +
			"ef6bce1b3d6f6c780abf012f3a768dc03036082226c7589772ffeecb8a132a8618c24b4fac8b7bb83f3c7110f5647b7d" +
			"67348d2eca7a5eacdc55a21e2ffb4cfe2ce9c76052ead05f685036195556614877be48116ad847c206da7a9fe87337cf" +
			"41c124425eba9e849380bb8f07bb7bc886318966b6490111fd5fb1ceb1c58b375b86da42572b9fbb5bbcda4e13511549" +
			"9400ece22f96dfa62729ddf91d60abe639d7f04f1878d6f8fe7099128b02062791fd709ede553ae3464e857ac79aee68" +
			"b11894b44dc82bd66c808e93b251c9a081fafddee24eda941f8285a798c6f407294f7a5c3a48a215c7724c80012c0f9e" +
			"dfa5f89c538eede5622cbf5c7f66f60b1dee7190fca0cae113fee270dec1d31ad265f61627684fb28920fe5228b3bcbe" +
			"bae724af386748488f35c23c725b9434821ebb406d3423d386f7dc14710f8bbce020462df285f063931fa308c6f7d8d4" +
			"978c327eb205170f69e876ecf380d1071b14f08cba30d49265bda4df2cd3edc37e08ea30e26ead2153566e1dcee0e08d" +
			"e99f8dfdaa3f49381768f81a0f2b9c3f8d1440a19899a16da2a76cb4420be7e03ecca09ca9545773d886ae7647b36210" +
			"9f29dd949a690ce4935fb9c92a59fafab7f78f484232585c4decca5410e30d8eaae3ae04c036f19d03150cabd2df7688" +
			"ec29aa46297101b1d58e1d77f4268a2749ce177548238e66e9265bbf5f6d288da0b1102c2c341f2fd2dc895998e3ae7e" +
			"30981a1a42d3dac6a29d1bd582e0382f46e002fe5ded6828d7b79e6508ac64062bf5c981987c48a09d2658bf7970794c" +
			"a309d9acdfc1f8b55ebb3a912e436c02ccadad1167c74841727218a876e3f2a05317896a0c151996bb3056c1f804c147" +
			"419d60a6fc87937ad35b2cf527f55ac066b4260ab3653465c6f2fd78ecc73a2994d4109a0e0ab80dcf02d6617e83b444" +
			"98b27dfee937c041dfd1618129bc636e2e2d14deb13ae54e91bf92eee56d6ff19212cedabfc35a18111566b6861a6c34" +
			"575a04db20c1a13ebd1a9140f9a9d7e66b50b19137f755d44f23ecae67baad4de1548825d8cee7f5f90269cee36363cc" +
			"3325fdac637c4fe1f0e1408ecb1db4ef44e1d9a941f722864388c7e681cd5616ca39cbd5ad8a6ef70d7aa5904f3d10e8" +
			"000d486fdb421f4e70ce0e5bb7754b9ce50e23b49d287e0bceb6ea0cfefaa1c1661183d8c632d37dfcb23d1caba43fbc" +
			"9dccabe0f3475773adc7c9ee65fd07b54c1a2df087635fc6593f82c7117edfaa123d9deb6d427faff4db201f0a832cb6" +
			"6130c8a2524934c40960285ab91de123e947d248fea9f01f6e4b7c4710ebcb6dc99d8c363d6cd6286f1d0113e4f0b674" +
			"21d5ec05e458d2bbff5da16d960d677b6edc94d78523aaa55f2a71abb6ea54ac07303f575b61696c92a3ec283977969d" +
			"c9d1186f82ac032f8c8ebee6fa14b3b6b9bfd9df6c7be0f20000000000000000000000000000000b12161d2428")
	if err != nil {
		t.Fatalf("vector: %v", err)
	}
	k, err := FromSeed(bytes.Repeat([]byte{7}, SeedSize))
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	if !Verify(k.Public(), []byte(ControlContext), []byte("karst migration vector"), sig) {
		t.Fatal("a signature made by cloudflare/circl no longer verifies")
	}
	// And it is genuinely being checked, not accepted blindly.
	if Verify(k.Public(), []byte(ControlContext), []byte("different message"), sig) {
		t.Fatal("the vector verified over the wrong message")
	}
}
