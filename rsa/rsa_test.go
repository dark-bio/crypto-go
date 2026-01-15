// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Tests that a raw byte encoded RSA private key can be decoded and re-encoded
// to the same bytes. The purpose is not to battle-test the implementation,
// rather to ensure that the code implements the format other subsystems expect.
func TestSecretKeyBytesCodec(t *testing.T) {
	// Generated with:
	//   openssl genrsa -out test.key 2048
	//   openssl rsa -in test.key -text -noout
	partPrime1 := "" +
		"ed9792f021b214b57fc6230d051da0783673475d9b9cf9f9003367b6362a" +
		"62201852f112cbb6fcadb00b17470e21dfa39ec2eef58ea2ff7e27b9e63b" +
		"90af84e482b53ea79760196bbd226627038d84eb16e75e2efacb9f432dbf" +
		"b93ec3f6fea10ec9c9b984e8c7d4e95fa76befc2f46e42c86d8479586b36" +
		"7cb49499b37bf01d"
	partPrime2 := "" +
		"da885d75be231c04ebf195455fcec9449044b212f2044ddeeb49c0c14898" +
		"35f8e91e56a6418570a9f50c2734c4fadb7f2eb2c50cff4ab0b34e389568" +
		"12f9b42632c66a248e09e52af8eb5e1c8cdd21fe65b86242fdf1e838235d" +
		"a1bf37ced6ae0e117c8dac77c34917a711bc6ecc949d0f000dae8f22dadf" +
		"46153c64d5ef7521"
	partPrivExp := "" +
		"02d864d6371a3586977264fa905c01495adbeba2fbab49cc1ea22d6d5c17" +
		"71b0a31b2a58c546e81990fa861e0954a4d9119d3698f41ca66b37c0b4a8" +
		"756f4efdd814d36393e3fb8b9662f1dc7725222565c95eb5389e3caa28e5" +
		"429608b898d677e9feffbb66207d3e881949dc0b53568a0ea9c6ae06bef3" +
		"6f74422960d8447b194ebff8ab5f08842153661278bbeb115dd131d26746" +
		"7315402b5d75560d4c20390499887f3d33021f4dda1cb36bfb9b54ed80c5" +
		"9bd3213f42a4ca7025d59a64e53d559e14ac84f8438b771c1ac94fb90aa4" +
		"1c7708e073510ad063bada4a261bc0b311a42b8d482d26b39fb82d44f133" +
		"c9ab9ccdd77b098fc6c0c647ed663781"
	partPubExp := "0000000000010001"

	input := partPrime1 + partPrime2 + partPrivExp + partPubExp
	inputBytes, _ := hex.DecodeString(input)

	var b [SecretKeySize]byte
	copy(b[:], inputBytes)

	key, err := ParseSecretKey(b)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	m := key.Marshal()
	if got := hex.EncodeToString(m[:]); got != input {
		t.Errorf("encoded key mismatch: have %s, want %s", got, input)
	}
}

// Tests that a raw byte encoded RSA public key can be decoded and re-encoded
// to the same bytes. The purpose is not to battle-test the implementation,
// rather to ensure that the code implements the format other subsystems expect.
func TestPublicKeyBytesCodec(t *testing.T) {
	// Generated with:
	//   openssl genrsa -out test.key 2048
	//   openssl rsa -in test.key -text -noout
	partMod := "" +
		"cad1a263e36205031c65b1befe8b1f65ac0af10c72aeb69ad295d1a651a3" +
		"f1191d4af8afdef14ab2d66d0253ef98228ee9f85fb822f92fccb3f6c23b" +
		"4745ac743e002fc81c63dc04531fc176f3cdcb5aebaa2797903fd791b9c8" +
		"474eb7b999295cf64935d9a5a4626849e77c472a6e00b8ff73d0f1a3b7c4" +
		"4da7e7bae4726b4f2f7f05741d576a13c1bc9077ee14d7e9af5192f8e7dc" +
		"2ffb212d4ef9c7fff4e87c3debf9a48346ac3618b24d7932d8e7cf6b266c" +
		"dce0ad59b16fce0a8420aebd332e28294862ef288917eacabf330cb29161" +
		"f78fcdf089bc2cb4086af8a7980637fb9cf0b4ed86d6a21208ae5a4e49d1" +
		"7ab6d945b65cef700217ada913ca34bd"
	partPubExp := "0000000000010001"

	input := partMod + partPubExp
	inputBytes, _ := hex.DecodeString(input)

	var b [PublicKeySize]byte
	copy(b[:], inputBytes)

	key, err := ParsePublicKey(b)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	m := key.Marshal()
	if got := hex.EncodeToString(m[:]); got != input {
		t.Errorf("encoded key mismatch: have %s, want %s", got, input)
	}
}

// Tests that a PEM encoded RSA private key can be decoded and re-encoded to
// the same string. The purpose is not to battle-test the PEM implementation,
// rather to ensure that the code implements the PEM format other subsystems
// expect.
func TestSecretKeyPEMCodec(t *testing.T) {
	// Generated with:
	//   openssl genrsa -out test.key 2048
	input := `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCwLLXTHaYT57yN
HZT6BTnJIDaJ8GTnu05PnwQQcV7Xgom164T52qaMmvsK/PGlzMzQdo9YjYKsExZE
EllJe4O1mVA1T/LyKLkPZgKqcp11/9UAkk3pHsPkb0YOb3g1721K6tQ78ufjeIOt
5WJ+n+HJHOvhvyjmO0aQ51eh0jSyUu6U9fA+qrtPO4D/mUVRDJmCLSyGzIMd4Xan
zTSWZ8JWLjahIdMPOZYUrGpICOxwt9Jaow37ogAalRVHnTb8PkklOo9pr0a3ZdQQ
P3yV/A5gmgXXLi2BkQ0b2y8FOuD/JjBXL4Ks9nUVn/nMMaFhDxmL3ZZ9AuvB94AR
B0MvuZh9AgMBAAECggEABoVaB1dURJhZDBV0OcI5iVWakr63md/F3kdDnlu+koDd
/V63rG76izDmsQQYP3Zgt0TW1ehDcmP3ziDG2blycF5WKM2tqGcwlfBvypn8WEnH
5eWEcEul5JFZ09C8b61N8sOALq01PzVOv8dCPu9jKzL19mfPofX4myKt4esKX2gy
psId9QmgsrRRsCSvQeUxOA3Sqaa0a+atALZByPKZN8XzmZu1Ie5QPQvh/xYDJU1D
GEiNgwZGy0eXL2Se5OjKAR40f4SzArbs/Jb2gRFHTjpdJ9g33GqoP94jZPcogtm2
FHgI5vl9jL4uXiSJLkgl4FfFvoIXWuUi1xAC5NDT4QKBgQDnaxGFvt6vW8JKEyEq
6Nf9K2Y2nQbvEmqnvS/RPwuqKuh66KCNG2rePFzXLHCplbYHt9hhF+Ity9lFzxSK
ipRC6BD9aqaqF6qhm1nZWnXsPWjWDsFYzQHv8LA4pL8gmxbz+IOs1jbbIQAdq8X5
uv7C1YSCrPkpm/nTljzwU/d/gwKBgQDC42in2DURf1+cU9Qw+hNDCy0EgkB7STzV
dCreCAFXhSIzFwq9bjzOeSFtvZlWxKNJKNUiDXgN/grRREG/m1kW7EdHAMiOVVNK
SbQ/+zHy6SMKNu0ArkokaCAEludVVRjkwh5GsyFvFaBINJBnp/zDYhNkkxStjCRf
rW0/fmcH/wKBgF/IA9+caWShEOBB3Kd66fKiJNMT2QvYToaQmhr8AiLzUXeVkuX0
ZB4JU8/HV/YIveeh4xAEp5uW1J29IN5ajxTGIkoQ+1xJIVl0CBMbCtW1cQ+v2byc
VWHu97DqFyUyq6RcxnshymCV3wtozi8Xg1w2rXq8hv/+y78UXrKFvllrAoGAItrb
F9GyRAvcxK+1boD7Ou1fwsOs1p/VknNxSz5xRv7Xi/2d/R0fIOpHEUJsjzkh3u6/
l5SDGTWLJ7wmaidVeqUNZmR8egBGoi2mYB8D4ubRTn1eS9XgCrzYpRl8DCXpCtiw
44IcA6sBfIhyHyfLLAJ5Z25qr1M2GiqBNG7d7G8CgYBoIYe3OeuqZn2T+eA3rmMv
djLUQsO3CvmFYBDvNqmiwNx3OOV/YFQVvSAGaEP/5pJGVmAKUDaALgTveToLV6jq
bS99QZDnrW+xkvJi6N1ZAlQpIOX5Y/Q2qyBa1Hf2Z21mnqZSN3HHC6aQl+83uety
JJXbL24vf1AajzeJk6CpdQ==
-----END PRIVATE KEY-----`

	key, err := ParseSecretKeyPEM(input)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	if got := strings.TrimSpace(key.MarshalPEM()); got != strings.TrimSpace(input) {
		t.Errorf("encoded key mismatch: have %s, want %s", got, strings.TrimSpace(input))
	}
}

// Tests that a PEM encoded RSA public key can be decoded and re-encoded to
// the same string. The purpose is not to battle-test the PEM implementation,
// rather to ensure that the code implements the PEM format other subsystems
// expect.
func TestPublicKeyPEMCodec(t *testing.T) {
	// Generated with:
	//   openssl rsa -in test.key -pubout -out test.pub
	input := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsCy10x2mE+e8jR2U+gU5
ySA2ifBk57tOT58EEHFe14KJteuE+dqmjJr7CvzxpczM0HaPWI2CrBMWRBJZSXuD
tZlQNU/y8ii5D2YCqnKddf/VAJJN6R7D5G9GDm94Ne9tSurUO/Ln43iDreVifp/h
yRzr4b8o5jtGkOdXodI0slLulPXwPqq7TzuA/5lFUQyZgi0shsyDHeF2p800lmfC
Vi42oSHTDzmWFKxqSAjscLfSWqMN+6IAGpUVR502/D5JJTqPaa9Gt2XUED98lfwO
YJoF1y4tgZENG9svBTrg/yYwVy+CrPZ1FZ/5zDGhYQ8Zi92WfQLrwfeAEQdDL7mY
fQIDAQAB
-----END PUBLIC KEY-----`

	key, err := ParsePublicKeyPEM(input)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	if got := strings.TrimSpace(key.MarshalPEM()); got != strings.TrimSpace(input) {
		t.Errorf("encded key mismatch: have %s, want %s", got, strings.TrimSpace(input))
	}
}

// Tests that a DER encoded RSA private key can be decoded and re-encoded to
// the same string. The purpose is not to battle-test the DER implementation,
// rather to ensure that the code implements the DER format other subsystems
// expect.
func TestSecretKeyDERCodec(t *testing.T) {
	// Generated with:
	//   openssl rsa -in test.key -outform DER -out test.key.der
	input := "" +
		"308204bc020100300d06092a864886f70d0101010500048204a6308204a2" +
		"0201000282010100b02cb5d31da613e7bc8d1d94fa0539c9203689f064e7" +
		"bb4e4f9f0410715ed78289b5eb84f9daa68c9afb0afcf1a5ccccd0768f58" +
		"8d82ac1316441259497b83b59950354ff2f228b90f6602aa729d75ffd500" +
		"924de91ec3e46f460e6f7835ef6d4aead43bf2e7e37883ade5627e9fe1c9" +
		"1cebe1bf28e63b4690e757a1d234b252ee94f5f03eaabb4f3b80ff994551" +
		"0c99822d2c86cc831de176a7cd349667c2562e36a121d30f399614ac6a48" +
		"08ec70b7d25aa30dfba2001a9515479d36fc3e49253a8f69af46b765d410" +
		"3f7c95fc0e609a05d72e2d81910d1bdb2f053ae0ff2630572f82acf67515" +
		"9ff9cc31a1610f198bdd967d02ebc1f7801107432fb9987d020301000102" +
		"82010006855a0757544498590c157439c23989559a92beb799dfc5de4743" +
		"9e5bbe9280ddfd5eb7ac6efa8b30e6b104183f7660b744d6d5e8437263f7" +
		"ce20c6d9b972705e5628cdada8673095f06fca99fc5849c7e5e584704ba5" +
		"e49159d3d0bc6fad4df2c3802ead353f354ebfc7423eef632b32f5f667cf" +
		"a1f5f89b22ade1eb0a5f6832a6c21df509a0b2b451b024af41e531380dd2" +
		"a9a6b46be6ad00b641c8f29937c5f3999bb521ee503d0be1ff1603254d43" +
		"18488d830646cb47972f649ee4e8ca011e347f84b302b6ecfc96f6811147" +
		"4e3a5d27d837dc6aa83fde2364f72882d9b6147808e6f97d8cbe2e5e2489" +
		"2e4825e057c5be82175ae522d71002e4d0d3e102818100e76b1185bedeaf" +
		"5bc24a13212ae8d7fd2b66369d06ef126aa7bd2fd13f0baa2ae87ae8a08d" +
		"1b6ade3c5cd72c70a995b607b7d86117e22dcbd945cf148a8a9442e810fd" +
		"6aa6aa17aaa19b59d95a75ec3d68d60ec158cd01eff0b038a4bf209b16f3" +
		"f883acd636db21001dabc5f9bafec2d58482acf9299bf9d3963cf053f77f" +
		"8302818100c2e368a7d835117f5f9c53d430fa13430b2d0482407b493cd5" +
		"742ade080157852233170abd6e3cce79216dbd9956c4a34928d5220d780d" +
		"fe0ad14441bf9b5916ec474700c88e55534a49b43ffb31f2e9230a36ed00" +
		"ae4a2468200496e7555518e4c21e46b3216f15a048349067a7fcc3621364" +
		"9314ad8c245fad6d3f7e6707ff0281805fc803df9c6964a110e041dca77a" +
		"e9f2a224d313d90bd84e86909a1afc0222f351779592e5f4641e0953cfc7" +
		"57f608bde7a1e31004a79b96d49dbd20de5a8f14c6224a10fb5c49215974" +
		"08131b0ad5b5710fafd9bc9c5561eef7b0ea172532aba45cc67b21ca6095" +
		"df0b68ce2f17835c36ad7abc86fffecbbf145eb285be596b02818022dadb" +
		"17d1b2440bdcc4afb56e80fb3aed5fc2c3acd69fd59273714b3e7146fed7" +
		"8bfd9dfd1d1f20ea4711426c8f3921deeebf97948319358b27bc266a2755" +
		"7aa50d66647c7a0046a22da6601f03e2e6d14e7d5e4bd5e00abcd8a5197c" +
		"0c25e90ad8b0e3821c03ab017c88721f27cb2c0279676e6aaf53361a2a81" +
		"346eddec6f028180682187b739ebaa667d93f9e037ae632f7632d442c3b7" +
		"0af9856010ef36a9a2c0dc7738e57f605415bd20066843ffe6924656600a" +
		"5036802e04ef793a0b57a8ea6d2f7d4190e7ad6fb192f262e8dd59025429" +
		"20e5f963f436ab205ad477f6676d669ea6523771c70ba69097ef37b9eb72" +
		"2495db2f6e2f7f501a8f378993a0a975"

	der, _ := hex.DecodeString(input)
	key, err := ParseSecretKeyDER(der)
	if err != nil {
		t.Fatalf("failed to parse key %v", err)
	}
	if got := hex.EncodeToString(key.MarshalDER()); got != input {
		t.Errorf("encoded key mismatch: have %s, want %s", got, input)
	}
}

// Tests that a DER encoded RSA public key can be decoded and re-encoded to
// the same string. The purpose is not to battle-test the DER implementation,
// rather to ensure that the code implements the DER format other subsystems
// expect.
func TestPublicKeyDERCodec(t *testing.T) {
	// Generated with:
	//   openssl rsa -in test.key -pubout -outform DER -out test.pub.der
	input := "" +
		"30820122300d06092a864886f70d01010105000382010f003082010a0282" +
		"010100b02cb5d31da613e7bc8d1d94fa0539c9203689f064e7bb4e4f9f04" +
		"10715ed78289b5eb84f9daa68c9afb0afcf1a5ccccd0768f588d82ac1316" +
		"441259497b83b59950354ff2f228b90f6602aa729d75ffd500924de91ec3" +
		"e46f460e6f7835ef6d4aead43bf2e7e37883ade5627e9fe1c91cebe1bf28" +
		"e63b4690e757a1d234b252ee94f5f03eaabb4f3b80ff9945510c99822d2c" +
		"86cc831de176a7cd349667c2562e36a121d30f399614ac6a4808ec70b7d2" +
		"5aa30dfba2001a9515479d36fc3e49253a8f69af46b765d4103f7c95fc0e" +
		"609a05d72e2d81910d1bdb2f053ae0ff2630572f82acf675159ff9cc31a1" +
		"610f198bdd967d02ebc1f7801107432fb9987d0203010001"

	der, _ := hex.DecodeString(input)
	key, err := ParsePublicKeyDER(der)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	if got := hex.EncodeToString(key.MarshalDER()); got != input {
		t.Errorf("encoded key mismatch: have %s, want %s", got, input)
	}
}

// Tests that the implemented fingerprint algorithm produces the expected
// checksum. The purpose is not to battle-test the implementation, rather
// to ensure that the code implements the format other subsystems expect.
func TestFingerprint(t *testing.T) {
	// Generated with:
	//   from Cryptodome.PublicKey import RSA
	//   import hashlib
	//
	//   with open('key.pem') as f:
	//       key = RSA.importKey(f.read())
	//   mod_le = key.n.to_bytes(256, 'little')
	//   exp_le = key.e.to_bytes(8, 'little')
	//
	//   print(hashlib.sha256(mod_le + exp_le).hexdigest())
	want := "1e2eaa59f13165ce5c3b4e028fd259767c2ee8d43d5d5ba7debf9d31834b46db"

	key, _ := ParsePublicKeyPEM(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsCy10x2mE+e8jR2U+gU5
ySA2ifBk57tOT58EEHFe14KJteuE+dqmjJr7CvzxpczM0HaPWI2CrBMWRBJZSXuD
tZlQNU/y8ii5D2YCqnKddf/VAJJN6R7D5G9GDm94Ne9tSurUO/Ln43iDreVifp/h
yRzr4b8o5jtGkOdXodI0slLulPXwPqq7TzuA/5lFUQyZgi0shsyDHeF2p800lmfC
Vi42oSHTDzmWFKxqSAjscLfSWqMN+6IAGpUVR502/D5JJTqPaa9Gt2XUED98lfwO
YJoF1y4tgZENG9svBTrg/yYwVy+CrPZ1FZ/5zDGhYQ8Zi92WfQLrwfeAEQdDL7mY
fQIDAQAB
-----END PUBLIC KEY-----`)

	fp := key.Fingerprint()
	if got := hex.EncodeToString(fp[:]); got != want {
		t.Errorf("fingerprint mismatch: have %s, want %s", got, want)
	}
}

// Tests signing and verifying messages. Note, this test is not meant to test
// cryptography, it is mostly an API sanity check to verify that everything
// seems to work.
//
// TODO(karalabe): Get some live test vectors for a bit more sanity
func TestSignVerify(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	message := []byte("message to authenticate")
	signature, _ := secret.Sign(message)
	if err := public.Verify(message, signature); err != nil {
		t.Errorf("failed to verify: %v", err)
	}
	if err := public.Verify([]byte("wrong message"), signature); err == nil {
		t.Error("verify succeeded")
	}
}
