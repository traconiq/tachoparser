package decoder

import (
	"crypto/sha1"
	"encoding/binary"
	"math/big"
	"testing"
)

// testRepeatedBlock stands in for a block that may occur more than once in vehicle unit
// data (activities, events and faults, detailed speed, technical data). Its "signature"
// holds when the single data byte is not zero.
type testRepeatedBlock struct {
	Verified bool  `aper:"-" json:"verified"`
	Value    uint8 `json:"value"`
}

func (b testRepeatedBlock) VerifyFirstGen(cert CertificateFirstGen, data []byte) (bool, error) {
	return len(data) == 1 && data[0] != 0, nil
}

type testVuWithRepeatedBlocks struct {
	Blocks []testRepeatedBlock `tv:"tag=0x7602" json:"blocks"`
	cert   CertificateFirstGen
}

func (v *testVuWithRepeatedBlocks) SignCertificateFirstGen() CertificateFirstGen {
	return v.cert
}

// testCertificateFirstGen builds a first generation certificate that decodes against a test CA
// with public exponent 1, so the recoverable part of the certificate is stored as it is.
func testCertificateFirstGen(t *testing.T) CertificateFirstGen {
	t.Helper()
	const caRef = uint64(0x0102030405060708)
	PKsFirstGen[caRef] = DecodedCertificateFirstGen{
		CertificateHolderReference: caRef,
		RsaModulus:                 new(big.Int).Lsh(big.NewInt(1), 1100),
		RsaExponent:                big.NewInt(1),
	}
	t.Cleanup(func() { delete(PKsFirstGen, caRef) })
	// C' = CPI | CAR | CHA | EOV | CHR | n | e (164 bytes)
	cPrime := make([]byte, 164)
	cPrime[0] = 0x01
	binary.BigEndian.PutUint64(cPrime[1:9], caRef)
	binary.BigEndian.PutUint64(cPrime[20:28], 0x1112131415161718)
	for i := 28; i < 156; i++ {
		cPrime[i] = 0xff
	}
	cPrime[163] = 0x01
	hash := sha1.Sum(cPrime)
	var c CertificateFirstGen
	c.Certificate[0] = 0x6a
	copy(c.Certificate[1:107], cPrime[:106])
	copy(c.Certificate[107:127], hash[:])
	c.Certificate[127] = 0xbc
	copy(c.Certificate[128:186], cPrime[106:])
	binary.BigEndian.PutUint64(c.Certificate[186:194], caRef)
	return c
}

func TestVerifiedIsSetOnEachRepeatedBlock(t *testing.T) {
	v := testVuWithRepeatedBlocks{cert: testCertificateFirstGen(t)}
	// three blocks with the same tag; the middle one does not verify
	data := []byte{0x76, 0x02, 0x05, 0x76, 0x02, 0x00, 0x76, 0x02, 0x07}
	verified, err := UnmarshalTV(data, &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Errorf("overall result should be false when one block does not verify")
	}
	if len(v.Blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(v.Blocks))
	}
	want := []bool{true, false, true}
	for i, b := range v.Blocks {
		if b.Verified != want[i] {
			t.Errorf("block %d: Verified = %v, want %v (value %d)", i, b.Verified, want[i], b.Value)
		}
	}
}
