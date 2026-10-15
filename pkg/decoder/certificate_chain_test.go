package decoder

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func testCertificateSecondGen(chr, car uint64, valid bool) CertificateSecondGen {
	d := DecodedCertificateSecondGen{Valid: valid}
	d.CertificateBody.CertificateHolderReference = chr
	d.CertificateBody.CertificateAuthorityReference = car
	return CertificateSecondGen{Certificate: []byte{0x7f, 0x21, 0x01}, DecodedCertificate: &d}
}

func TestCertificateChainSecondGen(t *testing.T) {
	const ca, card = uint64(0x0a0b0c0d0e0f0001), uint64(0x0a0b0c0d0e0f0002)
	PKsSecondGen[ca] = DecodedCertificateSecondGen{}
	t.Cleanup(func() { delete(PKsSecondGen, ca) })
	cases := []struct {
		name    string
		cert    CertificateSecondGen
		decoded bool
		want    string
	}{
		{"no data", CertificateSecondGen{}, false, ""},
		{"only 0x00 and 0xff", CertificateSecondGen{Certificate: []byte{0x00, 0xff}}, false, ""},
		{"signed by a known authority", testCertificateSecondGen(card, ca, true), true, CertificateChainValid},
		{"signature does not hold", testCertificateSecondGen(card, ca, false), true, CertificateChainInvalid},
		{"authority not in the store", testCertificateSecondGen(card, 0x99, false), true, CertificateChainCaNotFound},
		{"signs itself", testCertificateSecondGen(card, card, true), true, CertificateChainInvalid},
		{"could not be decoded", CertificateSecondGen{Certificate: []byte{0x01}}, false, CertificateChainInvalid},
	}
	for _, c := range cases {
		if got := certificateChainSecondGen(c.cert, c.decoded); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCertificateChainFirstGen(t *testing.T) {
	const ca = uint64(0x0102030405060708)
	PKsFirstGen[ca] = DecodedCertificateFirstGen{CertificateHolderReference: ca}
	t.Cleanup(func() { delete(PKsFirstGen, ca) })
	var known, unknown CertificateFirstGen
	known.Certificate[0], unknown.Certificate[0] = 0x6a, 0x6a
	binary.BigEndian.PutUint64(known.Certificate[186:194], ca)
	binary.BigEndian.PutUint64(unknown.Certificate[186:194], 0x99)
	cases := []struct {
		name    string
		cert    CertificateFirstGen
		decoded bool
		want    string
	}{
		{"no data", CertificateFirstGen{}, false, ""},
		{"decoded, so signed by a known authority", known, true, CertificateChainValid},
		{"known authority, but not signed by it", known, false, CertificateChainInvalid},
		{"authority not in the store", unknown, false, CertificateChainCaNotFound},
	}
	for _, c := range cases {
		if got := certificateChainFirstGen(c.cert, c.decoded); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

type testTopWithChain struct {
	CertificateChainFirstGen  string
	CertificateChainSecondGen string
}

func TestChainResultIsWrittenWhenTheStructureHasTheField(t *testing.T) {
	var top testTopWithChain
	v := reflect.ValueOf(&top).Elem()
	setCertificateChain(v, "CertificateChainSecondGen", CertificateChainValid)
	setCertificateChain(v, "NoSuchField", CertificateChainValid)
	if top.CertificateChainSecondGen != CertificateChainValid || top.CertificateChainFirstGen != "" {
		t.Errorf("unexpected result: %+v", top)
	}
}
