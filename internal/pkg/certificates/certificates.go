package certificates

import (
	"bytes"
	"embed"
	"encoding/binary"
	"io/fs"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/traconiq/tachoparser/pkg/decoder"
)

/*
All public keys downloaded from https://dtc.jrc.ec.europa.eu/ for "DT" (Digital Tachograph, 1st gen) and "ST" (Smart Tachograph, 2nd gen)
*/

//go:embed pks1/*.bin
var pks1 embed.FS

//go:embed pks2/*.bin
var pks2 embed.FS

func getPks1Fs() fs.FS {
	if _, err := os.Stat("./pks1/EC_PK.bin"); err == nil {
		log.Print("using pks1 live mode")
		return os.DirFS("pks1")
	}
	fSys, err := fs.Sub(pks1, "pks1")
	if err != nil {
		panic(err)
	}
	return fSys
}

func getPks2Fs() fs.FS {
	if _, err := os.Stat("./pks2/ERCA Gen2 (1) Root Certificate.bin"); err == nil {
		log.Print("using pks2 live mode")
		return os.DirFS("pks2")
	}
	fSys, err := fs.Sub(pks2, "pks2")
	if err != nil {
		panic(err)
	}
	return fSys
}

func loadPK1(path string, keyIdentifier uint64) {
	f, err := getPks1Fs().Open(path)
	if err != nil {
		log.Fatalf("error opening pk file: %s", err)
	}
	defer f.Close()
	contents, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatalf("error reading pk file: %s", err)
	}
	if len(contents) != 194 {
		log.Fatalf("error: pk file has wrong size: %v should be %v", len(contents), 194)
	}
	c := [194]byte{}
	copy(c[:], contents)
	cert := decoder.CertificateFirstGen{
		Certificate: c,
	}
	err = cert.Decode()
	if err != nil {
		log.Printf("error: could not decode certificate: %v (skipping)", err)
		return
	}
	if cert.DecodedCertificate.CertificateHolderReference != keyIdentifier {
		log.Printf("warn: CHR mismatch")
	}
	decoder.PKsFirstGen[keyIdentifier] = *cert.DecodedCertificate
}

func loadPK2(path string, keyIdentifier uint64) {
	f, err := getPks2Fs().Open(path)
	if err != nil {
		log.Fatalf("error opening pk file: %s", err)
	}
	defer f.Close()
	contents, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatalf("error reading pk file: %s", err)
	}
	if len(contents) < 204 || len(contents) > 341 {
		log.Printf("warn: pk file probably has wrong size: %v should be 204..341", len(contents))
	}
	cert := decoder.CertificateSecondGen{
		Certificate: contents,
	}
	err = cert.Decode()
	if err != nil {
		log.Printf("error: could not decode certificate: %v (skipping)", err)
		return
	}
	if cert.DecodedCertificate.CertificateBody.CertificateHolderReference != keyIdentifier {
		log.Printf("warn: CHR mismatch")
	}
	decoder.PKsSecondGen[keyIdentifier] = *cert.DecodedCertificate
}

func init() {
	// root CA - this is the only file already decoded
	// file structure
	// 0..7: key identifier
	// 8..135: modulus n
	// 136..143: exponent e
	f, err := getPks1Fs().Open("EC_PK.bin")
	if err != nil {
		log.Printf("error opening pk file: %s", err)
		return
	}
	defer f.Close()
	contentsFirstGen, err := ioutil.ReadAll(f)
	if err != nil {
		log.Printf("error reading pk file: %s", err)
		return
	}
	if len(contentsFirstGen) != 144 {
		log.Fatalf("error: root pk file has wrong size: %v should be %v", len(contentsFirstGen), 144)
	}
	var rootKeyIdentifier uint64
	buf := bytes.NewBuffer(contentsFirstGen[0:8])
	err = binary.Read(buf, binary.BigEndian, &rootKeyIdentifier)
	if err != nil {
		log.Fatalf("error parsing root key identifier: %s", err)
	}
	rootCert := decoder.DecodedCertificateFirstGen{
		CertificateHolderReference: rootKeyIdentifier,
	}
	rootCert.RsaModulus = new(big.Int).SetBytes(contentsFirstGen[8 : 8+128])
	rootCert.RsaExponent = new(big.Int).SetBytes(contentsFirstGen[8+128 : 8+128+8])
	decoder.PKsFirstGen[rootKeyIdentifier] = rootCert

	fs.WalkDir(getPks1Fs(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == "EC_PK.bin" {
			return nil // skip the root cert, we already have it
		}
		keyIdentifierStr := strings.TrimSuffix(d.Name(), ".bin")
		if len(keyIdentifierStr) == 16 {
			if keyIdentifier, err := strconv.ParseUint(keyIdentifierStr, 16, 64); err == nil {
				loadPK1(path, keyIdentifier)
			}
		}
		return nil
	})

	f2, err := getPks2Fs().Open("ERCA Gen2 (1) Root Certificate.bin")
	if err != nil {
		log.Printf("error opening pk file: %s", err)
		return
	}
	defer f2.Close()
	contentsSecondGen, err := ioutil.ReadAll(f2)
	if err != nil {
		log.Printf("error reading pk file: %s", err)
		return
	}
	if len(contentsSecondGen) < 204 || len(contentsSecondGen) > 341 {
		log.Fatalf("error: root pk file has wrong size: %v should be 204..341", len(contentsSecondGen))
	}
	cert := decoder.CertificateSecondGen{
		Certificate: contentsSecondGen,
	}
	err = cert.Decode()
	if err != nil {
		log.Fatalf("error: could not decode root pk: %v", err)
	}
	if cert.DecodedCertificate.CertificateBody.CertificateHolderReference != cert.DecodedCertificate.CertificateBody.CertificateAuthorityReference {
		log.Printf("warn: root CAR != root CHR")
	}
	decoder.PKsSecondGen[cert.DecodedCertificate.CertificateBody.CertificateHolderReference] = *cert.DecodedCertificate

	fs.WalkDir(getPks2Fs(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == "ERCA Gen2 (1) Root Certificate.bin" {
			return nil // skip the root cert, we already have it
		}
		keyIdentifierStr := strings.TrimSuffix(d.Name(), ".bin")
		if len(keyIdentifierStr) == 16 {
			if keyIdentifier, err := strconv.ParseUint(keyIdentifierStr, 16, 64); err == nil {
				loadPK2(path, keyIdentifier)
			}
		}
		return nil
	})
}
