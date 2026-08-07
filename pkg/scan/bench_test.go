package scan_test

// The premise of this package is that it is cheap enough to run inside the tco4
// device connection handler, where the full decoder is not. That premise is
// worth measuring rather than asserting, so the decoder is benchmarked next to
// the walk on the same files.

import (
	"os"
	"testing"

	"github.com/traconiq/tachoparser/pkg/decoder"
	"github.com/traconiq/tachoparser/pkg/scan"
)

func benchInput(b *testing.B, wantGen1 bool) []byte {
	b.Helper()
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		b.Skipf("no corpus: %v", err)
	}
	var best []byte
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) < 4 || e.Name()[0] == 'C' {
			continue
		}
		data, err := os.ReadFile(corpusDir + "/" + e.Name())
		if err != nil {
			continue
		}
		rep, err := scan.ScanVu(data)
		if err != nil || rep.HasGen1 != wantGen1 {
			continue
		}
		// the largest matching file, so the numbers mean something
		if len(data) > len(best) {
			best = data
		}
	}
	if best == nil {
		b.Skip("no matching corpus file")
	}
	return best
}

func BenchmarkScanVuGen1(b *testing.B) {
	data := benchInput(b, true)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scan.ScanVu(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanVuGen2(b *testing.B) {
	data := benchInput(b, false)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scan.ScanVu(data); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecodeVuGen1 is the comparison, not a target. It is what the tco4
// path would pay per download if validation meant decoding.
func BenchmarkDecodeVuGen1(b *testing.B) {
	data := benchInput(b, true)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var v decoder.Vu
		if _, err := decoder.UnmarshalTV(data, &v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeVuGen2(b *testing.B) {
	data := benchInput(b, false)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var v decoder.Vu
		if _, err := decoder.UnmarshalTV(data, &v); err != nil {
			b.Fatal(err)
		}
	}
}
