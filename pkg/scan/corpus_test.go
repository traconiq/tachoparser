package scan_test

// The corpus test is the reason this package lives in tachoparser rather than
// in the consumer: only here are both a set of real downloads and the
// reflection decoder available, so the cheap walk can be checked against the
// expensive one on genuine files. Everything in sizes.go is only as good as
// this test.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/traconiq/tachoparser/pkg/decoder"
	"github.com/traconiq/tachoparser/pkg/scan"
)

const corpusDir = "../../test/data"

// corpusFiles returns the vu and card downloads in the test corpus. Card files
// are the ones named C_*, which is the convention the archive uses.
func corpusFiles(t *testing.T) (vu, card []string) {
	t.Helper()
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Skipf("no corpus at %s: %v", corpusDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".ddd") {
			continue
		}
		p := filepath.Join(corpusDir, e.Name())
		if strings.HasPrefix(e.Name(), "C_") {
			card = append(card, p)
		} else {
			vu = append(vu, p)
		}
	}
	if len(vu)+len(card) == 0 {
		t.Skipf("corpus at %s holds no .DDD files", corpusDir)
	}
	return vu, card
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// TestScanVuCorpus is the load-bearing check on the gen1 size model. A wrong
// record width desynchronises the walk, and a desynchronised walk cannot land
// exactly on the end of the file with every tag recognised — it fails here
// rather than in production on a customer's download.
func TestScanVuCorpus(t *testing.T) {
	vu, _ := corpusFiles(t)
	for _, path := range vu {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data := read(t, path)
			rep, err := scan.ScanVu(data)
			if err != nil {
				t.Fatalf("scan failed: %v (consumed %d of %d bytes, %d blocks)",
					err, rep.Consumed, rep.Size, len(rep.Blocks))
			}
			if rep.Consumed != rep.Size {
				t.Errorf("consumed %d of %d bytes", rep.Consumed, rep.Size)
			}
			if len(rep.Blocks) == 0 {
				t.Fatal("no blocks found")
			}
			for _, b := range rep.Blocks {
				if b.Length < 0 || b.End() > rep.Size {
					t.Errorf("block 0x%04x at %d runs to %d, past the end", b.Tag, b.Offset, b.End())
				}
			}
			t.Logf("%d blocks, gen1=%v gen2=%v, %d padding bytes",
				len(rep.Blocks), rep.HasGen1, rep.HasGen2, rep.Padding)
		})
	}
}

// TestScanVuAgreesWithDecoder pins the block boundaries, not just the total.
// The scanner's per-tag block count must match how many blocks the decoder
// parsed out of the same file: a size model that happened to end in the right
// place while mis-splitting the blocks would pass the walk but fail here.
func TestScanVuAgreesWithDecoder(t *testing.T) {
	vu, _ := corpusFiles(t)
	for _, path := range vu {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data := read(t, path)
			rep, err := scan.ScanVu(data)
			if err != nil {
				t.Skipf("scan rejected the file, covered by TestScanVuCorpus: %v", err)
			}

			var v decoder.Vu
			if _, err := decoder.UnmarshalTV(data, &v); err != nil {
				t.Skipf("decoder could not parse this file either: %v", err)
			}

			for _, c := range []struct {
				tag  uint32
				name string
				n    int
			}{
				{scan.TagVuActivities1, "vu_activities_1", len(v.VuActivitiesFirstGen)},
				{scan.TagVuEventsFaults1, "vu_events_and_faults_1", len(v.VuEventsAndFaultsFirstGen)},
				{scan.TagVuDetailedSpeed1, "vu_detailed_speed_1", len(v.VuDetailedSpeedFirstGen)},
				{scan.TagVuTechnicalData1, "vu_technical_data_1", len(v.VuTechnicalDataFirstGen)},
				{scan.TagVuActivities2, "vu_activities_2", len(v.VuActivitiesSecondGen)},
				{scan.TagVuEventsFaults2, "vu_events_and_faults_2", len(v.VuEventsAndFaultsSecondGen)},
				{scan.TagVuDetailedSpeed2, "vu_detailed_speed_2", len(v.VuDetailedSpeedSecondGen)},
				{scan.TagVuTechnicalData2, "vu_technical_data_2", len(v.VuTechnicalDataSecondGen)},
				{scan.TagVuActivities2V2, "vu_activities_2_v2", len(v.VuActivitiesSecondGenV2)},
				{scan.TagVuEventsFaults2V2, "vu_events_and_faults_2_v2", len(v.VuEventsAndFaultsSecondGenV2)},
				{scan.TagVuTechnical2V2, "vu_technical_data_2_v2", len(v.VuTechnicalDataSecondGenV2)},
			} {
				if got := rep.Tags[c.tag]; got != c.n {
					t.Errorf("%s (0x%04x): scanner found %d blocks, decoder %d", c.name, c.tag, got, c.n)
				}
			}
		})
	}
}

func TestScanCardCorpus(t *testing.T) {
	_, card := corpusFiles(t)
	for _, path := range card {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data := read(t, path)
			rep, err := scan.ScanCard(data)
			if err != nil {
				t.Fatalf("scan failed: %v (consumed %d of %d bytes, %d records)",
					err, rep.Consumed, rep.Size, len(rep.Blocks))
			}
			if rep.Consumed != rep.Size {
				t.Errorf("consumed %d of %d bytes", rep.Consumed, rep.Size)
			}
			if len(rep.Blocks) == 0 {
				t.Fatal("no records found")
			}
			for _, p := range rep.Problems {
				t.Logf("problem: %v", p)
			}
			t.Logf("%d records, gen1=%v gen2=%v, %d padding bytes",
				len(rep.Blocks), rep.HasGen1, rep.HasGen2, rep.Padding)
		})
	}
}

// TestDetectCorpus checks the framing sniffer against files whose kind we know
// from the archive naming convention, so tooling handed a bare file can pick
// the right walker.
func TestDetectCorpus(t *testing.T) {
	vu, card := corpusFiles(t)
	for _, path := range vu {
		if got := scan.Detect(read(t, path)); got != scan.KindVu {
			t.Errorf("%s: Detect = %q, want %q", filepath.Base(path), got, scan.KindVu)
		}
	}
	for _, path := range card {
		if got := scan.Detect(read(t, path)); got != scan.KindCard {
			t.Errorf("%s: Detect = %q, want %q", filepath.Base(path), got, scan.KindCard)
		}
	}
}

// TestScanDispatches checks that the kind-agnostic entry point reaches the same
// verdict as calling the right walker directly.
func TestScanDispatches(t *testing.T) {
	vu, card := corpusFiles(t)
	for _, path := range append(append([]string{}, vu...), card...) {
		data := read(t, path)
		got, gotErr := scan.Scan(data)
		var want *scan.Report
		var wantErr error
		if scan.Detect(data) == scan.KindCard {
			want, wantErr = scan.ScanCard(data)
		} else {
			want, wantErr = scan.ScanVu(data)
		}
		if (gotErr == nil) != (wantErr == nil) || got.Kind != want.Kind || len(got.Blocks) != len(want.Blocks) {
			t.Errorf("%s: Scan disagrees with the direct walker", filepath.Base(path))
		}
	}
}

func TestDetectRejectsRubbish(t *testing.T) {
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"too short", []byte{0x76}},
		{"not a ddd file", []byte("this is a text file, not a download")},
		{"zeros", make([]byte, 64)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scan.Detect(c.data); got != scan.KindUnknown {
				t.Errorf("Detect = %q, want unknown", got)
			}
			if _, err := scan.Scan(c.data); err == nil {
				t.Error("Scan accepted something that is not a download")
			}
		})
	}
}
