package scan_test

// What the package is actually for: taking a real download, breaking it the way
// a bad transfer breaks it, and confirming the walk says so.

import (
	"testing"

	"github.com/traconiq/tachoparser/pkg/scan"
)

// firstGoodVuGen1 returns a corpus file that actually exercises the gen1 size
// model. Picking whatever comes first would quietly test gen2 twice.
func firstGoodVuGen1(t *testing.T) []byte {
	t.Helper()
	vu, _ := corpusFiles(t)
	for _, p := range vu {
		data := read(t, p)
		if rep, err := scan.ScanVu(data); err == nil && rep.HasGen1 {
			return data
		}
	}
	t.Skip("no gen1 vu file in the corpus scans cleanly")
	return nil
}

func firstGoodCard(t *testing.T) []byte {
	t.Helper()
	_, card := corpusFiles(t)
	for _, p := range card {
		data := read(t, p)
		if _, err := scan.ScanCard(data); err == nil {
			return data
		}
	}
	t.Skip("no card file in the corpus scans cleanly")
	return nil
}

func TestEmptyInput(t *testing.T) {
	for _, c := range []struct {
		name string
		scan func([]byte) (*scan.Report, error)
	}{
		{"vu", scan.ScanVu},
		{"card", scan.ScanCard},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep, err := c.scan(nil)
			if err == nil {
				t.Fatal("empty input accepted")
			}
			if rep.Fatal().Code != scan.CodeEmpty {
				t.Errorf("code = %q, want %q", rep.Fatal().Code, scan.CodeEmpty)
			}
		})
	}
}

// TestVuTruncatedMidBlock is the headline case: a transfer that stopped part
// way through. The CRC would catch this only if the device noticed; when the
// device CRCs its own short buffer, this walk is what is left.
func TestVuTruncatedMidBlock(t *testing.T) {
	good := firstGoodVuGen1(t)
	rep, _ := scan.ScanVu(good)
	if len(rep.Blocks) < 2 {
		t.Skip("need a file with at least two blocks")
	}
	last := rep.Blocks[len(rep.Blocks)-1]
	if last.Length < 4 {
		t.Skip("last block too small to truncate meaningfully")
	}

	// cut inside the final block, not on its boundary
	cut := last.Offset + last.Header + last.Length/2
	rep, err := scan.ScanVu(good[:cut])
	if err == nil {
		t.Fatalf("truncated file accepted (%d of %d bytes)", cut, len(good))
	}
	if got := rep.Fatal().Code; got != scan.CodeTruncated {
		t.Errorf("code = %q, want %q (%v)", got, scan.CodeTruncated, rep.Fatal())
	}
}

// TestVuTruncatedOnBlockBoundary documents a real limit rather than a bug: a
// transfer cut exactly between two blocks yields a shorter file that is still
// structurally sound. Catching that needs the announced size or a required-tag
// policy, not the walk.
func TestVuTruncatedOnBlockBoundary(t *testing.T) {
	good := firstGoodVuGen1(t)
	rep, _ := scan.ScanVu(good)
	if len(rep.Blocks) < 2 {
		t.Skip("need a file with at least two blocks")
	}
	boundary := rep.Blocks[len(rep.Blocks)-1].Offset

	short, err := scan.ScanVu(good[:boundary])
	if err != nil {
		t.Fatalf("a file cut on a block boundary should still walk: %v", err)
	}
	if short.Consumed != boundary {
		t.Errorf("consumed %d, want %d", short.Consumed, boundary)
	}
	if len(short.Blocks) != len(rep.Blocks)-1 {
		t.Errorf("got %d blocks, want %d", len(short.Blocks), len(rep.Blocks)-1)
	}
}

func TestVuTrailingGarbage(t *testing.T) {
	good := firstGoodVuGen1(t)
	broken := append(append([]byte{}, good...), 0xde, 0xad, 0xbe, 0xef)

	rep, err := scan.ScanVu(broken)
	if err == nil {
		t.Fatal("file with a garbage tail accepted")
	}
	if got := rep.Fatal().Code; got != scan.CodeUnknownTag && got != scan.CodeTrailingData {
		t.Errorf("code = %q, want unknown_tag or trailing_data (%v)", got, rep.Fatal())
	}
}

// TestVuTrailingPadding is the other side of the same coin: fill must not be
// mistaken for corruption, or every padded download gets rejected.
func TestVuTrailingPadding(t *testing.T) {
	good := firstGoodVuGen1(t)
	for _, fill := range []byte{0x00, 0xff} {
		padded := append([]byte{}, good...)
		for i := 0; i < 64; i++ {
			padded = append(padded, fill)
		}
		rep, err := scan.ScanVu(padded)
		if err != nil {
			t.Errorf("fill 0x%02x: padded file rejected: %v", fill, err)
			continue
		}
		if rep.Padding != 64 {
			t.Errorf("fill 0x%02x: padding = %d, want 64", fill, rep.Padding)
		}
	}
}

// TestVuCorruptGen1Count corrupts a record count in a gen1 block. The block
// then claims a different extent than it has, so the walk either runs off the
// end of the file or lands on something that is not a tag. This is the check
// that the gen1 size model is doing real work and not just adding up to the
// file length by luck.
//
// The byte chosen is NoOfVuFaults, the first payload byte of an events-and-
// faults block — one of the few counts whose offset within its block is fixed,
// so the test does not have to restate the size model to find one.
func TestVuCorruptGen1Count(t *testing.T) {
	good := firstGoodVuGen1(t)
	rep, _ := scan.ScanVu(good)

	var target *scan.Block
	for i := range rep.Blocks {
		if rep.Blocks[i].Tag == scan.TagVuEventsFaults1 {
			target = &rep.Blocks[i]
			break
		}
	}
	if target == nil {
		t.Skip("no gen1 events-and-faults block in the corpus file")
	}

	broken := append([]byte{}, good...)
	broken[target.Offset+target.Header] ^= 0x7f

	if _, err := scan.ScanVu(broken); err == nil {
		t.Error("a corrupted gen1 record count was accepted")
	}
}

// TestVuCorruptPayloadIsInvisible records the boundary of what this package
// claims. Flipping bytes that are neither a tag nor a length leaves the framing
// intact, and the walk says so — correctly. Detecting that would mean verifying
// the signatures, which is what DEV-4927 established we cannot do.
func TestVuCorruptPayloadIsInvisible(t *testing.T) {
	good := firstGoodVuGen1(t)
	rep, _ := scan.ScanVu(good)

	var target *scan.Block
	for i := range rep.Blocks {
		if rep.Blocks[i].Tag == scan.TagVuOverview1 {
			target = &rep.Blocks[i]
			break
		}
	}
	if target == nil {
		t.Skip("no gen1 overview block")
	}

	broken := append([]byte{}, good...)
	// somewhere inside the member state certificate: opaque to the walk
	broken[target.Offset+target.Header+64] ^= 0xff

	if _, err := scan.ScanVu(broken); err != nil {
		t.Errorf("payload corruption should leave the framing intact, got: %v", err)
	}
}

func TestCardCorruptLength(t *testing.T) {
	good := firstGoodCard(t)
	rep, _ := scan.ScanCard(good)
	if len(rep.Blocks) == 0 {
		t.Skip("no records")
	}
	first := rep.Blocks[0]

	broken := append([]byte{}, good...)
	// inflate the first record's length so the walk cannot land on the end
	broken[first.Offset+3] = 0x7f
	broken[first.Offset+4] = 0xff

	if _, err := scan.ScanCard(broken); err == nil {
		t.Error("a card record claiming more bytes than the file holds was accepted")
	}
}

func TestCardTruncated(t *testing.T) {
	good := firstGoodCard(t)
	rep, _ := scan.ScanCard(good)
	if len(rep.Blocks) < 2 {
		t.Skip("need at least two records")
	}
	last := rep.Blocks[len(rep.Blocks)-1]
	if last.Length < 4 {
		t.Skip("last record too small to truncate meaningfully")
	}

	cut := last.Offset + last.Header + last.Length/2
	r, err := scan.ScanCard(good[:cut])
	if err == nil {
		t.Fatalf("truncated card file accepted (%d of %d bytes)", cut, len(good))
	}
	if got := r.Fatal().Code; got != scan.CodeTruncated {
		t.Errorf("code = %q, want %q (%v)", got, scan.CodeTruncated, r.Fatal())
	}
}

// TestCardAllZeros is the shape a completely failed transfer takes: the right
// length, no content.
func TestCardAllZeros(t *testing.T) {
	rep, err := scan.ScanCard(make([]byte, 4096))
	if err == nil {
		t.Fatal("an all-zero card file was accepted")
	}
	if len(rep.Blocks) != 0 {
		t.Errorf("found %d records in an all-zero file", len(rep.Blocks))
	}
}

func TestVuAllZeros(t *testing.T) {
	if _, err := scan.ScanVu(make([]byte, 4096)); err == nil {
		t.Fatal("an all-zero vu file was accepted")
	}
}

func TestReportMissing(t *testing.T) {
	good := firstGoodVuGen1(t)
	rep, err := scan.ScanVu(good)
	if err != nil {
		t.Fatal(err)
	}
	// a tag no vu download carries
	missing := rep.Missing(scan.TagVuOverview1, scan.TagVuOverview2, 0x76ff)
	found := false
	for _, m := range missing {
		if m == 0x76ff {
			found = true
		}
	}
	if !found {
		t.Errorf("Missing did not report the absent tag: %#v", missing)
	}
}
