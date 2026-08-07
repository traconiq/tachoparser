// Package scan checks that a downloaded tachograph file is structurally intact
// without decoding it.
//
// It exists because a corrupt download that still parses far enough to be named
// looks, to everything downstream, exactly like a good one: it gets archived,
// uploaded and delivered, so nobody retries it and the gap only surfaces months
// later when the data is asked for (DEV-4927).
//
// The obvious answer — verify the digital signatures — is not usable. A large
// share of genuinely valid files fail verification in practice, and it requires
// running the full ASN.1 decoder, which does not cope with production ingest
// volume. So this package deliberately does much less: it walks the file's own
// framing from the first byte to the last and reports whether the structure
// adds up. One linear pass, no reflection, no allocation per record, standard
// library only.
//
// What that catches is truncation, padding, desynchronised lengths and garbage
// tails — the failure modes a transport CRC misses because the device computed
// it over its own already-corrupt buffer.
//
// Scan does not decide anything. It reports what it found, including the tags
// present, so the caller can apply its own policy: which blocks are required
// differs per fleet, and a valid file does not have to contain everything.
//
// # Cost
//
// This package must not import pkg/decoder, directly or transitively. Doing so
// would pull the reflection tables and the embedded certificates into every
// binary that only wants the cheap check. TestNoDecoderImport enforces it.
package scan

import (
	"errors"
	"fmt"
)

// Kind distinguishes the two download types, which have entirely different
// framing.
type Kind string

const (
	KindVu   Kind = "vu"   // vehicle unit download
	KindCard Kind = "card" // driver card download
)

// Generation is the tachograph generation a block belongs to.
type Generation uint8

const (
	GenUnknown Generation = 0
	Gen1       Generation = 1 // Annex 1B
	Gen2       Generation = 2 // Annex 1C, both versions
)

func (g Generation) String() string {
	switch g {
	case Gen1:
		return "gen1"
	case Gen2:
		return "gen2"
	}
	return "unknown"
}

// Block is one top-level unit of the file: a TREP block in a vu download, an
// elementary file record in a card download.
type Block struct {
	Tag    uint32     // 0x7601 for vu blocks, 0x050200 for card records
	Gen    Generation // generation the tag belongs to
	Offset int        // offset of the tag itself
	Header int        // bytes of framing before the payload (tag, and length for card)
	Length int        // payload length in bytes
}

// End is the offset one past the block.
func (b Block) End() int { return b.Offset + b.Header + b.Length }

// Code classifies a problem so callers can act on categories rather than parse
// message text.
type Code string

const (
	CodeEmpty        Code = "empty"         // no data at all
	CodeTruncated    Code = "truncated"     // a block runs past the end of the file
	CodeUnknownTag   Code = "unknown_tag"   // tag not in the known set
	CodeTrailingData Code = "trailing_data" // bytes after the last block that are not padding
	CodeRunaway      Code = "runaway"       // implausible block or record-array count
	// CodeNoBlocks: the file has a length but holds nothing. A transfer that
	// failed outright arrives as the right number of bytes of fill, which the
	// padding rule would otherwise swallow without complaint.
	CodeNoBlocks Code = "no_blocks"
)

// Severity says whether a problem invalidates the file. Warnings are recorded
// so an operator can see them without the download being rejected; the caller
// remains free to treat them as fatal.
type Severity uint8

const (
	SeverityWarning Severity = iota
	SeverityFatal
)

func (s Severity) String() string {
	if s == SeverityFatal {
		return "fatal"
	}
	return "warning"
}

// Problem is one finding, anchored at the byte offset where it was noticed.
type Problem struct {
	Code     Code
	Severity Severity
	Offset   int
	Detail   string
}

func (p Problem) Error() string {
	return fmt.Sprintf("%s at offset %d: %s", p.Code, p.Offset, p.Detail)
}

// Report is what a scan found. It is always returned, including when the walk
// failed part way: Blocks then holds what was read before the failure, which is
// what makes a quarantined file diagnosable.
type Report struct {
	Kind     Kind
	Size     int // length of the input
	Consumed int // bytes accounted for by blocks and padding
	Padding  int // trailing 0x00/0xff fill, tolerated
	Blocks   []Block
	Tags     map[uint32]int // tag -> number of occurrences
	HasGen1  bool
	HasGen2  bool
	Problems []Problem
}

// OK reports whether the file is structurally sound: every byte accounted for
// and no fatal problem.
func (r *Report) OK() bool { return r.Fatal() == nil }

// Fatal returns the first fatal problem, or nil.
func (r *Report) Fatal() *Problem {
	for i := range r.Problems {
		if r.Problems[i].Severity == SeverityFatal {
			return &r.Problems[i]
		}
	}
	return nil
}

// Err returns the first fatal problem as an error, or nil, so callers can use
// the ordinary Go shape without walking Problems.
func (r *Report) Err() error {
	if p := r.Fatal(); p != nil {
		return *p
	}
	return nil
}

// Has reports whether the file contains at least one block with this tag.
func (r *Report) Has(tag uint32) bool { return r.Tags[tag] > 0 }

// Missing returns those of the required tags that are absent. Which tags are
// required is a policy question — not every valid file contains everything —
// so the caller supplies the set.
func (r *Report) Missing(required ...uint32) []uint32 {
	var missing []uint32
	for _, t := range required {
		if !r.Has(t) {
			missing = append(missing, t)
		}
	}
	return missing
}

func (r *Report) add(code Code, sev Severity, offset int, format string, args ...interface{}) {
	r.Problems = append(r.Problems, Problem{
		Code:     code,
		Severity: sev,
		Offset:   offset,
		Detail:   fmt.Sprintf(format, args...),
	})
}

func (r *Report) block(b Block) {
	r.Blocks = append(r.Blocks, b)
	if r.Tags == nil {
		r.Tags = make(map[uint32]int)
	}
	r.Tags[b.Tag]++
	switch b.Gen {
	case Gen1:
		r.HasGen1 = true
	case Gen2:
		r.HasGen2 = true
	}
}

// internal sentinels, translated into Problems by the walkers
var (
	errShort       = errors.New("data ends inside the block")
	errUnknownTrep = errors.New("unknown transfer response tag")
)

// maxBlocks bounds both walkers. A real download is a few dozen blocks for a
// vu (one activities block per day of the period) and well under a hundred
// records for a card; anything beyond this is a desynchronised walk chewing
// through garbage, and stopping keeps a corrupt file from costing real time.
const maxBlocks = 4096

func be16(d []byte) int { return int(d[0])<<8 | int(d[1]) }
func be24(d []byte) uint32 {
	return uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
}

// isPadding reports whether d is entirely 0x00 or entirely 0xff. Cards and some
// vus pad the tail of a transfer to a block boundary, and that padding must not
// be mistaken for corruption.
func isPadding(d []byte) bool {
	if len(d) == 0 {
		return true
	}
	fill := d[0]
	if fill != 0x00 && fill != 0xff {
		return false
	}
	for _, b := range d {
		if b != fill {
			return false
		}
	}
	return true
}
