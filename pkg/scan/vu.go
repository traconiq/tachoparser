package scan

import "errors"

// Vehicle-unit downloads are a bare sequence of transfer-response blocks, each
// introduced by a two-byte tag 0x76<TREP>. There is no length field: a gen1
// block's extent follows from its Annex 1B layout (see sizes.go), a gen2 block
// is a run of self-describing record arrays.
const vuTagLead = 0x76

const (
	trepInterfaceVersion = 0x00 // gen-neutral, precedes the data blocks

	trepOverview1      = 0x01
	trepActivities1    = 0x02
	trepEventsFaults1  = 0x03
	trepDetailedSpeed1 = 0x04
	trepTechnicalData1 = 0x05

	trepOverview2      = 0x21
	trepActivities2    = 0x22
	trepEventsFaults2  = 0x23
	trepDetailedSpeed2 = 0x24
	trepTechnicalData2 = 0x25

	// Annex 1C version 2. There is deliberately no 0x34: the specification
	// defines no v2 detailed-speed transfer.
	trepOverview2V2     = 0x31
	trepActivities2V2   = 0x32
	trepEventsFaults2V2 = 0x33
	trepTechnical2V2    = 0x35
)

// Tags a caller can require or look for. The value is the two tag bytes, so
// TagVuOverview1 is 0x7601.
const (
	TagVuInterfaceVersion uint32 = 0x7600

	TagVuOverview1      uint32 = 0x7601
	TagVuActivities1    uint32 = 0x7602
	TagVuEventsFaults1  uint32 = 0x7603
	TagVuDetailedSpeed1 uint32 = 0x7604
	TagVuTechnicalData1 uint32 = 0x7605

	TagVuOverview2      uint32 = 0x7621
	TagVuActivities2    uint32 = 0x7622
	TagVuEventsFaults2  uint32 = 0x7623
	TagVuDetailedSpeed2 uint32 = 0x7624
	TagVuTechnicalData2 uint32 = 0x7625

	TagVuOverview2V2     uint32 = 0x7631
	TagVuActivities2V2   uint32 = 0x7632
	TagVuEventsFaults2V2 uint32 = 0x7633
	TagVuTechnical2V2    uint32 = 0x7635
)

// recordTypeSignature terminates a gen2 block: the signature record array is
// always its last element.
const recordTypeSignature = 0x08

// maxRecordArrays bounds the gen2 inner walk. The widest block defined by the
// specification is nowhere near this; exceeding it means the walk lost sync.
const maxRecordArrays = 128

var errRunaway = errors.New("implausible number of records")

// ScanVu walks a vehicle-unit download and reports its structure. The report is
// always non-nil, and holds the blocks read before any failure. The error is
// the first fatal problem, so callers that only care whether the file is usable
// can ignore the report.
func ScanVu(data []byte) (*Report, error) {
	r := &Report{Kind: KindVu, Size: len(data), Tags: make(map[uint32]int)}
	if len(data) == 0 {
		r.add(CodeEmpty, SeverityFatal, 0, "no data")
		return r, r.Err()
	}

	p := 0
walk:
	for p < len(data) {
		if len(r.Blocks) >= maxBlocks {
			r.add(CodeRunaway, SeverityFatal, p, "more than %d blocks", maxBlocks)
			break
		}
		// A tag must start with 0x76. Anything else is either the padding some
		// devices append, or the point at which the walk lost the thread.
		if data[p] != vuTagLead {
			if isPadding(data[p:]) {
				r.Padding = len(data) - p
				p = len(data)
				break
			}
			r.add(CodeUnknownTag, SeverityFatal, p, "expected a 0x76 transfer response tag, found 0x%02x", data[p])
			break
		}
		if p+2 > len(data) {
			r.add(CodeTruncated, SeverityFatal, p, "file ends inside a block tag")
			break
		}

		trep := data[p+1]
		tag := uint32(vuTagLead)<<8 | uint32(trep)
		gen := vuGeneration(trep)
		payload := data[p+2:]

		var (
			n   int
			err error
		)
		switch {
		case trep == trepInterfaceVersion:
			n, err = advance(payload, 0, widthInterfaceVersion)
		case gen == Gen1:
			n, err = gen1BlockSize(trep, payload)
		case gen == Gen2:
			n, err = gen2BlockSize(payload)
		default:
			// Unknown tag and no length field: there is no way to skip it, so
			// the walk has to stop here. Consumed stays at p, which is where a
			// reader of the quarantined file should start looking.
			r.add(CodeUnknownTag, SeverityFatal, p, "unknown transfer response 0x%04x", tag)
			break walk
		}
		if err != nil {
			switch {
			case errors.Is(err, errRunaway):
				r.add(CodeRunaway, SeverityFatal, p, "block 0x%04x: %v", tag, err)
			case errors.Is(err, errUnknownTrep):
				r.add(CodeUnknownTag, SeverityFatal, p, "unknown transfer response 0x%04x", tag)
			default:
				r.add(CodeTruncated, SeverityFatal, p, "block 0x%04x: %v (%d bytes left)", tag, err, len(payload))
			}
			break
		}

		r.block(Block{Tag: tag, Gen: gen, Offset: p, Header: 2, Length: n})
		p += 2 + n
	}

	r.Consumed = p
	if p < len(data) && r.Fatal() == nil {
		// unreachable while every early exit records a problem, but a silent
		// short read would be the worst possible outcome here
		r.add(CodeTrailingData, SeverityFatal, p, "%d bytes after the last block", len(data)-p)
	}
	if len(r.Blocks) == 0 && r.Fatal() == nil {
		// nothing but fill: a transfer that failed outright still arrives with
		// a plausible length, and the padding rule above would accept it
		r.add(CodeNoBlocks, SeverityFatal, 0, "no blocks at all (%d bytes of fill)", r.Padding)
	}
	return r, r.Err()
}

// gen2BlockSize returns the payload length of a gen2 block. Every element is a
// record array — record type, record size, record count, then the records — so
// the block describes its own extent and ends with the signature array.
func gen2BlockSize(d []byte) (int, error) {
	p := 0
	for i := 0; i < maxRecordArrays; i++ {
		if p+5 > len(d) {
			return 0, errShort
		}
		recordType := d[p]
		recordSize := be16(d[p+1 : p+3])
		count := be16(d[p+3 : p+5])
		var err error
		if p, err = advance(d, p+5, recordSize*count); err != nil {
			return 0, err
		}
		if recordType == recordTypeSignature {
			return p, nil
		}
	}
	return 0, errRunaway
}

func vuGeneration(trep byte) Generation {
	switch trep {
	case trepOverview1, trepActivities1, trepEventsFaults1, trepDetailedSpeed1, trepTechnicalData1:
		return Gen1
	case trepOverview2, trepActivities2, trepEventsFaults2, trepDetailedSpeed2, trepTechnicalData2,
		trepOverview2V2, trepActivities2V2, trepEventsFaults2V2, trepTechnical2V2:
		return Gen2
	}
	return GenUnknown
}
