package scan

// Driver card downloads are plain TLV: a three-byte tag (the two-byte file
// identifier plus an appendix byte) followed by a big-endian uint16 length and
// that many payload bytes. The appendix distinguishes generation and content:
// 0x00 gen1 data, 0x01 gen1 signature, 0x02 gen2 data, 0x03 gen2 signature.
const cardHeaderLen = 5

// Tags a caller is likely to require. The rest of the known set lives in
// cardTags; these are named because they are the ones that carry identity and
// the ones a usable card file is expected to have.
const (
	TagCardIccIdentification1 uint32 = 0x000200
	TagCardIccIdentification2 uint32 = 0x000202
	TagCardApplicationId1     uint32 = 0x050100
	TagCardApplicationId2     uint32 = 0x050102
	TagCardEventData1         uint32 = 0x050200
	TagCardEventData2         uint32 = 0x050202
	TagCardDriverActivity1    uint32 = 0x050400
	TagCardDriverActivity2    uint32 = 0x050402
	TagCardVehiclesUsed1      uint32 = 0x050500
	TagCardVehiclesUsed2      uint32 = 0x050502
	TagCardPlaceDailyWork1    uint32 = 0x050600
	TagCardPlaceDailyWork2    uint32 = 0x050602
	TagCardIdentification1    uint32 = 0x052000
	TagCardIdentification2    uint32 = 0x052002
)

// cardTags is the set of tags the decoder knows. It is used only to flag the
// unexpected — an unknown tag is recorded and skipped, because unlike a vu
// block a card record states its own length, so one unrecognised record does
// not cost us the rest of the file.
//
// TestCardTagsMatchDecoder keeps this in step with the decoder's struct tags.
var cardTags = map[uint32]bool{
	0x000200: true, 0x000201: true, 0x000202: true, 0x000203: true,
	0x000500: true, 0x000501: true, 0x000502: true, 0x000503: true,
	0x050100: true, 0x050101: true, 0x050102: true, 0x050103: true,
	0x050200: true, 0x050201: true, 0x050202: true, 0x050203: true,
	0x050300: true, 0x050301: true, 0x050302: true, 0x050303: true,
	0x050400: true, 0x050401: true, 0x050402: true, 0x050403: true,
	0x050500: true, 0x050501: true, 0x050502: true, 0x050503: true,
	0x050600: true, 0x050601: true, 0x050602: true, 0x050603: true,
	0x050700: true, 0x050701: true, 0x050702: true, 0x050703: true,
	0x050800: true, 0x050801: true, 0x050802: true, 0x050803: true,
	0x050e00: true, 0x050e01: true, 0x050e02: true, 0x050e03: true,
	0x052000: true, 0x052001: true, 0x052002: true, 0x052003: true,
	0x052100: true, 0x052101: true, 0x052102: true, 0x052103: true,
	0x052200: true, 0x052201: true, 0x052202: true, 0x052203: true,
	0x052302: true, 0x052303: true,
	0x052402: true, 0x052403: true,
	0x052502: true, 0x052503: true,
	0x052602: true, 0x052603: true,
	0x052702: true, 0x052703: true,
	0x052802: true, 0x052803: true,
	0x052902: true, 0x052903: true,
	0x053002: true, 0x053003: true,
	0x054002: true, 0x054003: true,
	0xc10000: true, 0xc10002: true, 0xc10102: true,
	0xc10800: true, 0xc10802: true, 0xc10902: true,
}

// ScanCard walks a driver-card download and reports its structure. As for
// ScanVu the report is always non-nil and the error is the first fatal problem.
func ScanCard(data []byte) (*Report, error) {
	r := &Report{Kind: KindCard, Size: len(data), Tags: make(map[uint32]int)}
	if len(data) == 0 {
		r.add(CodeEmpty, SeverityFatal, 0, "no data")
		return r, r.Err()
	}

	p := 0
	for p < len(data) {
		if len(r.Blocks) >= maxBlocks {
			r.add(CodeRunaway, SeverityFatal, p, "more than %d records", maxBlocks)
			break
		}
		if p+cardHeaderLen > len(data) {
			// A short tail is fill, not a record — as long as that is all it is.
			if isPadding(data[p:]) {
				r.Padding = len(data) - p
				p = len(data)
				break
			}
			r.add(CodeTruncated, SeverityFatal, p, "%d bytes left, too few for a record header", len(data)-p)
			break
		}

		tag := be24(data[p:])
		length := be16(data[p+3 : p+5])

		// An all-zero (or all-0xff) header is where the real records stop and
		// the card's own fill begins. Treat it as the end, provided the rest of
		// the file really is fill.
		if (tag == 0x000000 || tag == 0xffffff) && (length == 0x0000 || length == 0xffff) {
			if isPadding(data[p:]) {
				r.Padding = len(data) - p
				p = len(data)
				break
			}
			r.add(CodeTrailingData, SeverityFatal, p, "empty record header followed by %d bytes that are not fill", len(data)-p)
			break
		}

		end := p + cardHeaderLen + length
		if end > len(data) || end < p {
			r.add(CodeTruncated, SeverityFatal, p,
				"record 0x%06x claims %d bytes, only %d left", tag, length, len(data)-p-cardHeaderLen)
			break
		}
		if !cardTags[tag] {
			// Recoverable: the length is trustworthy enough to step over it,
			// and the walk still has to land exactly on the end of the file.
			r.add(CodeUnknownTag, SeverityWarning, p, "unknown record 0x%06x (%d bytes)", tag, length)
		}

		r.block(Block{Tag: tag, Gen: cardGeneration(tag), Offset: p, Header: cardHeaderLen, Length: length})
		p = end
	}

	r.Consumed = p
	if p < len(data) && r.Fatal() == nil {
		r.add(CodeTrailingData, SeverityFatal, p, "%d bytes after the last record", len(data)-p)
	}
	if len(r.Blocks) == 0 && r.Fatal() == nil {
		r.add(CodeNoBlocks, SeverityFatal, 0, "no records at all (%d bytes of fill)", r.Padding)
	}
	return r, r.Err()
}

// cardGeneration reads the generation out of the tag's appendix byte.
func cardGeneration(tag uint32) Generation {
	switch tag & 0xff {
	case 0x00, 0x01:
		return Gen1
	case 0x02, 0x03:
		return Gen2
	}
	return GenUnknown
}
