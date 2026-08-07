package scan

// Detect reports whether data looks like a vehicle-unit or a driver-card
// download, or KindUnknown if it is neither.
//
// The two framings are distinguishable from the first bytes: a vu download
// opens with a transfer-response tag, which always begins 0x76, while a card
// download opens with a TLV record whose three-byte tag is an elementary file
// identifier — none of which start with 0x76. Callers that already know which
// kind they asked the device for should not use this; it is for tooling handed
// a file with nothing but its contents to go on.
//
// Detection is deliberately shallow: it identifies the framing, it does not
// validate. A truncated or corrupt file of either kind is still detected as
// that kind, which is the point — you want ScanVu/ScanCard to then say what is
// wrong with it, rather than being told "unknown" and learning nothing.
func Detect(data []byte) Kind {
	if len(data) < 3 {
		return KindUnknown
	}
	if data[0] == vuTagLead {
		return KindVu
	}
	if cardTags[be24(data)] {
		return KindCard
	}
	return KindUnknown
}

// KindUnknown is returned by Detect when the leading bytes match neither
// framing.
const KindUnknown Kind = ""

// Scan dispatches to ScanVu or ScanCard according to Detect. It returns a
// report with a single fatal problem when the framing is unrecognisable, so a
// caller can treat "not a DDD file at all" the same way as any other rejection.
func Scan(data []byte) (*Report, error) {
	switch Detect(data) {
	case KindVu:
		return ScanVu(data)
	case KindCard:
		return ScanCard(data)
	}
	r := &Report{Size: len(data), Tags: make(map[uint32]int)}
	if len(data) == 0 {
		r.add(CodeEmpty, SeverityFatal, 0, "no data")
		return r, r.Err()
	}
	r.add(CodeUnknownTag, SeverityFatal, 0,
		"not a tachograph download: starts with 0x%s, which is neither a vu transfer response nor a known card record", hexPrefix(data))
	return r, r.Err()
}

func hexPrefix(data []byte) string {
	const digits = "0123456789abcdef"
	n := 3
	if len(data) < n {
		n = len(data)
	}
	out := make([]byte, 0, n*2)
	for _, b := range data[:n] {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}
