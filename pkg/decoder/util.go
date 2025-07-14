package decoder

import (
	"log"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

/*
Helper functions for decoding the data
*/

// trimSpaceAndZero trims spaces, 0x00 and 0xff values off a string
func trimSpaceAndZero(s string) string {
	w := "\t\n\v\f\r \x85\xA0\x00\xFF"
	return strings.Trim(s, w)
}

// bytesToString checks if the byte array is valid (not all 0 or 255) and trims spaces and zeros
func bytesToString(b []byte) string {
	ok := false
	for i := 0; i < len(b); i++ {
		if b[i] > 0 && b[i] < 255 {
			ok = true
			break
		}
	}
	if !ok {
		return ""
	}
	return trimSpaceAndZero(string(b))
}

// decodeWithCodePage decodes a byte slice with the given code page, returns the trimmed decoded string
func decodeWithCodePage(codePage byte, data []byte) (string, error) {

	if codePage == 255 {
		// codepage 255 means empty/unassigned string
		// https://github.com/jugglingcats/tachograph-reader/issues/56#issuecomment-647665548
		return "", nil
	}

	ok := false
	for i := 0; i < len(data); i++ {
		if data[i] > 0 && data[i] < 255 {
			ok = true
			break
		}
	}
	if !ok {
		return "", nil
	}
	// 1: 8859-1
	// 2: 8859-2
	// 3: 8859-3
	// 5: 8859-5
	// 7: 8859-7
	// 9: 8859-9
	// 13: 8859-13
	// 15: 8859-15
	// 16: 8859-16
	// 80: KOI8-R
	// 85: KOI8-U
	var cmap *charmap.Charmap
	switch codePage {
	case 0:
		// should be ASCII, according to
		// https://github.com/jugglingcats/tachograph-reader/blob/master/src/regions/CodePageStringRegion.cs
		// but no charmap.ASCII
		cmap = charmap.ISO8859_1 // same as ASCII but has 128-255 chars
	case 1:
		cmap = charmap.ISO8859_1
	case 2:
		cmap = charmap.ISO8859_2
	case 3:
		cmap = charmap.ISO8859_3
	case 5:
		cmap = charmap.ISO8859_5
	case 7:
		cmap = charmap.ISO8859_7
	case 9:
		cmap = charmap.ISO8859_9
	case 13:
		cmap = charmap.ISO8859_13
	case 15:
		cmap = charmap.ISO8859_15
	case 16:
		cmap = charmap.ISO8859_16
	case 80:
		cmap = charmap.KOI8R
	case 85:
		cmap = charmap.KOI8U
	default:
		log.Printf("warn: unsupported code page %v", codePage)
		cmap = charmap.ISO8859_1
	}
	dec := cmap.NewDecoder()
	res, err := dec.String(string(data))
	if err != nil {
		log.Printf("error: could not decode code page string: %v", err)
		return "", err
	}
	return trimSpaceAndZero(res), nil
}
