// Command dddsimple extracts the identifying fields from a tachograph or
// driver-card download by byte matching, without decoding it.
//
// It answers "what is this file" — the plate and vehicle identification number
// of a vu download, the card number and holder name of a card download — which
// is what an archive file name is built from. For "is this file intact", see
// dddscan.
//
// The extraction itself lives in pkg/simple so that this command, dddscan and
// flotilla_api all share one implementation. It used to be duplicated here, and
// the copy drifted: it byte-sliced the first name for the holder's initial
// (mangling any name starting with a non-ASCII letter), passed the plate
// through a format string, and replaced non-printable bytes with underscores
// without ever validating the decoded field — so a corrupt plate came out as
// "_____________" and was treated as a good name. Those are fixed in pkg/simple
// and there is now only one copy to keep fixed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/traconiq/tachoparser/pkg/simple"
)

var (
	card   = flag.Bool("card", false, "File is a driver card")
	input  = flag.String("input", "", "Input file (optional, stdin is used if not set)")
	output = flag.String("output", "", "Output file (optional, stdout is used if not set)")
)

func main() {
	flag.Parse()

	var data []byte
	var err error
	if *input == "" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("error: could not read stdin: %v", err)
		}
	} else {
		data, err = os.ReadFile(*input)
		if err != nil {
			log.Fatalf("error: could not read file: %v", err)
		}
	}

	// The file name needs a timestamp. The download's own read time is not in
	// the file at a place this parser looks, and the callers that care pass
	// their own, so use now — the fields either side of it are what matters
	// here.
	now := time.Now()

	var out interface{}
	if *card {
		cardNo, firstName, lastName, err := simple.CardExtractCardNumberAndDriverName(data)
		if err != nil {
			log.Fatalf("error: could not parse card: %v", err)
		}
		name, err := simple.CardFileName(data, now)
		if err != nil {
			log.Fatalf("error: could not build card file name: %v", err)
		}
		out = map[string]string{
			"CardNumber": cardNo,
			"FirstName":  firstName,
			"LastName":   lastName,
			"CardName":   name,
		}
	} else {
		idNo, regNo, err := simple.VuExtractIdentificationNumberAndRegistrationNumber(data)
		if err != nil {
			log.Fatalf("error: could not parse vu data: %v", err)
		}
		name, err := simple.VuFileName(data, now)
		if err != nil {
			log.Fatalf("error: could not build vu file name: %v", err)
		}
		out = map[string]string{
			"IdentificationNumber": idNo,
			"RegistrationNumber":   regNo,
			"VuName":               name,
		}
	}

	dataOut, err := json.Marshal(out)
	if err != nil {
		log.Fatalf("error: could not marshal result: %v", err)
	}
	if *output == "" || *output == "-" {
		fmt.Print(string(dataOut))
		return
	}
	if err := os.WriteFile(*output, dataOut, 0644); err != nil {
		log.Fatalf("error: could not write output file: %v", err)
	}
}
