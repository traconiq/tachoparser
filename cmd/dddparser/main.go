package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	_ "github.com/kyburz-switzerland-ag/tachoparser/internal/pkg/certificates"
	"github.com/kyburz-switzerland-ag/tachoparser/pkg/decoder"
)

var (
	card      = flag.Bool("card", false, "File is a driver card")
	vu        = flag.Bool("vu", false, "File is a vu file")
	input     = flag.String("input", "", "Input file (optional, stdin is used if not set)")
	output    = flag.String("output", "", "Output file (optional, stdout is used if not set)")
	inputList = flag.String("input-list", "", "Process files from newline-separated list into .json files at same place (mutually exclusive with input)")
	format    = flag.Bool("format", false, "Pretty-print JSON output")
)

func main() {
	log.Printf("loaded certificates: %v %v", len(decoder.PKsFirstGen), len(decoder.PKsSecondGen))

	flag.Parse()
	if (*card && *vu) || (!*card && !*vu) {
		log.Fatal("either card or vu must be set")
	}

	// Check that inputList and input are mutually exclusive
	if *inputList != "" && *input != "" {
		log.Fatal("input-list and input are mutually exclusive")
	}

	if *inputList != "" {
		processBatch()
	} else {
		processSingle()
	}
}

func processSingle() {
	var data []byte
	if *input == "" {
		var err error
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("error: could not read stdin: %v", err)
		}
	} else {
		var err error
		data, err = os.ReadFile(*input)
		if err != nil {
			log.Fatalf("error: could not read file: %v", err)
		}
	}

	dataOut, err := processData(data)
	if err != nil {
		log.Fatalf("error: could not process data: %v", err)
	}

	if *output == "" || *output == "-" {
		fmt.Print(string(dataOut))
	} else {
		err := os.WriteFile(*output, dataOut, 0644)
		if err != nil {
			log.Fatalf("error: could not write output file: %v", err)
		}
	}
}

func processBatch() {
	// Read the input list file
	listFile, err := os.Open(*inputList)
	if err != nil {
		log.Fatalf("error: could not open input list file: %v", err)
	}
	defer listFile.Close()

	scanner := bufio.NewScanner(listFile)
	var inputFiles []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			inputFiles = append(inputFiles, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("error: could not read input list file: %v", err)
	}

	if len(inputFiles) == 0 {
		log.Fatal("error: no input files found in list")
	}

	// Process each file
	for _, inputFile := range inputFiles {
		data, err := os.ReadFile(inputFile)
		if err != nil {
			log.Printf("warning: could not read file %s: %v", inputFile, err)
			continue
		}

		dataOut, err := processData(data)
		if err != nil {
			log.Printf("warning: could not process file %s: %v", inputFile, err)
			continue
		}

		// For inputList, always write individual files in the same folder with .json extension
		outputFile := inputFile + ".json"
		err = os.WriteFile(outputFile, dataOut, 0644)
		if err != nil {
			log.Printf("warning: could not write output file %s: %v", outputFile, err)
		} else {
			log.Printf("processed %s -> %s", inputFile, outputFile)
		}
	}
}

func processData(data []byte) ([]byte, error) {
	if *card {
		var c decoder.Card
		_, err := decoder.UnmarshalTLV(data, &c)
		if err != nil {
			return nil, fmt.Errorf("could not parse card: %v", err)
		}
		if *format {
			return json.MarshalIndent(c, "", "  ")
		}
		return json.Marshal(c)
	} else {
		var v decoder.Vu
		_, err := decoder.UnmarshalTV(data, &v)
		if err != nil {
			return nil, fmt.Errorf("could not parse vu data: %v", err)
		}
		if *format {
			return json.MarshalIndent(v, "", "  ")
		}
		return json.Marshal(v)
	}
}
