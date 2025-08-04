package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/ncruces/zenity"
	"github.com/traconiq/tachoparser/pkg/decoder"
)

const defaultPath = ``
const defaultName = `out.json`

func main() {
	fileNameInput, err := zenity.SelectFile(
		zenity.Title("Datei auswählen..."),
		zenity.Filename(defaultPath),
		zenity.FileFilters{
			{"Tacho Dateien", []string{"*.ddd"}, true},
		})
	if err != nil {
		log.Fatalf("error: could not get input file: %v", err)
	}

	fileNameOutput, err := zenity.SelectFileSave(
		zenity.Title("Speichern unter..."),
		zenity.ConfirmOverwrite(),
		zenity.Filename(defaultName),
		zenity.FileFilters{
			{"JSON Dateien", []string{"*.json"}, true},
		})
	if err != nil {
		log.Fatalf("error: could not get output file: %v", err)
	}
	log.Printf("input: %s, output: %s", fileNameInput, fileNameOutput)
	err = zenity.Question("Handelt es sich um eine Fahrerkarte?",
		zenity.Title("Kartentyp"),
		zenity.CancelLabel("Nein"),
		zenity.OKLabel("Ja"),
		zenity.QuestionIcon)
	fileTypeCard := true
	if err != nil {
		if err == zenity.ErrCanceled {
			fileTypeCard = false
		} else {
			log.Fatalf("error: could not get file type: %v", err)
		}
	}
	data, err := os.ReadFile(fileNameInput)
	if err != nil {
		log.Fatalf("error: could not read file: %v", err)
	}
	var dataOut []byte
	if fileTypeCard {
		var err error
		var c decoder.Card
		_, err = decoder.UnmarshalTLV(data, &c)
		if err != nil {
			log.Fatalf("error: could not parse card: %v", err)
		}
		dataOut, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			log.Fatalf("error: could not marshal card: %v", err)
		}
	} else {
		var err error
		var v decoder.Vu
		_, err = decoder.UnmarshalTV(data, &v)
		if err != nil {
			log.Fatalf("error: could not parse vu data: %v", err)
		}
		dataOut, err = json.MarshalIndent(v, "", "  ")
		if err != nil {
			log.Fatalf("error: could not marshal vu data: %v", err)
		}
	}
	err = os.WriteFile(fileNameOutput, dataOut, 0644)
	if err != nil {
		log.Fatalf("error: could not write output file: %v", err)
	}
}
