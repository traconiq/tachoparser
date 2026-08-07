// Command dddscan checks whether tachograph downloads are structurally intact,
// without decoding them.
//
// It is the command-line face of pkg/scan, and exists for the job that motivated
// that package: a directory of rejected downloads that somebody has to triage.
// Point it at a file or a directory and it says, per file, whether the framing
// adds up and where it stops adding up if it does not.
//
//	dddscan file.DDD                      # one file, human readable
//	dddscan -r /srv/tacho/acme/invalid    # sweep a quarantine directory
//	dddscan -q -r /srv/tacho              # only report the broken ones
//	dddscan -json file.DDD | jq .         # structured output
//
// The exit code is meant for scripts: 0 when every file scanned cleanly, 1 when
// at least one had a fatal problem, 2 when the arguments or the filesystem were
// the problem. With -strict, warnings count as failures too.
//
// What it does NOT do is tell you a file is genuine. It reads framing, not
// signatures — see the pkg/scan documentation for why signature verification is
// not usable here. A file can pass this and still be rubbish inside; what it
// catches is truncation, padding, desynchronised lengths and garbage tails.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/traconiq/tachoparser/pkg/scan"
)

var (
	recurse   = flag.Bool("r", false, "recurse into directories")
	jsonOut   = flag.Bool("json", false, "emit one JSON object per file instead of a human-readable line")
	quiet     = flag.Bool("q", false, "only report files that have problems")
	strict    = flag.Bool("strict", false, "treat warnings as failures for the exit code")
	verbose   = flag.Bool("v", false, "also list the blocks found in each file")
	asVu      = flag.Bool("vu", false, "treat every input as a vehicle-unit download instead of detecting")
	asCard    = flag.Bool("card", false, "treat every input as a driver-card download instead of detecting")
	requireIn = flag.String("require", "", "comma-separated tags (hex, e.g. 7601,7602) that a file must contain; reported as a problem when absent")
	ext       = flag.String("ext", ".ddd", "when recursing, only read files with this extension (case-insensitive); empty reads everything")
)

// exit codes
const (
	exitOK      = 0
	exitProblem = 1
	exitUsage   = 2
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: dddscan [flags] <file|dir>...\n\n"+
			"Reports whether tachograph downloads are structurally intact.\n"+
			"Reads stdin when no path is given.\n\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *asVu && *asCard {
		fmt.Fprintln(os.Stderr, "dddscan: -vu and -card are mutually exclusive")
		os.Exit(exitUsage)
	}
	required, err := parseRequired(*requireIn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dddscan: -require: %v\n", err)
		os.Exit(exitUsage)
	}

	paths, err := collect(flag.Args(), *recurse, *ext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dddscan: %v\n", err)
		os.Exit(exitUsage)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	failed, warned, scanned := 0, 0, 0
	report := func(name string, data []byte) {
		scanned++
		rep, err := scanOne(data)
		missing := rep.Missing(required...)
		switch {
		case err != nil:
			failed++
		case len(missing) > 0:
			// A required tag that is absent is a policy failure, not a framing
			// one, so it is counted here rather than inside the walk.
			failed++
		case len(rep.Problems) > 0:
			warned++
		}
		if *jsonOut {
			if err := enc.Encode(newResult(name, rep, missing)); err != nil {
				fmt.Fprintf(os.Stderr, "dddscan: %v\n", err)
			}
			return
		}
		if *quiet && err == nil && len(rep.Problems) == 0 && len(missing) == 0 {
			return
		}
		printHuman(name, rep, missing)
	}

	if len(paths) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dddscan: stdin: %v\n", err)
			os.Exit(exitUsage)
		}
		report("<stdin>", data)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dddscan: %v\n", err)
			failed++
			continue
		}
		report(p, data)
	}

	if !*jsonOut && scanned > 1 {
		fmt.Printf("\n%d scanned, %d failed, %d with warnings\n", scanned, failed, warned)
	}
	switch {
	case failed > 0:
		os.Exit(exitProblem)
	case *strict && warned > 0:
		os.Exit(exitProblem)
	}
	os.Exit(exitOK)
}

func scanOne(data []byte) (*scan.Report, error) {
	switch {
	case *asVu:
		return scan.ScanVu(data)
	case *asCard:
		return scan.ScanCard(data)
	}
	return scan.Scan(data)
}

// collect expands the arguments into a list of files, descending into
// directories only when asked so a mistyped path cannot silently sweep a tree.
func collect(args []string, recurse bool, ext string) ([]string, error) {
	var out []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, arg)
			continue
		}
		if !recurse {
			return nil, fmt.Errorf("%s is a directory (pass -r to recurse)", arg)
		}
		err = filepath.WalkDir(arg, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if ext != "" && !strings.EqualFold(filepath.Ext(p), ext) {
				return nil
			}
			out = append(out, p)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

func parseRequired(s string) ([]uint32, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []uint32
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(strings.TrimPrefix(part, "0x"), "0X")
		if part == "" {
			continue
		}
		var v uint32
		if _, err := fmt.Sscanf(part, "%x", &v); err != nil {
			return nil, fmt.Errorf("%q is not a hex tag", part)
		}
		out = append(out, v)
	}
	return out, nil
}

// result is the JSON shape. It mirrors the report but renders tags as hex
// strings, because a bare 30209 helps nobody.
type result struct {
	File     string         `json:"file"`
	Kind     string         `json:"kind"`
	OK       bool           `json:"ok"`
	Size     int            `json:"size"`
	Consumed int            `json:"consumed"`
	Padding  int            `json:"padding,omitempty"`
	Gen      []string       `json:"generations,omitempty"`
	Tags     map[string]int `json:"tags,omitempty"`
	Missing  []string       `json:"missing,omitempty"`
	Blocks   []blockOut     `json:"blocks,omitempty"`
	Problems []problemOut   `json:"problems,omitempty"`
}

type blockOut struct {
	Tag    string `json:"tag"`
	Gen    string `json:"generation"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

type problemOut struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Offset   int    `json:"offset"`
	Detail   string `json:"detail"`
}

func newResult(name string, rep *scan.Report, missing []uint32) result {
	r := result{
		File:     name,
		Kind:     string(rep.Kind),
		OK:       rep.OK() && len(missing) == 0,
		Size:     rep.Size,
		Consumed: rep.Consumed,
		Padding:  rep.Padding,
	}
	if rep.HasGen1 {
		r.Gen = append(r.Gen, "gen1")
	}
	if rep.HasGen2 {
		r.Gen = append(r.Gen, "gen2")
	}
	if len(rep.Tags) > 0 {
		r.Tags = make(map[string]int, len(rep.Tags))
		for tag, n := range rep.Tags {
			r.Tags[tagString(tag, rep.Kind)] = n
		}
	}
	for _, m := range missing {
		r.Missing = append(r.Missing, tagString(m, rep.Kind))
	}
	if *verbose {
		for _, b := range rep.Blocks {
			r.Blocks = append(r.Blocks, blockOut{
				Tag: tagString(b.Tag, rep.Kind), Gen: b.Gen.String(), Offset: b.Offset, Length: b.Length,
			})
		}
	}
	for _, p := range rep.Problems {
		r.Problems = append(r.Problems, problemOut{
			Code: string(p.Code), Severity: p.Severity.String(), Offset: p.Offset, Detail: p.Detail,
		})
	}
	return r
}

// tagString renders a tag the width it is written in the specification: two
// bytes for a vu transfer response, three for a card record.
func tagString(tag uint32, kind scan.Kind) string {
	if kind == scan.KindCard {
		return fmt.Sprintf("%06x", tag)
	}
	return fmt.Sprintf("%04x", tag)
}

func printHuman(name string, rep *scan.Report, missing []uint32) {
	status := "ok"
	if !rep.OK() {
		status = "FAILED"
	} else if len(missing) > 0 {
		status = "INCOMPLETE"
	} else if len(rep.Problems) > 0 {
		status = "ok (warnings)"
	}

	gen := "-"
	switch {
	case rep.HasGen1 && rep.HasGen2:
		gen = "gen1+gen2"
	case rep.HasGen1:
		gen = "gen1"
	case rep.HasGen2:
		gen = "gen2"
	}
	kind := string(rep.Kind)
	if kind == "" {
		kind = "unknown"
	}

	fmt.Printf("%s: %s — %s, %s, %d blocks, %d bytes", name, status, kind, gen, len(rep.Blocks), rep.Size)
	if rep.Padding > 0 {
		fmt.Printf(", %d padding", rep.Padding)
	}
	if rep.Consumed != rep.Size {
		fmt.Printf(", %d unaccounted", rep.Size-rep.Consumed)
	}
	fmt.Println()

	for _, p := range rep.Problems {
		fmt.Printf("    %s: %s at offset %d: %s\n", p.Severity, p.Code, p.Offset, p.Detail)
	}
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for _, m := range missing {
			names = append(names, tagString(m, rep.Kind))
		}
		fmt.Printf("    fatal: required tags absent: %s\n", strings.Join(names, ", "))
	}
	if *verbose {
		for _, b := range rep.Blocks {
			fmt.Printf("    %s  %s  offset %d, %d bytes\n", tagString(b.Tag, rep.Kind), b.Gen, b.Offset, b.Length)
		}
	}
}
