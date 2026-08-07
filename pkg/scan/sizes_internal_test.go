package scan

// The width constants in sizes.go are the one place in this package where a
// silent mistake produces a false rejection rather than a visible failure, so
// they are not trusted on inspection: this recomputes every one of them from
// the decoder's own struct definitions.
//
// This is an internal test file (package scan) because the constants are
// unexported. It is the only place in the package that may import pkg/decoder,
// and it does so in a _test.go file, which never reaches a shipped binary —
// TestNoDecoderImport checks the non-test files.

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/traconiq/tachoparser/pkg/decoder"
)

// fixedWidth returns the encoded byte width of t, mirroring how the decoder
// consumes bytes per kind. A slice whose length comes from a count field has no
// fixed width and is reported as an error rather than guessed at.
func fixedWidth(t reflect.Type, tag string) (int, error) {
	for _, c := range strings.Split(tag, ",") {
		if c == "-" {
			return 0, nil // marker field, not part of the encoding
		}
	}
	switch t.Kind() {
	case reflect.Ptr:
		return fixedWidth(t.Elem(), tag)
	case reflect.Bool:
		return 0, nil
	case reflect.Int8, reflect.Uint8:
		return 1, nil
	case reflect.Int16, reflect.Uint16:
		return 2, nil
	case reflect.Int32, reflect.Uint32:
		return 4, nil
	case reflect.Int, reflect.Int64, reflect.Uint, reflect.Uint64:
		return 8, nil
	case reflect.String:
		n, ok := literalSize(tag)
		if !ok {
			return 0, fmt.Errorf("string sized by field (%q)", tag)
		}
		return n, nil
	case reflect.Array:
		w, err := fixedWidth(t.Elem(), "")
		if err != nil {
			return 0, err
		}
		return t.Len() * w, nil
	case reflect.Slice:
		n, ok := literalSize(tag)
		if !ok {
			return 0, fmt.Errorf("slice sized by field (%q)", tag)
		}
		w, err := fixedWidth(t.Elem(), "")
		if err != nil {
			return 0, err
		}
		return n * w, nil
	case reflect.Struct:
		total := 0
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			w, err := fixedWidth(f.Type, f.Tag.Get("aper"))
			if err != nil {
				return 0, fmt.Errorf("%s.%s: %w", t.Name(), f.Name, err)
			}
			total += w
		}
		return total, nil
	}
	return 0, fmt.Errorf("unhandled kind %v", t.Kind())
}

func literalSize(tag string) (int, bool) {
	for _, c := range strings.Split(tag, ",") {
		if !strings.HasPrefix(c, "size=") {
			continue
		}
		v := strings.TrimPrefix(c, "size=")
		if strings.Contains(v, "..") {
			return 0, false
		}
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	return 0, false
}

func typeOf[T any]() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }

// TestGen1RecordWidths is load bearing: if it fails, the gen1 walk in sizes.go
// will desynchronise and reject good downloads.
func TestGen1RecordWidths(t *testing.T) {
	cases := []struct {
		name string
		typ  reflect.Type
		want int
	}{
		{"CertificateFirstGen", typeOf[decoder.MemberStateCertificateFirstGen](), widthCertificate1},
		{"VuCertificateFirstGen", typeOf[decoder.VuCertificateFirstGen](), widthCertificate1},
		{"SignatureFirstGen", typeOf[decoder.SignatureFirstGen](), widthSignature1},
		{"TimeReal", typeOf[decoder.TimeReal](), widthTimeReal},
		{"VehicleIdentificationNumber", typeOf[decoder.VehicleIdentificationNumber](), widthVin},
		{"VehicleRegistrationIdentification", typeOf[decoder.VehicleRegistrationIdentification](), widthRegistrationId},
		{"VuDownloadablePeriod", typeOf[decoder.VuDownloadablePeriod](), widthDownloadPeriod},
		{"CardSlotsStatus", typeOf[decoder.CardSlotsStatus](), widthCardSlots},
		{"VuDownloadActivityDataFirstGen", typeOf[decoder.VuDownloadActivityDataFirstGen](), widthDownloadAct1},
		{"OdometerValueMidnight", typeOf[decoder.OdometerValueMidnight](), widthOdometerShort},
		{"VuOverSpeedingControlData", typeOf[decoder.VuOverSpeedingControlData](), widthOverspeedCtl},
		{"VuIdentificationFirstGen", typeOf[decoder.VuIdentificationFirstGen](), widthVuIdent1},
		{"SensorPaired", typeOf[decoder.SensorPaired](), widthSensorPaired},
		{"DownloadInterfaceVersion", typeOf[decoder.DownloadInterfaceVersion](), widthInterfaceVersion},

		{"VuCompanyLocksRecordFirstGen", typeOf[decoder.VuCompanyLocksRecordFirstGen](), widthCompanyLocksRec1},
		{"VuControlActivityRecordFirstGen", typeOf[decoder.VuControlActivityRecordFirstGen](), widthControlActivityRec1},
		{"VuCardIWRecordFirstGen", typeOf[decoder.VuCardIWRecordFirstGen](), widthCardIWRec1},
		{"ActivityChangeInfo", typeOf[decoder.ActivityChangeInfo](), widthActivityChange},
		{"VuPlaceDailyWorkPeriodRecordFirstGen", typeOf[decoder.VuPlaceDailyWorkPeriodRecordFirstGen](), widthPlaceRec1},
		{"SpecificConditionRecord", typeOf[decoder.SpecificConditionRecord](), widthSpecificCondRec},
		{"VuFaultRecordFirstGen", typeOf[decoder.VuFaultRecordFirstGen](), widthFaultRec1},
		{"VuEventRecordFirstGen", typeOf[decoder.VuEventRecordFirstGen](), widthEventRec1},
		{"VuOverSpeedingEventRecordFirstGen", typeOf[decoder.VuOverSpeedingEventRecordFirstGen](), widthOverspeedEventRec1},
		{"VuTimeAdjustmentRecordFirstGen", typeOf[decoder.VuTimeAdjustmentRecordFirstGen](), widthTimeAdjustRec1},
		{"VuDetailedSpeedBlock", typeOf[decoder.VuDetailedSpeedBlock](), widthDetailedSpeedBlock},
		{"VuCalibrationRecordFirstGen", typeOf[decoder.VuCalibrationRecordFirstGen](), widthCalibrationRec1},
	}
	for _, c := range cases {
		got, err := fixedWidth(c.typ, "")
		if err != nil {
			t.Errorf("%s: could not compute a fixed width: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: decoder says %d bytes, sizes.go says %d", c.name, got, c.want)
		}
	}
}

// TestGen1BlockFieldOrder guards the other half of the size model: the widths
// can all be right while the block is composed of the wrong ones. Comparing the
// fixed part of each block against the decoder's struct catches that.
func TestGen1BlockFieldOrder(t *testing.T) {
	// The overview's fixed prefix runs up to the first counted array
	// (VuCompanyLocksData), so sum the decoder's fields until then.
	overview := typeOf[decoder.VuOverviewFirstGen]()
	prefix := 0
	for i := 0; i < overview.NumField(); i++ {
		f := overview.Field(i)
		if f.Name == "VuCompanyLocksData" {
			break
		}
		w, err := fixedWidth(f.Type, f.Tag.Get("aper"))
		if err != nil {
			t.Fatalf("overview prefix stops being fixed at %s: %v", f.Name, err)
		}
		prefix += w
	}
	if prefix != gen1OverviewPrefix {
		t.Errorf("overview fixed prefix: decoder says %d, sizes.go says %d", prefix, gen1OverviewPrefix)
	}

	// And the offsets used to read fields out of the overview without decoding.
	for _, c := range []struct {
		field string
		want  int
	}{
		{"VehicleIdentificationNumber", gen1OverviewVinOffset},
		{"VehicleRegistrationIdentification", gen1OverviewRegistrationOffset},
		{"CurrentDateTime", gen1OverviewCurrentTimeOffset},
		{"VuDownloadablePeriod", gen1OverviewPeriodOffset},
	} {
		got := 0
		found := false
		for i := 0; i < overview.NumField(); i++ {
			f := overview.Field(i)
			if f.Name == c.field {
				found = true
				break
			}
			w, err := fixedWidth(f.Type, f.Tag.Get("aper"))
			if err != nil {
				t.Fatalf("offset of %s is not fixed: %v", c.field, err)
			}
			got += w
		}
		if !found {
			t.Errorf("%s: no such field on VuOverviewFirstGen any more", c.field)
			continue
		}
		if got != c.want {
			t.Errorf("offset of %s: decoder says %d, sizes.go says %d", c.field, got, c.want)
		}
	}
}

// TestGen2SignatureRecordType checks the constant the gen2 walk uses to find
// the end of a block.
func TestGen2SignatureRecordType(t *testing.T) {
	if recordTypeSignature != decoder.RecordTypeSignature {
		t.Errorf("signature record type: decoder says 0x%02x, scan says 0x%02x",
			decoder.RecordTypeSignature, recordTypeSignature)
	}
}

// TestCardTagsMatchDecoder keeps the known-tag set in step with the decoder's
// tlv struct tags. A tag missing here is only a warning at scan time, but a
// warning nobody can act on is noise, and noise is how a real finding gets
// ignored.
func TestCardTagsMatchDecoder(t *testing.T) {
	card := typeOf[decoder.Card]()
	fromDecoder := make(map[uint32]bool)
	for i := 0; i < card.NumField(); i++ {
		tag := card.Field(i).Tag.Get("tlv")
		if tag == "" {
			continue
		}
		for _, c := range strings.Split(tag, ",") {
			if !strings.HasPrefix(c, "tag=") {
				continue
			}
			v, err := strconv.ParseUint(strings.TrimPrefix(c, "tag="), 0, 32)
			if err != nil {
				t.Fatalf("%s: cannot parse tlv tag %q", card.Field(i).Name, tag)
			}
			fromDecoder[uint32(v)] = true
		}
	}
	if len(fromDecoder) == 0 {
		t.Fatal("no tlv tags found on decoder.Card; the check would pass vacuously")
	}

	for tag := range fromDecoder {
		if !cardTags[tag] {
			t.Errorf("decoder knows card tag 0x%06x, cardTags does not", tag)
		}
	}
	for tag := range cardTags {
		if !fromDecoder[tag] {
			t.Errorf("cardTags has 0x%06x, the decoder does not know it", tag)
		}
	}
}
