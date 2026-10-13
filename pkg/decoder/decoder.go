package decoder

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// UnmarshalTLV decodes the bytes in data into inter. It also verifies the data based on the signatures and certificates, if possible.
// The data is tag-length-value encoded and the structure given by the "tv" tags in the struct.
// This function is meant to decode driver card data.
// inter needs to be a pointer, otherwise the code will panic!
func UnmarshalTLV(data []byte, inter interface{}) (verified bool, err error) {
	defer func() {
		// recover from panic if one occurred.
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				// Fallback err (per specs, error strings should be lowercase w/o punctuation
				err = errors.New("unknown panic")
			}
			verified = false
		}
	}()
	pt := reflect.TypeOf(inter)
	pv := reflect.ValueOf(inter)
	t := pt.Elem()
	v := pv.Elem()
	var signCertificateFirstGenMethod, signCertificateSecondGenMethod reflect.Method
	if m, ok := pt.MethodByName("SignCertificateFirstGen"); ok {
		signCertificateFirstGenMethod = m
	}
	if m, ok := pt.MethodByName("SignCertificateSecondGen"); ok {
		signCertificateSecondGenMethod = m
	}
	knownTags := make(map[[3]byte]reflect.Value)
	for i := 0; i < t.NumField(); i++ {
		if fieldTag := t.Field(i).Tag.Get("tlv"); fieldTag != "" {
			var tlvTag [3]byte
			for _, component := range strings.Split(fieldTag, ",") {
				switch {
				case strings.HasPrefix(component, "tag=0x"): // TODO: maybe a bit more sophisticated parsing here
					if h, err := hex.DecodeString(component[6:]); err == nil && len(h) == 3 {
						tlvTag[0] = h[0]
						tlvTag[1] = h[1]
						tlvTag[2] = h[2]
					}
				}
			}
			if tlvTag[0] != 0 || tlvTag[1] != 0 || tlvTag[2] != 0 {
				knownTags[tlvTag] = v.Field(i)
			}
		}
	}
	type dataRangeSignatureFirstGen struct {
		start, length int
		VerifiedField reflect.Value
	}
	type dataRangeSignatureSecondGen struct {
		start, length int
		VerifiedField reflect.Value
	}
	dataRangeSignatureFirstGenMap := make(map[[3]byte]dataRangeSignatureFirstGen)
	dataRangeSignatureSecondGenMap := make(map[[3]byte]dataRangeSignatureSecondGen)
	// log.Printf("%+v", knownTags)
	globalSizes := make(map[string]int)
	// first pass - data
	for currentPos := 0; currentPos < len(data) && len(data[currentPos:]) > 2; {
		var currentTag [3]byte
		found := false
		currentTag[0] = data[currentPos+0]
		currentTag[1] = data[currentPos+1]
		currentTag[2] = data[currentPos+2]
		currentPos += 3
		var field reflect.Value
		if f, ok := knownTags[currentTag]; ok {
			// log.Printf("found tag: %v : %+v", currentTag, f)
			field = f
			found = true
		} else {
			log.Printf("warn: unknown tag: %v", currentTag)
		}
		if len(data[currentPos:]) > 1 {
			buf := bytes.NewBuffer(data[currentPos : currentPos+2])
			var size uint16
			binary.Read(buf, binary.BigEndian, &size)
			// log.Printf("size: %v", size)
			currentPos += 2
			if len(data[currentPos:]) >= int(size) && size > 0 && found && (currentTag[2]&0x01) == 0 {
				_, _, _, err := parseASN1Field(field, field.Type(), -1, 0, 0, int(size), 0, data[currentPos:currentPos+int(size)], nil, globalSizes)
				if err != nil {
					log.Printf("error: %v (ignored, skip ahead to next tag)", err)
				} else {
					switch currentTag[2] {
					case 0x00: // 1st gen
						dataRangeSignatureFirstGenMap[currentTag] = dataRangeSignatureFirstGen{
							start:         currentPos,
							length:        int(size),
							VerifiedField: field.FieldByName("Verified"),
						}
					case 0x02: // 2nd gen
						dataRangeSignatureSecondGenMap[currentTag] = dataRangeSignatureSecondGen{
							start:         currentPos,
							length:        int(size),
							VerifiedField: field.FieldByName("Verified"),
						}
					}
				}
			}
			if len(data[currentPos:]) >= int(size) {
				currentPos += int(size)
			} else {
				log.Printf("error: data missing, length: %v remaining data: %v", size, len(data[currentPos:]))
				currentPos = len(data) // put pointer to the end
			}
		} else {
			log.Printf("error: data missing, remaining data: %v", len(data[currentPos:]))
			currentPos = len(data) // put pointer to the end
		}
	}
	var signCertificateFirstGen CertificateFirstGen
	var signCertificateSecondGen CertificateSecondGen
	// after the parsing, retrieve the sign certificate
	if signCertificateFirstGenMethod.Func.IsValid() {
		certVals := signCertificateFirstGenMethod.Func.Call([]reflect.Value{pv})
		if len(certVals) > 0 {
			if cert, ok := certVals[0].Interface().(CertificateFirstGen); ok {
				signCertificateFirstGen = cert
			}
		}
	}
	if signCertificateSecondGenMethod.Func.IsValid() {
		certVals := signCertificateSecondGenMethod.Func.Call([]reflect.Value{pv})
		if len(certVals) > 0 {
			if cert, ok := certVals[0].Interface().(CertificateSecondGen); ok {
				signCertificateSecondGen = cert
			}
		}
	}
	signCertificateFirstGenValid := false
	if err := signCertificateFirstGen.Decode(); err == nil {
		signCertificateFirstGenValid = true
	}
	signCertificateSecondGenValid := false
	if err := signCertificateSecondGen.Decode(); err == nil {
		signCertificateSecondGenValid = true
	}
	verified = false
	verificationStarted := false
	// second pass - signatures
	for currentPos := 0; currentPos < len(data) && len(data[currentPos:]) > 2; {
		var currentTag [3]byte
		found := false
		currentTag[0] = data[currentPos+0]
		currentTag[1] = data[currentPos+1]
		currentTag[2] = data[currentPos+2]
		currentPos += 3
		var field reflect.Value
		if f, ok := knownTags[currentTag]; ok {
			// log.Printf("found tag: %v : %+v", currentTag, f)
			field = f
			found = true
		} else {
			log.Printf("warn: unknown tag: %v", currentTag)
		}
		if len(data[currentPos:]) > 1 {
			buf := bytes.NewBuffer(data[currentPos : currentPos+2])
			var size uint16
			binary.Read(buf, binary.BigEndian, &size)
			// log.Printf("size: %v", size)
			currentPos += 2
			if len(data[currentPos:]) >= int(size) && size > 0 && found && (currentTag[2]&0x01) == 1 {
				_, _, _, err := parseASN1Field(field, field.Type(), -1, 0, 0, int(size), 0, data[currentPos:currentPos+int(size)], nil, globalSizes)
				if err != nil {
					log.Printf("error: %v (ignored, skip ahead to next tag)", err)
				} else {
					var signForTag [3]byte
					signForTag[0] = currentTag[0]
					signForTag[1] = currentTag[1]
					signForTag[2] = currentTag[2] - 1
					switch currentTag[2] {
					case 0x01: // 1st gen
						if dr, ok := dataRangeSignatureFirstGenMap[signForTag]; signCertificateFirstGenValid && ok {
							if currentSignature, ok := field.Interface().(SignatureFirstGen); ok {
								if ver, err := currentSignature.Verify(signCertificateFirstGen, data[dr.start:dr.start+dr.length]); err == nil {
									if dr.VerifiedField.IsValid() && dr.VerifiedField.CanSet() {
										dr.VerifiedField.SetBool(ver)
									}
									if !verificationStarted {
										verified = ver
									} else {
										verified = verified && ver
									}
								} else {
									log.Printf("error: could not verify: %v", err)
									verified = false
								}
							}
						}
					case 0x03: // 2nd gen
						if dr, ok := dataRangeSignatureSecondGenMap[signForTag]; signCertificateSecondGenValid && ok {
							if currentSignature, ok := field.Interface().(SignatureSecondGen); ok {
								if ver, err := currentSignature.Verify(signCertificateSecondGen, data[dr.start:dr.start+dr.length]); err == nil {
									// it seems not to be enough to call Verify on the Signature struct, we also need to set the Verified field manually
									if dr.VerifiedField.IsValid() && dr.VerifiedField.CanSet() {
										dr.VerifiedField.SetBool(ver)
									}
									if !verificationStarted {
										verified = ver
									} else {
										verified = verified && ver
									}
								} else {
									log.Printf("error: could not verify: %v", err)
									verified = false
								}
							}
						}
					}
				}
				verificationStarted = true
			}
			if len(data[currentPos:]) >= int(size) {
				currentPos += int(size)
			} else {
				log.Printf("error: data missing, length: %v remaining data: %v", size, len(data[currentPos:]))
				currentPos = len(data) // put pointer to the end
			}
		} else {
			log.Printf("error: data missing, remaining data: %v", len(data[currentPos:]))
			currentPos = len(data) // put pointer to the end
		}
	}

	return verified, nil
}

// inter needs to be a pointer, otherwise the code will panic!
// returns true if the contents are verified
func UnmarshalTV(data []byte, inter interface{}) (verified bool, err error) {
	defer func() {
		// recover from panic if one occurred.
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				// Fallback err (per specs, error strings should be lowercase w/o punctuation
				err = errors.New("unknown panic")
			}
			verified = false
		}
	}()
	// log.Println("in UnmarshalTv")
	pt := reflect.TypeOf(inter)
	pv := reflect.ValueOf(inter)
	t := pt.Elem()
	v := pv.Elem()
	verifyFirstGenMethods := make(map[[2]byte]reflect.Method)
	verifySecondGenMethods := make(map[[2]byte]reflect.Method)
	var signCertificateFirstGenMethod, signCertificateSecondGenMethod reflect.Method
	if m, ok := pt.MethodByName("SignCertificateFirstGen"); ok {
		signCertificateFirstGenMethod = m
	}
	if m, ok := pt.MethodByName("SignCertificateSecondGen"); ok {
		signCertificateSecondGenMethod = m
	}
	knownTags := make(map[[2]byte]reflect.Value)
	for i := 0; i < t.NumField(); i++ {
		if fieldTag := t.Field(i).Tag.Get("tv"); fieldTag != "" {
			var tvTag [2]byte
			for _, component := range strings.Split(fieldTag, ",") {
				switch {
				case strings.HasPrefix(component, "tag=0x"):
					if h, err := hex.DecodeString(component[6:]); err == nil && len(h) == 2 {
						tvTag[0] = h[0]
						tvTag[1] = h[1]
					}
				}
			}
			if tvTag[0] != 0 || tvTag[1] != 0 {
				knownTags[tvTag] = v.Field(i)
				switch v.Field(i).Kind() {
				case reflect.Struct:
					if m, ok := t.Field(i).Type.MethodByName("VerifyFirstGen"); ok {
						verifyFirstGenMethods[tvTag] = m
					}
					if m, ok := t.Field(i).Type.MethodByName("VerifySecondGen"); ok {
						verifySecondGenMethods[tvTag] = m
					}
				case reflect.Slice:
					if m, ok := t.Field(i).Type.Elem().MethodByName("VerifyFirstGen"); ok {
						verifyFirstGenMethods[tvTag] = m
					}
					if m, ok := t.Field(i).Type.Elem().MethodByName("VerifySecondGen"); ok {
						verifySecondGenMethods[tvTag] = m
					}
				}

			}
		}
	}
	// log.Printf("%+v", knownTags)
	type verifyRange struct {
		gen           int
		start, length int
		method        reflect.Method
		field         reflect.Value
		// blocks that may occur more than once (slice fields) are parsed into a new value that is
		// then copied into the slice. The result of the verification must be written to the element
		// in the slice, not to that value, so we remember the slice field and the element index.
		// The element is looked up only after parsing, as appending may move the backing array.
		slice reflect.Value
		index int
	}
	verifyRanges := make([]verifyRange, 0)
	globalSizes := make(map[string]int)
	visitedTags := make(map[[2]byte]bool)
	var currentTag [2]byte
	var found bool
	for currentPos := 0; currentPos < len(data) && len(data[currentPos:]) > 1; {
		found = false
		currentTag[0] = data[currentPos+0]
		currentTag[1] = data[currentPos+1]
		currentPos += 2
		var field reflect.Value
		if f, ok := knownTags[currentTag]; ok {
			// log.Printf("found tag: %v : %+v", currentTag, f)
			field = f
			found = true
		} else {
			log.Printf("unknown tag: %v", currentTag)
		}
		if len(data[currentPos:]) > 0 && found {
			parseIntoField := field
			fieldType := field.Type()
			switch field.Kind() {
			case reflect.Struct:
			case reflect.Slice:
				if _, ok := visitedTags[currentTag]; !ok {
					visitedTags[currentTag] = true
					field.Set(reflect.MakeSlice(fieldType, 0, 0))
				}
				fieldType = fieldType.Elem()
				parseIntoField = reflect.New(fieldType).Elem()
			}
			_, actualSizeBytes, _, err := parseASN1Field(parseIntoField, fieldType, -1, 0, 0, 0, 0, data[currentPos:], nil, globalSizes)
			// actualSize, actualSizeBytes, _, err := parseASN1Field(field, field.Type(), 1, 0, 0, 0, 0, data[currentPos:], nil, globalSizes)
			// log.Printf("result tv struct parsing: %v %v %v", actualSize, actualSizeBytes, err)
			if err != nil {
				return false, err
			}
			var sliceField reflect.Value
			sliceIndex := -1
			if field.Kind() == reflect.Slice {
				field.Set(reflect.Append(field, parseIntoField))
				sliceField = field
				sliceIndex = field.Len() - 1
			}
			if len(data[currentPos:]) >= actualSizeBytes {
				if vm, ok := verifyFirstGenMethods[currentTag]; ok {
					verifyRanges = append(verifyRanges, verifyRange{
						gen:    1,
						start:  currentPos,
						length: actualSizeBytes,
						method: vm,
						field:  parseIntoField,
						slice:  sliceField,
						index:  sliceIndex,
					})
				}
				if vm, ok := verifySecondGenMethods[currentTag]; ok {
					verifyRanges = append(verifyRanges, verifyRange{
						gen:    2,
						start:  currentPos,
						length: actualSizeBytes,
						method: vm,
						field:  parseIntoField,
						slice:  sliceField,
						index:  sliceIndex,
					})
				}
				currentPos += actualSizeBytes
			} else {
				log.Printf("error: data missing, length: %v remaining data: %v", actualSizeBytes, len(data[currentPos:]))
				currentPos = len(data) // put pointer to the end
			}
		} else {
			log.Println("error: data missing or unknown tag")
			currentPos = len(data) // put pointer to the end
		}
	}
	// these two certificates are updated using the SignCertificate method of the top level structure
	var signCertificateFirstGen CertificateFirstGen
	var signCertificateSecondGen CertificateSecondGen
	// after the parsing, retrieve the sign certificate
	if signCertificateFirstGenMethod.Func.IsValid() {
		certVals := signCertificateFirstGenMethod.Func.Call([]reflect.Value{pv})
		if len(certVals) > 0 {
			if cert, ok := certVals[0].Interface().(CertificateFirstGen); ok {
				// log.Printf("found 1st gen sign certificate: %+v", cert)
				signCertificateFirstGen = cert
			}
		}
	}
	if signCertificateSecondGenMethod.Func.IsValid() {
		certVals := signCertificateSecondGenMethod.Func.Call([]reflect.Value{pv})
		if len(certVals) > 0 {
			if cert, ok := certVals[0].Interface().(CertificateSecondGen); ok {
				// log.Printf("found 2nd gen sign certificate: %+v", cert)
				signCertificateSecondGen = cert
			}
		}
	}
	signCertificateFirstGenValid := false
	if err := signCertificateFirstGen.Decode(); err == nil {
		signCertificateFirstGenValid = true
	}
	signCertificateSecondGenValid := false
	if err := signCertificateSecondGen.Decode(); err == nil {
		signCertificateSecondGenValid = true
	}
	verificationStarted := false
	verified = false
	if signCertificateFirstGenValid || signCertificateSecondGenValid {
		// verify the individual fields in a second pass, since only now we know the certificate
		for _, vr := range verifyRanges {
			var certValue reflect.Value
			switch vr.gen {
			case 1:
				if signCertificateFirstGenValid {
					certValue = reflect.ValueOf(signCertificateFirstGen)
				}
			case 2:
				if signCertificateSecondGenValid {
					certValue = reflect.ValueOf(signCertificateSecondGen)
				}
			}
			if !certValue.IsValid() {
				// we may not have a cert for this generation
				continue
			}
			dataValue := reflect.ValueOf(data[vr.start : vr.start+vr.length])
			res := vr.method.Func.Call([]reflect.Value{vr.field, certValue, dataValue})
			if len(res) > 1 {
				success := res[0].Bool()
				var err error
				if e, ok := res[1].Interface().(error); ok {
					err = e
				}
				ver := false
				if success && err == nil {
					ver = true
				}
				target := vr.field
				if vr.slice.IsValid() && vr.index >= 0 && vr.index < vr.slice.Len() {
					target = vr.slice.Index(vr.index)
				}
				if verifiedField := target.FieldByName("Verified"); verifiedField.IsValid() && verifiedField.CanSet() {
					verifiedField.SetBool(ver)
				}
				if !verificationStarted {
					verified = ver
				} else {
					verified = verified && ver
				}
			} else {
				verified = false
			}
			verificationStarted = true
		}
	}
	return verified, nil
}

// based on the reflect.Type, try to determine the total size of the element
// returns the size (in elements, if array, slice or string, 1 otherwise
// min/max size
// size in bytes
// element size, if array or slice
// much of the size calculation code is duplicated from the actual parsing code
func getASN1FieldSize(fieldType reflect.Type, fieldTag, fieldName string, inSizeBytes int, sizes, globalSizes map[string]int, data []byte) (size, minSize, maxSize, sizeBytes, elementSizeBytes, sizeVal int, structureSize, ignore bool, err error) {
	// if fieldTag != "" {
	// log.Printf("in getASN1FieldSize, name: %v tag: %v sizeBytes: %v", fieldName, fieldTag, inSizeBytes)
	// }
	sizeBytes = inSizeBytes
	global := false
	minSize = 0
	maxSize = 0
	hasExpected := false
	expectedVal := uint64(0)
	if fieldTag != "" {
		components := strings.Split(fieldTag, ",")
		for _, component := range components {
			switch {
			case strings.HasPrefix(component, "cond=") && len(component) > 5:
				condStr := component[5:]
				if strings.Contains(condStr, "==") {
					parts := strings.SplitN(condStr, "==", 2)
					if condVal, err := strconv.ParseUint(parts[1], 0, 64); err == nil {
						if s, ok := sizes[parts[0]]; ok && s != int(condVal) {
							return 0, 0, 0, 0, 0, 0, false, true, nil
						}
					}
				}
			case strings.HasPrefix(component, "size=") && len(component) > 5:
				sizeStr := component[5:]
				if strings.Contains(sizeStr, "..") {
					if sizeComponents := strings.SplitN(sizeStr, "..", 2); len(sizeComponents) == 2 {
						if ms, err := strconv.ParseUint(sizeComponents[0], 10, 16); err == nil {
							minSize = int(ms)
						} else {
							if ms, ok := sizes[sizeComponents[0]]; ok {
								minSize = ms
							} else {
								if ms, ok := globalSizes[sizeComponents[0]]; ok {
									minSize = ms
								}
							}
						}
						if ms, err := strconv.ParseUint(sizeComponents[1], 10, 16); err == nil {
							maxSize = int(ms)
						} else {
							if ms, ok := sizes[sizeComponents[1]]; ok {
								maxSize = ms
							} else {
								if ms, ok := globalSizes[sizeComponents[1]]; ok {
									maxSize = ms
								}
							}
						}
					}
				} else {
					sizeSet := false
					if s, err := strconv.ParseUint(sizeStr, 10, 64); err == nil {
						size = int(s)
						sizeSet = true
					} else {
						if s, ok := sizes[sizeStr]; ok {
							size = s
							sizeSet = true
						} else {
							if s, ok := globalSizes[sizeStr]; ok {
								size = s
								sizeSet = true
							}
						}
					}
					// log.Printf("set size to: %v", size)
					if sizeSet && size == 0 {
						// log.Printf("size was set to zero, skipping")
						// this happens if the record number is zero in recordarray structs
						return 0, 0, 0, 0, 0, 0, false, ignore, nil
					}
				}
			case strings.HasPrefix(component, "elementsize=") && len(component) > 12:
				sizeStr := component[12:]
				if s, err := strconv.ParseUint(sizeStr, 10, 64); err == nil {
					elementSizeBytes = int(s)
				} else {
					if s, ok := sizes[sizeStr]; ok {
						elementSizeBytes = s
					} else {
						if s, ok := globalSizes[sizeStr]; ok {
							elementSizeBytes = s
						}
					}
				}
				// log.Printf("found element size: %v", elementSizeBytes)
			case strings.HasPrefix(component, "name=") && len(component) > 5:
				// fields can be given extra names which can be referenced from the size field of following fields
				fieldName = component[5:]
			case strings.HasPrefix(component, "expected=") && len(component) > 9:
				hasExpected = true
				expectedStr := component[9:]
				// TODO: only uint64 is supported
				if e, err := strconv.ParseUint(expectedStr, 0, 64); err == nil {
					expectedVal = e
				} else {
					if e, ok := sizes[expectedStr]; ok {
						expectedVal = uint64(e)
					} else {
						if e, ok := globalSizes[expectedStr]; ok {
							expectedVal = uint64(e)
						}
					}
				}
			case component == "structuresize":
				structureSize = true
			case component == "global":
				global = true
			case component == "-":
				// completely ignore
				return 0, 0, 0, 0, 0, 0, false, true, nil
			}
		}
	}
	if sizeBytes == 0 && elementSizeBytes > 0 {
		sizeBytes = elementSizeBytes * size
	}
	switch fieldType.Kind() {
	case reflect.Ptr:
		// log.Println("in size: is a pointer - dereference")
		return getASN1FieldSize(fieldType.Elem(), fieldTag, fieldName, sizeBytes, sizes, globalSizes, data)
	case reflect.Int, reflect.Int64:
		if len(data) < 8 {
			return 0, 0, 0, 0, 0, 0, false, ignore, errors.New("data not long enough for int64")
		}
		size = 1
		sizeBytes = 8
		elementSizeBytes = 0
		var tmpVal int64
		b := bytes.NewBuffer(data[0:8])
		binary.Read(b, binary.BigEndian, &tmpVal)
		if tmpVal >= 0 {
			sizeVal = int(tmpVal)
		}
		if hasExpected && expectedVal != uint64(tmpVal) {
			// if an expected value is not there, assume it is the wrong surrounding struct, so the surrounding struct is completely missing (structuresize=true and sizeval=0)
			return 0, 0, 0, 0, 0, 0, true, ignore, nil
		}
	case reflect.Int32:
		if len(data) < 4 {
			return 0, 0, 0, 0, 0, 0, false, ignore, errors.New("data not long enough for int32")
		}
		size = 1
		sizeBytes = 4
		var tmpVal int32
		b := bytes.NewBuffer(data[0:4])
		binary.Read(b, binary.BigEndian, &tmpVal)
		if tmpVal >= 0 {
			sizeVal = int(tmpVal)
		}
		if hasExpected && expectedVal != uint64(tmpVal) {
			return 0, 0, 0, 0, 0, 0, true, ignore, nil
		}
	case reflect.Int16:
		if len(data) < 2 {
			return 0, 0, 0, 0, 0, 0, false, ignore, errors.New("data not long enough for int16")
		}
		size = 1
		sizeBytes = 2
		var tmpVal int16
		b := bytes.NewBuffer(data[0:2])
		binary.Read(b, binary.BigEndian, &tmpVal)
		if tmpVal >= 0 {
			sizeVal = int(tmpVal)
		}
		if hasExpected && expectedVal != uint64(tmpVal) {
			return 0, 0, 0, 0, 0, 0, true, ignore, nil
		}
	case reflect.Int8:
		if len(data) < 1 {
			return 0, 0, 0, 0, 0, 0, false, ignore, errors.New("data not long enough for int8")
		}
		size = 1
		sizeBytes = 1
		var tmpVal int8
		b := bytes.NewBuffer(data[0:1])
		binary.Read(b, binary.BigEndian, &tmpVal)
		if tmpVal >= 0 {
			sizeVal = int(tmpVal)
		}
		if hasExpected && expectedVal != uint64(tmpVal) {
			return 0, 0, 0, 0, 0, 0, true, ignore, nil
		}
	case reflect.Uint, reflect.Uint64:
		if len(data) < 8 {
			return 0, 0, 0, 0, 0, 0, false, ignore, errors.New("data not long enough for uint64")
		}
		size = 1
		sizeBytes = 8
		var tmpVal uint64
		b := bytes.NewBuffer(data[0:8])
		binary.Read(b, binary.BigEndian, &tmpVal)
		sizeVal = int(tmpVal)
		if hasExpected && expectedVal != uint64(tmpVal) {
			return 0, 0, 0, 0, 0, 0, true, ignore, nil
		}
	case reflect.Uint32:
		if len(data) < 4 {
			return 0, 0, 0, 0, 0, 0, false, ignore, errors.New("data not long enough for uint32")
		}
		size = 1
		sizeBytes = 4
		var tmpVal uint32
		b := bytes.NewBuffer(data[0:4])
		binary.Read(b, binary.BigEndian, &tmpVal)
		sizeVal = int(tmpVal)
		if hasExpected && expectedVal != uint64(tmpVal) {
			return 0, 0, 0, 0, 0, 0, true, ignore, nil
		}
	case reflect.Uint16:
		if len(data) < 2 {
			return 0, 0, 0, 0, 0, 0, false, ignore, errors.New("data not long enough for uint16")
		}
		size = 1
		sizeBytes = 2
		var tmpVal uint16
		b := bytes.NewBuffer(data[0:2])
		binary.Read(b, binary.BigEndian, &tmpVal)
		sizeVal = int(tmpVal)
		if hasExpected && expectedVal != uint64(tmpVal) {
			return 0, 0, 0, 0, 0, 0, true, ignore, nil
		}
	case reflect.Uint8:
		if len(data) < 1 {
			return 0, 0, 0, 0, 0, 0, false, ignore, errors.New("data not long enough for uint8")
		}
		size = 1
		sizeBytes = 1
		sizeVal = int(data[0])
		if hasExpected && expectedVal != uint64(data[0]) {
			return 0, 0, 0, 0, 0, 0, true, ignore, nil
		}
	case reflect.Array:
		// fixed length array
		if size > 0 && size != fieldType.Len() {
			return 0, 0, 0, 0, 0, 0, false, ignore, fmt.Errorf("array length mismatch: %v != %v", size, fieldType.Len())
		}
		size = fieldType.Len()
		if size == 0 {
			sizeBytes = 0
			break
		}
		elemType := fieldType.Elem()
		if elementSizeBytes == 0 {
			elementSizeBytes = sizeBytes / size // size of a single element, if known (zero otherwise)
		}
		sizeBytes = 0
		// log.Printf("in array size, size: %v, element size: %v", size, elementSizeBytes)
		actualElementSizeBytes := 0
		for i := 0; i < fieldType.Len(); i++ {
			elementData := data[sizeBytes:]
			if elementSizeBytes > 0 {
				elementData = data[sizeBytes : sizeBytes+elementSizeBytes]
			}
			eName := ""
			if fieldName != "" {
				eName = fmt.Sprintf("%s[%d]", fieldName, i)
			}
			_, _, _, actualElementSizeBytes, _, _, _, _, err = getASN1FieldSize(elemType, "", eName, elementSizeBytes, sizes, globalSizes, elementData)
			if err != nil {
				return 0, 0, 0, 0, 0, 0, false, ignore, err
			}
			if actualElementSizeBytes > 0 {
				sizeBytes += actualElementSizeBytes
			} else {
				sizeBytes += elementSizeBytes
			}
		}
		if actualElementSizeBytes > 0 && elementSizeBytes == 0 {
			elementSizeBytes = actualElementSizeBytes
		}
	case reflect.Slice:
		if size == 0 {
			sizeBytes = 0
			break
		}
		actualSizeBytes := 0
		elemType := fieldType.Elem()
		// log.Printf("in slice size, size: %v sizeBytes: %v elementSizeBytes: %v", size, sizeBytes, elementSizeBytes)
		if size > 0 {
			// there is a prescribed size, so we use it
			if elementSizeBytes == 0 {
				elementSizeBytes = sizeBytes / size // size of a single element, if known (zero otherwise)
			}
			// log.Printf("in slice size fixed size, compute element size, size: %v sizeBytes: %v elementSizeBytes: %v", size, sizeBytes, elementSizeBytes)
			actualElementSizeBytes := 0
			for i := 0; i < size && len(data) >= actualSizeBytes+elementSizeBytes; i++ {
				elementData := data[actualSizeBytes:]
				if elementSizeBytes > 0 {
					elementData = data[actualSizeBytes : actualSizeBytes+elementSizeBytes]
				}
				eName := ""
				if fieldName != "" {
					eName = fmt.Sprintf("%s[%d]", fieldName, i)
				}
				_, _, _, actualElementSizeBytes, _, _, _, _, err = getASN1FieldSize(elemType, "", eName, elementSizeBytes, sizes, globalSizes, elementData)
				if err != nil {
					return 0, 0, 0, 0, 0, 0, false, ignore, err
				}
				// log.Printf("actualElementSizeBytes: %d", actualElementSizeBytes)
				if actualElementSizeBytes > 0 && elementSizeBytes == 0 {
					elementSizeBytes = actualElementSizeBytes
				}
				actualSizeBytes += actualElementSizeBytes
			}
			sizeBytes = actualSizeBytes
		} else {
			// dynamic size, possibly min and max given
			actualElementSizeBytes := 0
			actualSize := 0
			if sizeBytes > 0 {
				for actualSize = 0; len(data[actualSizeBytes:]) >= elementSizeBytes && actualSizeBytes < sizeBytes; actualSize++ {
					elementData := data[actualSizeBytes:]
					if elementSizeBytes > 0 {
						elementData = data[actualSizeBytes : actualSizeBytes+elementSizeBytes]
					}
					eName := ""
					if fieldName != "" {
						eName = fmt.Sprintf("%s[%d]", fieldName, actualSize)
					}
					_, _, _, actualElementSizeBytes, _, _, _, _, err = getASN1FieldSize(elemType, "", eName, elementSizeBytes, sizes, globalSizes, elementData)
					if err != nil {
						return 0, 0, 0, 0, 0, 0, false, ignore, err
					}
					if actualElementSizeBytes > 0 && elementSizeBytes == 0 {
						elementSizeBytes = actualElementSizeBytes
					}
					actualSizeBytes += actualElementSizeBytes
				}
				size = actualSize
				sizeBytes = actualSizeBytes
			} else {
				if maxSize > 0 {
					for actualSize = 0; len(data[actualSizeBytes:]) >= elementSizeBytes && actualSize < maxSize; actualSize++ {
						elementData := data[actualSizeBytes:]
						if elementSizeBytes > 0 {
							elementData = data[actualSizeBytes : actualSizeBytes+elementSizeBytes]
						}
						eName := ""
						if fieldName != "" {
							eName = fmt.Sprintf("%s[%d]", fieldName, actualSize)
						}
						_, _, _, actualElementSizeBytes, _, _, _, _, err = getASN1FieldSize(elemType, "", eName, elementSizeBytes, sizes, globalSizes, elementData)
						if err != nil {
							return 0, 0, 0, 0, 0, 0, false, ignore, err
						}
						if actualElementSizeBytes > 0 && elementSizeBytes == 0 {
							elementSizeBytes = actualElementSizeBytes
						}
						actualSizeBytes += actualElementSizeBytes
					}
					size = actualSize
					sizeBytes = actualSizeBytes
				} else {
					for actualSize = 0; len(data[actualSizeBytes:]) >= elementSizeBytes; actualSize++ {
						elementData := data[actualSizeBytes:]
						if elementSizeBytes > 0 {
							elementData = data[actualSizeBytes : actualSizeBytes+elementSizeBytes]
						}
						eName := ""
						if fieldName != "" {
							eName = fmt.Sprintf("%s[%d]", fieldName, actualSize)
						}
						_, _, _, actualElementSizeBytes, _, _, _, _, err = getASN1FieldSize(elemType, "", eName, elementSizeBytes, sizes, globalSizes, elementData)
						if err != nil {
							return 0, 0, 0, 0, 0, 0, false, ignore, err
						}
						if actualElementSizeBytes > 0 && elementSizeBytes == 0 {
							elementSizeBytes = actualElementSizeBytes
						}
						actualSizeBytes += actualElementSizeBytes
					}
					size = actualSize
					sizeBytes = actualSizeBytes
				}
			}
			if minSize > 0 && actualSize < minSize {
				log.Printf("warn: size constraint violated:  %v (min: %v)", actualSize, minSize)
				// return 0, 0, 0, 0, 0, 0, false, fmt.Errorf("minimum size constraint violated: %v (min: %v)", actualSize, minSize)
			}
			if maxSize > 0 && actualSize > maxSize {
				log.Printf("warn: maximum size constraint violated: %v (max: %v)", actualSize, maxSize)
				// return 0, 0, 0, 0, 0, 0, false, fmt.Errorf("maximum size constraint violated: %v (max: %v)", actualSize, maxSize)
			}
		}
	case reflect.Struct:
		// log.Printf("in struct size, size: %v, sizeBytes: %v", size, sizeBytes)
		inStructPos := 0
		if sizeBytes == 0 { // unknown length, try to determine
			for i := 0; i < fieldType.NumField(); i++ { // iterate the struct's fields
				fieldData := data[inStructPos:]
				fieldIgnore := false
				_, _, _, fieldSizeBytes, _, fieldSizeVal, fieldStructureSize, fieldIgnore, err := getASN1FieldSize(fieldType.Field(i).Type, fieldType.Field(i).Tag.Get("aper"), fieldType.Field(i).Name, 0, sizes, globalSizes, fieldData)
				if err != nil {
					return 0, 0, 0, 0, 0, 0, false, ignore, err
				}
				if fieldIgnore {
					continue
				}
				if fieldStructureSize {
					inStructPos = fieldSizeVal
					break
				}
				inStructPos += fieldSizeBytes
			}
			sizeBytes = inStructPos
		}
		// log.Printf("in struct size after computing sizeBytes: %v", sizeBytes)
		size = 1
		elementSizeBytes = 0
		maxSize = 0
		minSize = 0
	}
	if fieldName != "" && sizeVal >= 0 {
		if global {
			globalSizes[fieldName] = sizeVal
		} else {
			sizes[fieldName] = sizeVal
		}
	}
	// log.Printf("sizes: %+v", sizes)
	return size, minSize, maxSize, sizeBytes, elementSizeBytes, sizeVal, structureSize, ignore, err
}

func initializeStruct(t reflect.Type, v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		ft := t.Field(i)
		switch ft.Type.Kind() {
		case reflect.Slice:
			f.Set(reflect.MakeSlice(ft.Type, 0, 0))
		case reflect.Struct:
			initializeStruct(ft.Type, f)
		case reflect.Ptr:
			fv := reflect.New(ft.Type.Elem())
			initializeStruct(ft.Type.Elem(), fv.Elem())
			f.Set(fv)
		default:
		}
	}
}

// parse a single field of an asn1 structure. Can also be used for the outer struct and handles all supported types.
// the size parameter is important for slices and strings, it contains the length (not in bytes, but in elements)
// for dynamic sizes (slice/string), minSize and maxSize must be given
// pointers are dereferenced and passed on
func parseASN1Field(field reflect.Value, fieldType reflect.Type, size int, minSize, maxSize int, sizeBytes int, elementSizeBytes int, data []byte, sizes, globalSizes map[string]int) (actualSize int, actualSizeBytes int, sizeVal int, err error) {
	// log.Printf("in parseASN1Field, type: %v, kind: %v, size: %v, sizeBytes: %v", fieldType, fieldType.Kind(), size, sizeBytes)
	switch fieldType.Kind() {
	case reflect.Ptr:
		// dereference the pointer, create a new element if required
		if field.IsNil() {
			newElement := reflect.New(field.Type().Elem())
			if newElement.Kind() == reflect.Struct {
				initializeStruct(field.Type().Elem(), newElement.Elem())
			}
			field.Set(newElement)
		}
		return parseASN1Field(field.Elem(), fieldType.Elem(), size, minSize, maxSize, sizeBytes, elementSizeBytes, data, sizes, globalSizes)
	case reflect.Int, reflect.Int64:
		if len(data) < 8 {
			return 0, 0, 0, errors.New("data not long enough")
		}
		actualSize = 1
		actualSizeBytes = 8
		var tmpVal int64
		b := bytes.NewBuffer(data[0:8])
		binary.Read(b, binary.BigEndian, &tmpVal)
		field.SetInt(tmpVal)
		if tmpVal >= 0 {
			sizeVal = int(tmpVal)
		}
	case reflect.Int32:
		if len(data) < 4 {
			return 0, 0, 0, errors.New("data not long enough")
		}
		actualSize = 1
		actualSizeBytes = 4
		var tmpVal int32
		b := bytes.NewBuffer(data[0:4])
		binary.Read(b, binary.BigEndian, &tmpVal)
		field.SetInt(int64(tmpVal))
		if tmpVal >= 0 {
			sizeVal = int(tmpVal)
		}
	case reflect.Int16:
		if len(data) < 2 {
			return 0, 0, 0, errors.New("data not long enough")
		}
		actualSize = 1
		actualSizeBytes = 2
		var tmpVal int16
		b := bytes.NewBuffer(data[0:2])
		binary.Read(b, binary.BigEndian, &tmpVal)
		field.SetInt(int64(tmpVal))
		if tmpVal >= 0 {
			sizeVal = int(tmpVal)
		}
	case reflect.Int8:
		if len(data) < 1 {
			return 0, 0, 0, errors.New("data not long enough")
		}
		actualSize = 1
		actualSizeBytes = 1
		var tmpVal int8
		b := bytes.NewBuffer(data[0:1])
		binary.Read(b, binary.BigEndian, &tmpVal)
		field.SetInt(int64(tmpVal))
		if tmpVal >= 0 {
			sizeVal = int(tmpVal)
		}
	case reflect.Uint, reflect.Uint64:
		if len(data) < 8 {
			return 0, 0, 0, errors.New("data not long enough")
		}
		actualSize = 1
		actualSizeBytes = 8
		var tmpVal uint64
		b := bytes.NewBuffer(data[0:8])
		binary.Read(b, binary.BigEndian, &tmpVal)
		field.SetUint(tmpVal)
		sizeVal = int(tmpVal)
	case reflect.Uint32:
		if len(data) < 4 {
			return 0, 0, 0, errors.New("data not long enough")
		}
		actualSize = 1
		actualSizeBytes = 4
		var tmpVal uint32
		b := bytes.NewBuffer(data[0:4])
		binary.Read(b, binary.BigEndian, &tmpVal)
		field.SetUint(uint64(tmpVal))
		sizeVal = int(tmpVal)
	case reflect.Uint16:
		if len(data) < 2 {
			return 0, 0, 0, errors.New("data not long enough")
		}
		actualSize = 1
		actualSizeBytes = 2
		var tmpVal uint16
		b := bytes.NewBuffer(data[0:2])
		binary.Read(b, binary.BigEndian, &tmpVal)
		field.SetUint(uint64(tmpVal))
		sizeVal = int(tmpVal)
	case reflect.Uint8:
		if len(data) < 1 {
			return 0, 0, 0, errors.New("data not long enough")
		}
		actualSize = 1
		actualSizeBytes = 1
		field.SetUint(uint64(data[0]))
		sizeVal = int(data[0])
	case reflect.Array:
		// fixed length array
		if size >= 0 && size != fieldType.Len() {
			return 0, 0, 0, fmt.Errorf("array length mismatch: %v != %v", size, fieldType.Len())
		}

		actualSize = fieldType.Len()
		if actualSize == 0 {
			break
		}
		actualSizeBytes = 0
		elemType := fieldType.Elem()
		if elementSizeBytes == 0 {
			elementSizeBytes = sizeBytes / actualSize // size of a single element, if known (zero otherwise)
		}
		actualElementSizeBytes := 0
		for i := 0; i < fieldType.Len(); i++ {
			elementData := data[actualSizeBytes:]
			if elementSizeBytes > 0 {
				elementData = data[actualSizeBytes : actualSizeBytes+elementSizeBytes]
			}
			_, actualElementSizeBytes, _, err = parseASN1Field(field.Index(i), elemType, 0, 0, 0, elementSizeBytes, 0, elementData, sizes, globalSizes)
			if err != nil {
				return 0, 0, 0, err
			}
			actualSizeBytes += actualElementSizeBytes
		}
	case reflect.String:
		if sizeBytes == 0 && size < 0 {
			return 0, 0, 0, fmt.Errorf("for strings size or sizebytes is required")
		}
		if size == 0 {
			break
		}
		str := ""
		var r rune
		if sizeBytes == 0 {
			if maxSize > 0 {
				for currPos, s := 0, 0; currPos < len(data) && len([]rune(str)) < maxSize; currPos += s {
					r, s = utf8.DecodeRune(data[currPos:])
					if r == utf8.RuneError {
						break
					}
					str += string(r)
				}
			} else {
				// log.Printf("about to decode runes for data: %v", data)
				for currPos, s := 0, 0; currPos < len(data) && len([]rune(str)) < size; currPos += s {
					// log.Printf("current position: %v - runes: %v - bytes: %v - data left: %v", currPos, len([]rune(str)), len(str), len(data[currPos:]))
					r, s = utf8.DecodeRune(data[currPos:])
					if r == utf8.RuneError {
						log.Printf("decode rune error")
						break
					}
					// log.Printf("decoded rune: %v", r)
					str += string(r)
				}
			}
		} else {
			// log.Printf("about to decode runes for data: %v", data)
			for currPos, s := 0, 0; currPos < len(data) && len(str) < sizeBytes; currPos += s {
				// log.Printf("current position: %v - runes: %v - bytes: %v - data left: %v", currPos, len([]rune(str)), len(str), len(data[currPos:]))
				r, s = utf8.DecodeRune(data[currPos:])
				if r == utf8.RuneError {
					log.Printf("decode rune error")
					break
				}
				// log.Printf("decoded rune: %v", r)
				str += string(r)
			}
		}
		field.SetString(str)
		actualSize = len([]rune(str))
		if minSize > 0 && actualSize < minSize {
			return 0, 0, 0, fmt.Errorf("string size mismatch %v (minimum: %v)", actualSize, minSize)
		}
		if size > 0 && actualSize != size {
			return 0, 0, 0, fmt.Errorf("string size mismatch %v (should be: %v)", actualSize, size)
		}
		actualSizeBytes = len(str)
		if sv, err := strconv.ParseInt(str, 0, 64); err == nil && sv >= 0 {
			sizeVal = int(sv)
		}
	case reflect.Slice:
		// log.Printf("in slice parse, size: %v", size)
		elemType := fieldType.Elem()
		if size > 0 {
			// there is a prescribed size, so we use it
			// log.Printf("create new fixed size slice, size: %v", size)
			field.Set(reflect.MakeSlice(fieldType, size, size))
			if elementSizeBytes == 0 {
				elementSizeBytes = sizeBytes / size // size of a single element, if known (zero otherwise)
			}
			// log.Printf("current elementsizebytes: %v", elementSizeBytes)
			// log.Printf("current data size: %v", len(data))
			// log.Printf("actualSizeBytes: %v", actualSizeBytes)
			actualElementSizeBytes := 0
			for i := 0; i < size && len(data) >= actualSizeBytes+elementSizeBytes; i++ {
				elementData := data[actualSizeBytes:]
				if elementSizeBytes > 0 {
					elementData = data[actualSizeBytes : actualSizeBytes+elementSizeBytes]
				}
				_, actualElementSizeBytes, _, err = parseASN1Field(field.Index(i), elemType, -1, 0, 0, elementSizeBytes, 0, elementData, sizes, globalSizes)
				if err != nil {
					return 0, 0, 0, err
				}
				if actualElementSizeBytes > 0 && elementSizeBytes == 0 {
					elementSizeBytes = actualElementSizeBytes
				}
				actualSizeBytes += actualElementSizeBytes
			}
			actualSize = size
		} else {
			// dynamic size, possibly min and max given
			field.Set(reflect.MakeSlice(fieldType, 0, 0))
			actualElementSizeBytes := 0
			if sizeBytes > 0 {
				for actualSize = 0; len(data[actualSizeBytes:]) >= elementSizeBytes && actualSizeBytes < sizeBytes; actualSize++ {
					elementData := data[actualSizeBytes:]
					if elementSizeBytes > 0 {
						elementData = data[actualSizeBytes : actualSizeBytes+elementSizeBytes]
					}
					newVal := reflect.New(elemType).Elem()
					_, actualElementSizeBytes, _, err = parseASN1Field(newVal, elemType, -1, 0, 0, elementSizeBytes, 0, elementData, sizes, globalSizes)
					if err != nil {
						return 0, 0, 0, err
					}
					field.Set(reflect.Append(field, newVal))
					if actualElementSizeBytes > 0 && elementSizeBytes == 0 {
						elementSizeBytes = actualElementSizeBytes
					}
					actualSizeBytes += actualElementSizeBytes
				}
			} else {
				if maxSize > 0 {
					for actualSize = 0; len(data[actualSizeBytes:]) >= elementSizeBytes && actualSize < maxSize; actualSize++ {
						elementData := data[actualSizeBytes:]
						if elementSizeBytes > 0 {
							elementData = data[actualSizeBytes : actualSizeBytes+elementSizeBytes]
						}
						newVal := reflect.New(elemType).Elem()
						_, actualElementSizeBytes, _, err = parseASN1Field(newVal, elemType, -1, 0, 0, elementSizeBytes, 0, elementData, sizes, globalSizes)
						if err != nil {
							return 0, 0, 0, err
						}
						field.Set(reflect.Append(field, newVal))
						if actualElementSizeBytes > 0 && elementSizeBytes == 0 {
							elementSizeBytes = actualElementSizeBytes
						}
						actualSizeBytes += actualElementSizeBytes
					}
				} else {
					for actualSize = 0; len(data[actualSizeBytes:]) >= elementSizeBytes; actualSize++ {
						elementData := data[actualSizeBytes:]
						if elementSizeBytes > 0 {
							elementData = data[actualSizeBytes : actualSizeBytes+elementSizeBytes]
						}
						newVal := reflect.New(elemType).Elem()
						_, actualElementSizeBytes, _, err = parseASN1Field(newVal, elemType, -1, 0, 0, elementSizeBytes, 0, elementData, sizes, globalSizes)
						if err != nil {
							return 0, 0, 0, err
						}
						field.Set(reflect.Append(field, newVal))
						if actualElementSizeBytes > 0 && elementSizeBytes == 0 {
							elementSizeBytes = actualElementSizeBytes
						}
						actualSizeBytes += actualElementSizeBytes
					}
				}
			}
			if minSize > 0 && actualSize < minSize {
				log.Printf("warn: minimum size constraint violated: %v (min: %v)", actualSize, minSize)
				// return 0, 0, 0, fmt.Errorf("minimum size constraint violated: %v (min: %v)", actualSize, minSize)
			}
			if maxSize > 0 && actualSize > maxSize {
				log.Printf("maximum size constraint violated: %v (max: %v)", actualSize, maxSize)
				// return 0, 0, 0, fmt.Errorf("maximum size constraint violated: %v (max: %v)", actualSize, maxSize)
			}
		}
	case reflect.Struct:
		if len(data) < sizeBytes {
			return 0, 0, 0, fmt.Errorf("struct size mismatch: data len %v (should be: %v)", len(data), sizeBytes)
		}
		if sizes == nil {
			sizes = make(map[string]int)
		}
		inStructPos := 0
		if sizeBytes == 0 {
			// do a first pass checking for a "structuresize" tag
			for i := 0; i < fieldType.NumField(); i++ { // iterate the struct's fields
				fieldData := data[inStructPos:]
				_, _, _, fieldSizeBytes, _, fieldSizeVal, fieldStructureSize, fieldIgnore, err := getASN1FieldSize(fieldType.Field(i).Type, fieldType.Field(i).Tag.Get("aper"), fieldType.Field(i).Name, 0, sizes, globalSizes, fieldData)
				if err != nil {
					// log.Printf("error: could not determine field length: %v", err)
					return 0, 0, 0, err
				}
				if fieldIgnore {
					continue
				}
				if fieldStructureSize {
					inStructPos = fieldSizeVal
					break
				}
				inStructPos += fieldSizeBytes
			}
			sizeBytes = inStructPos
		}

		// log.Printf("in struct parse, sizeBytes: %v %v", sizeBytes, fieldType.Name())
		bytesLeft := sizeBytes
		inStructPos = 0

		for i := 0; i < fieldType.NumField(); i++ { // iterate the struct's fields
			fieldData := data[inStructPos:]
			if sizeBytes > 0 && len(data) <= sizeBytes {
				fieldData = data[inStructPos:sizeBytes]
			}
			if bytesLeft > 0 && len(data) <= inStructPos+bytesLeft {
				fieldData = data[inStructPos : inStructPos+bytesLeft]
			}
			inSizeBytes := 0
			if i == fieldType.NumField()-1 {
				inSizeBytes = bytesLeft
			}
			fieldSize, fieldMinSize, fieldMaxSize, fieldSizeBytes, fieldElementSizeBytes, _, _, fieldIgnore, err := getASN1FieldSize(fieldType.Field(i).Type, fieldType.Field(i).Tag.Get("aper"), fieldType.Field(i).Name, inSizeBytes, sizes, globalSizes, fieldData)
			if err != nil {
				return 0, 0, 0, err
			}
			if fieldIgnore {
				continue
			}
			if fieldSizeBytes == 0 && i == fieldType.NumField()-1 {
				// TODO: the test `i == fieldType.NumField()-1` checks that the field is the last field in the struct. This does not cover the case where an ignored field is the last field.
				fieldSizeBytes = bytesLeft
			}
			// log.Printf("get field size result: %v %v %v %v %v", fieldSize, fieldMinSize, fieldMaxSize, fieldSizeBytes, fieldElementSizeBytes)
			if fieldSizeBytes > 0 {
				fieldData = data[inStructPos : inStructPos+fieldSizeBytes]
			} else {
				// log.Println("zero field size bytes, skipping")
				continue
			}
			_, fieldActualSizeBytes, _, err := parseASN1Field(field.Field(i), fieldType.Field(i).Type, fieldSize, fieldMinSize, fieldMaxSize, fieldSizeBytes, fieldElementSizeBytes, fieldData, sizes, globalSizes)
			if err != nil {
				return 0, 0, 0, err
			}
			// log.Printf("parse asn field result: %v %v %v", fieldActualSize, fieldActualSizeBytes, fieldSizeVal)
			if fieldActualSizeBytes > 0 {
				bytesLeft -= fieldActualSizeBytes
				inStructPos += fieldActualSizeBytes
			} else {
				if fieldSizeBytes > 0 {
					bytesLeft -= fieldSizeBytes
					inStructPos += fieldSizeBytes
				}
			}
			// log.Printf("struct field %d inStructPos %d bytesLeft %d", i, inStructPos, bytesLeft)
		}
		actualSize = 1
		actualSizeBytes = inStructPos
	default:
		return 0, 0, 0, fmt.Errorf("unsupported kind: %v", fieldType.Kind())
	}
	return actualSize, actualSizeBytes, sizeVal, nil
}
