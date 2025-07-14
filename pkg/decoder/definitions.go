package decoder

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"time"

	"github.com/keybase/go-crypto/brainpool"
)

/*
All definitions required to parse vu and driver data data.
Extracted from the definitions in the following eu regulatory documents available at https://eur-lex.europa.eu/
- Commission Implementing Regulation (EU) 2016/799 of 18 March 2016 implementing Regulation (EU) No 165/2014 of the European Parliament and of the Council laying down the requirements for the construction, testing, installation, operation and repair of tachographs and their components
-- consolidated version of 2020-02-26, including changes from
-- Commission Implementing Regulation (EU) 2018/502 of 28 February 2018 amending Implementing Regulation (EU) 2016/799 laying down the requirements for the construction, testing, installation, operation and repair of tachographs and their components
*/

/*
=====================
Top-level definitions
=====================

- Card (1st and 2nd gen driver data)
- Vu (1st and 2nd gen vehicle unit)
*/

// data blocks are
// 3 bytes tag (first 2 bytes are the smart data EF FID, with an added "00" or "01"; "00" is the actual data and "01" is the signature. "02" and "03" are added for 2nd generation data ("02") and signature ("03"))
// 2 bytes length (big endian) - payload length in bytes
// after these 5 bytes follow <length> bytes of payload which is to be parsed
// note that both 1st and 2nd gen data blocks may be present on the same data!
// this definition is extracted from Appendix 2, 4.1 and 4.2.1
type Card struct {
	CardIccIdentificationFirstGen                                         CardIccIdentificationFirstGen                       `tlv:"tag=0x000200" json:"card_icc_identification_1,omitempty"`
	CardIccIdentificationFirstGenSignature                                SignatureFirstGen                                   `tlv:"tag=0x000201" json:"card_icc_identification_1_sig,omitempty"`
	CardIccIdentificationSecondGen                                        CardIccIdentificationSecondGen                      `tlv:"tag=0x000202" json:"card_icc_identification_2,omitempty"`
	CardIccIdentificationSecondGenSignature                               SignatureSecondGen                                  `tlv:"tag=0x000203" json:"card_icc_identification_2_sig,omitempty"`
	CardChipIdentificationFirstGen                                        CardChipIdentification                              `tlv:"tag=0x000500" json:"card_chip_identification_1,omitempty"`
	CardChipIdentificationFirstGenSignature                               SignatureFirstGen                                   `tlv:"tag=0x000501" json:"card_chip_identification_1_sig,omitempty"`
	CardChipIdentificationSecondGen                                       CardChipIdentification                              `tlv:"tag=0x000502" json:"card_chip_identification_2,omitempty"`
	CardChipIdentificationSecondGenSignature                              SignatureSecondGen                                  `tlv:"tag=0x000503" json:"card_chip_identification_2_sig,omitempty"`
	DriverCardApplicationIdentificationFirstGen                           DriverCardApplicationIdentificationFirstGen         `tlv:"tag=0x050100" json:"driver_card_application_identification_1,omitempty"`
	DriverCardApplicationIdentificationFirstGenSignature                  SignatureFirstGen                                   `tlv:"tag=0x050101" json:"driver_card_application_identification_1_sig,omitempty"`
	DriverCardApplicationIdentificationSecondGen                          DriverCardApplicationIdentificationSecondGen        `tlv:"tag=0x050102" json:"driver_card_application_identification_2,omitempty"`
	DriverCardApplicationIdentificationSecondGenSignature                 SignatureSecondGen                                  `tlv:"tag=0x050103" json:"driver_card_application_identification_2_sig,omitempty"`
	CardEventDataFirstGen                                                 CardEventDataFirstGen                               `tlv:"tag=0x050200" json:"card_event_data_1,omitempty"`
	CardEventDataFirstGenSignature                                        SignatureFirstGen                                   `tlv:"tag=0x050201" json:"card_event_data_1_sig,omitempty"`
	CardEventDataSecondGen                                                CardEventDataSecondGen                              `tlv:"tag=0x050202" json:"card_event_data_2,omitempty"`
	CardEventDataSecondGenSignature                                       SignatureSecondGen                                  `tlv:"tag=0x050203" json:"card_event_data_2_sig,omitempty"`
	CardFaultDataFirstGen                                                 CardFaultDataFirstGen                               `tlv:"tag=0x050300" json:"card_fault_data_1,omitempty"`
	CardFaultDataFirstGenSignature                                        SignatureFirstGen                                   `tlv:"tag=0x050301" json:"card_fault_data_1_sig,omitempty"`
	CardFaultDataSecondGen                                                CardFaultDataSecondGen                              `tlv:"tag=0x050302" json:"card_fault_data_2,omitempty"`
	CardFaultDataSecondGenSignature                                       SignatureSecondGen                                  `tlv:"tag=0x050303" json:"card_fault_data_2_sig,omitempty"`
	CardDriverActivityFirstGen                                            CardDriverActivityFirstGen                          `tlv:"tag=0x050400" json:"card_driver_activity_1,omitempty"`
	CardDriverActivityFirstGenSignature                                   SignatureFirstGen                                   `tlv:"tag=0x050401" json:"card_driver_activity_1_sig,omitempty"`
	CardDriverActivitySecondGen                                           CardDriverActivitySecondGen                         `tlv:"tag=0x050402" json:"card_driver_activity_2,omitempty"`
	CardDriverActivitySecondGenSignature                                  SignatureSecondGen                                  `tlv:"tag=0x050403" json:"card_driver_activity_2_sig,omitempty"`
	CardVehiclesUsedFirstGen                                              CardVehiclesUsedFirstGen                            `tlv:"tag=0x050500" json:"card_vehicles_used_1,omitempty"`
	CardVehiclesUsedFirstGenSignature                                     SignatureFirstGen                                   `tlv:"tag=0x050501" json:"card_vehicles_used_1_sig,omitempty"`
	CardVehiclesUsedSecondGen                                             CardVehiclesUsedSecondGen                           `tlv:"tag=0x050502" json:"card_vehicles_used_2,omitempty"`
	CardVehiclesUsedSecondGenSignature                                    SignatureSecondGen                                  `tlv:"tag=0x050503" json:"card_vehicles_used_2_sig,omitempty"`
	CardPlaceDailyWorkPeriodFirstGen                                      CardPlaceDailyWorkPeriodFirstGen                    `tlv:"tag=0x050600" json:"card_place_daily_work_period_1,omitempty"`
	CardPlaceDailyWorkPeriodFirstGenSignature                             SignatureFirstGen                                   `tlv:"tag=0x050601" json:"card_place_daily_work_period_1_sig,omitempty"`
	CardPlaceDailyWorkPeriodSecondGen                                     CardPlaceDailyWorkPeriodSecondGen                   `tlv:"tag=0x050602" json:"card_place_daily_work_period_2,omitempty"`
	CardPlaceDailyWorkPeriodSecondGenSignature                            SignatureSecondGen                                  `tlv:"tag=0x050603" json:"card_place_daily_work_period_2_sig,omitempty"`
	CardCurrentUseFirstGen                                                CardCurrentUse                                      `tlv:"tag=0x050700" json:"card_current_use_1,omitempty"`
	CardCurrentUseFirstGenSignature                                       SignatureFirstGen                                   `tlv:"tag=0x050701" json:"card_current_use_1_sig,omitempty"`
	CardCurrentUseSecondGen                                               CardCurrentUse                                      `tlv:"tag=0x050702" json:"card_current_use_2,omitempty"`
	CardCurrentUseSecondGenSignature                                      SignatureSecondGen                                  `tlv:"tag=0x050703" json:"card_current_use_2_sig,omitempty"`
	CardControlActivityDataRecordFirstGen                                 CardControlActivityDataRecord                       `tlv:"tag=0x050800" json:"card_control_activity_data_record_1,omitempty"`
	CardControlActivityDataRecordFirstGenSignature                        SignatureFirstGen                                   `tlv:"tag=0x050801" json:"card_control_activity_data_record_1_sig,omitempty"`
	CardControlActivityDataRecordSecondGen                                CardControlActivityDataRecord                       `tlv:"tag=0x050802" json:"card_control_activity_data_record_2,omitempty"`
	CardControlActivityDataRecordSecondGenSignature                       SignatureSecondGen                                  `tlv:"tag=0x050803" json:"card_control_activity_data_record_2_sig,omitempty"`
	LastCardDownloadFirstGen                                              LastCardDownload                                    `tlv:"tag=0x050e00" json:"last_card_download_1,omitempty"`
	LastCardDownloadFirstGenSignature                                     SignatureFirstGen                                   `tlv:"tag=0x050e01" json:"last_card_download_1_sig,omitempty"`
	LastCardDownloadSecondGen                                             LastCardDownload                                    `tlv:"tag=0x050e02" json:"last_card_download_2,omitempty"`
	LastCardDownloadSecondGenSignature                                    SignatureSecondGen                                  `tlv:"tag=0x050e03" json:"last_card_download_2_sig,omitempty"`
	CardIdentificationAndDriverCardHolderIdentificationFirstGen           CardIdentificationAndDriverCardHolderIdentification `tlv:"tag=0x052000" json:"card_identification_and_driver_card_holder_identification_1,omitempty"`
	CardIdentificationAndDriverCardHolderIdentificationFirstGenSignature  SignatureFirstGen                                   `tlv:"tag=0x052001" json:"card_identification_and_driver_card_holder_identification_1_sig,omitempty"`
	CardIdentificationAndDriverCardHolderIdentificationSecondGen          CardIdentificationAndDriverCardHolderIdentification `tlv:"tag=0x052002" json:"card_identification_and_driver_card_holder_identification_2,omitempty"`
	CardIdentificationAndDriverCardHolderIdentificationSecondGenSignature SignatureSecondGen                                  `tlv:"tag=0x052003" json:"card_identification_and_driver_card_holder_identification_2_sig,omitempty"`
	CardDrivingLicenceInformationFirstGen                                 CardDrivingLicenceInformation                       `tlv:"tag=0x052100" json:"card_driving_licence_information_1,omitempty"`
	CardDrivingLicenceInformationFirstGenSignature                        SignatureFirstGen                                   `tlv:"tag=0x052101" json:"card_driving_licence_information_1_sig,omitempty"`
	CardDrivingLicenceInformationSecondGen                                CardDrivingLicenceInformation                       `tlv:"tag=0x052102" json:"card_driving_licence_information_2,omitempty"`
	CardDrivingLicenceInformationSecondGenSignature                       SignatureSecondGen                                  `tlv:"tag=0x052103" json:"card_driving_licence_information_2_sig,omitempty"`
	SpecificConditionsFirstGen                                            SpecificConditionsFirstGen                          `tlv:"tag=0x052200" json:"specific_conditions_1,omitempty"`
	SpecificConditionsFirstGenSignature                                   SignatureFirstGen                                   `tlv:"tag=0x052201" json:"specific_conditions_1_sig,omitempty"`
	SpecificConditionsSecondGen                                           SpecificConditionsSecondGen                         `tlv:"tag=0x052202" json:"specific_conditions_2,omitempty"`
	SpecificConditionsSecondGenSignature                                  SignatureSecondGen                                  `tlv:"tag=0x052203" json:"specific_conditions_2_sig,omitempty"`
	CardVehicleUnitsUsed                                                  CardVehicleUnitsUsed                                `tlv:"tag=0x052302" json:"card_vehicle_units_used,omitempty"`
	CardVehicleUnitsUsedSignature                                         SignatureSecondGen                                  `tlv:"tag=0x052303" json:"card_vehicle_units_used_sig,omitempty"`
	GNSSAccumulatedDriving                                                GNSSAccumulatedDriving                              `tlv:"tag=0x052402" json:"gnss_accumulated_driving,omitempty"`
	GNSSAccumulatedDrivingSignature                                       SignatureSecondGen                                  `tlv:"tag=0x052403" json:"gnss_accumulated_driving_sig,omitempty"`
	DriverCardApplicationIdentificationSecondGenV2                        DriverCardApplicationIdentificationSecondGenV2      `tlv:"tag=0x052502" json:"driver_card_application_identification_v2,omitempty"`
	DriverCardApplicationIdentificationSecondGenV2Signature               SignatureSecondGen                                  `tlv:"tag=0x052503" json:"driver_card_application_identification_v2_sig,omitempty"`
	CardPlaceAuthDailyWorkPeriod                                          CardPlaceAuthDailyWorkPeriod                        `tlv:"tag=0x052602" json:"card_place_auth_daily_work_period,omitempty"`
	CardPlaceAuthDailyWorkPeriodSignature                                 SignatureSecondGen                                  `tlv:"tag=0x052603" json:"card_place_auth_daily_work_period_sig,omitempty"`
	GNSSAuthAccumulatedDriving                                            GNSSAuthAccumulatedDriving                          `tlv:"tag=0x052702" json:"gnss_auth_accumulated_driving,omitempty"`
	GNSSAuthAccumulatedDrivingSignature                                   SignatureSecondGen                                  `tlv:"tag=0x052703" json:"gnss_auth_accumulated_driving_sig,omitempty"`
	CardBorderCrossings                                                   CardBorderCrossings                                 `tlv:"tag=0x052802" json:"card_border_crossings,omitempty"`
	CardBorderCrossingsSignature                                          SignatureSecondGen                                  `tlv:"tag=0x052803" json:"card_border_crossings_sig,omitempty"`
	CardLoadUnloadOperations                                              CardLoadUnloadOperations                            `tlv:"tag=0x052902" json:"card_load_unload_operations,omitempty"`
	CardLoadUnloadOperationsSignature                                     SignatureSecondGen                                  `tlv:"tag=0x052903" json:"card_load_unload_operations_sig,omitempty"`
	CardLoadTypeEntries                                                   CardLoadTypeEntries                                 `tlv:"tag=0x053002" json:"card_load_type_entries,omitempty"`
	CardLoadTypeEntriesSignature                                          SignatureSecondGen                                  `tlv:"tag=0x053003" json:"card_load_type_entries_sig,omitempty"`
	VuConfiguration                                                       VuConfiguration                                     `tlv:"tag=0x054002" json:"vu_configuration,omitempty"`
	VuConfigurationSignature                                              SignatureSecondGen                                  `tlv:"tag=0x054003" json:"vu_configuration_sig,omitempty"`
	CardCertificateFirstGen                                               CertificateFirstGen                                 `tlv:"tag=0xc10000" json:"card_certificate,omitempty"`
	CardMACertificate                                                     CertificateSecondGen                                `tlv:"tag=0xc10002" json:"card_ma_certificate,omitempty"`
	CardSignCertificate                                                   CertificateSecondGen                                `tlv:"tag=0xc10102" json:"card_sign_certificate,omitempty"`
	MemberStateCertificateFirstGen                                        CertificateFirstGen                                 `tlv:"tag=0xc10800" json:"member_state_certificate,omitempty"`
	CACertificate                                                         CertificateSecondGen                                `tlv:"tag=0xc10802" json:"ca_certificate,omitempty"`
	LinkCertificateSecondGen                                              CertificateSecondGen                                `tlv:"tag=0xc10902" json:"link_certificate,omitempty"`
}

func (c *Card) SignCertificateFirstGen() CertificateFirstGen {
	if err := c.MemberStateCertificateFirstGen.Decode(); err == nil {
		if _, ok := PKsFirstGen[c.MemberStateCertificateFirstGen.DecodedCertificate.CertificateHolderReference]; !ok {
			PKsFirstGen[c.MemberStateCertificateFirstGen.DecodedCertificate.CertificateHolderReference] = *c.MemberStateCertificateFirstGen.DecodedCertificate
		}
	}
	if err := c.CardCertificateFirstGen.Decode(); err == nil {
		if _, ok := PKsFirstGen[c.CardCertificateFirstGen.DecodedCertificate.CertificateHolderReference]; !ok {
			PKsFirstGen[c.CardCertificateFirstGen.DecodedCertificate.CertificateHolderReference] = *c.CardCertificateFirstGen.DecodedCertificate
		}
	}
	return c.CardCertificateFirstGen
}

func (c *Card) SignCertificateSecondGen() CertificateSecondGen {
	// not quite sure about the order, does the link certificate require the ca certificate (as given in the data) or the other way around, or are those independent?
	// we try to decode ca first, then link, then ca again, just in case
	if err := c.CACertificate.Decode(); err == nil {
		if _, ok := PKsSecondGen[c.CACertificate.DecodedCertificate.CertificateBody.CertificateHolderReference]; !ok {
			PKsSecondGen[c.CACertificate.DecodedCertificate.CertificateBody.CertificateHolderReference] = *c.CACertificate.DecodedCertificate
		}
	}
	if err := c.LinkCertificateSecondGen.Decode(); err == nil {
		if _, ok := PKsSecondGen[c.LinkCertificateSecondGen.DecodedCertificate.CertificateBody.CertificateHolderReference]; !ok {
			PKsSecondGen[c.LinkCertificateSecondGen.DecodedCertificate.CertificateBody.CertificateHolderReference] = *c.LinkCertificateSecondGen.DecodedCertificate
		}
	}
	if err := c.CACertificate.Decode(); err == nil {
		if _, ok := PKsSecondGen[c.CACertificate.DecodedCertificate.CertificateBody.CertificateHolderReference]; !ok {
			PKsSecondGen[c.CACertificate.DecodedCertificate.CertificateBody.CertificateHolderReference] = *c.CACertificate.DecodedCertificate
		}
	}
	// the mutual auth certification is probably not needed here, we try to decode it anyway
	if err := c.CardMACertificate.Decode(); err == nil {
		if _, ok := PKsSecondGen[c.CardMACertificate.DecodedCertificate.CertificateBody.CertificateHolderReference]; !ok {
			PKsSecondGen[c.CardMACertificate.DecodedCertificate.CertificateBody.CertificateHolderReference] = *c.CardMACertificate.DecodedCertificate
		}
	}
	if err := c.CardSignCertificate.Decode(); err == nil {
		if _, ok := PKsSecondGen[c.CardSignCertificate.DecodedCertificate.CertificateBody.CertificateHolderReference]; !ok {
			PKsSecondGen[c.CardSignCertificate.DecodedCertificate.CertificateBody.CertificateHolderReference] = *c.CardSignCertificate.DecodedCertificate
		}
	}
	return c.CardSignCertificate
}

// VU data specs
// not in tlv format, but in tv (and the tags are only 2 bytes)
// defined in Appendix 7, 2.2.6
// note that there is no assumption in the docs about how many of each of the tags appear in the vu data, so
// we restrict to *one* overview block in order to allow only *one* signing certificate, but do not restrict the
// number of all other blocks (in real data, there are regularly multiple blocks of the same type)
// also, there is no assumption about if there are both first and second generation data in the same dataset,
// so we do allow it.
type Vu struct {
	VuDownloadInterfaceVersion   DownloadInterfaceVersion       `tv:"tag=0x7600" json:"vu_download_interface_version"`
	VuOverviewFirstGen           VuOverviewFirstGen             `tv:"tag=0x7601" json:"vu_overview_1"`
	VuOverviewSecondGen          VuOverviewSecondGen            `tv:"tag=0x7621" json:"vu_overview_2"`
	VuOverviewSecondGenV2        VuOverviewSecondGenV2          `tv:"tag=0x7631" json:"vu_overview_2_v2"`
	VuActivitiesFirstGen         []VuActivitiesFirstGen         `tv:"tag=0x7602" json:"vu_activities_1"`
	VuActivitiesSecondGen        []VuActivitiesSecondGen        `tv:"tag=0x7622" json:"vu_activities_2"`
	VuActivitiesSecondGenV2      []VuActivitiesSecondGenV2      `tv:"tag=0x7632" json:"vu_activities_2_v2"`
	VuEventsAndFaultsFirstGen    []VuEventsAndFaultsFirstGen    `tv:"tag=0x7603" json:"vu_events_and_faults_1"`
	VuEventsAndFaultsSecondGen   []VuEventsAndFaultsSecondGen   `tv:"tag=0x7623" json:"vu_events_and_faults_2"`
	VuEventsAndFaultsSecondGenV2 []VuEventsAndFaultsSecondGenV2 `tv:"tag=0x7633" json:"vu_events_and_faults_2_v2"`
	VuDetailedSpeedFirstGen      []VuDetailedSpeedFirstGen      `tv:"tag=0x7604" json:"vu_detailed_speed_1"`
	VuDetailedSpeedSecondGen     []VuDetailedSpeedSecondGen     `tv:"tag=0x7624" json:"vu_detailed_speed_2"`
	// No VuDetailedSpeedSecondGenV2! According to the specs, the tag 7634 does not exist
	VuTechnicalDataFirstGen    []VuTechnicalDataFirstGen    `tv:"tag=0x7605" json:"vu_technical_data_1"`
	VuTechnicalDataSecondGen   []VuTechnicalDataSecondGen   `tv:"tag=0x7625" json:"vu_technical_data_2"`
	VuTechnicalDataSecondGenV2 []VuTechnicalDataSecondGenV2 `tv:"tag=0x7635" json:"vu_technical_data_2_v2"`
}

// SignCertificateFirstGen returns the CertificateFirstGen to verify the signature of the first generation blocks in the Vu data
// it also decodes all known certificates and inserts them into the global certificate store PKsFirstGen
func (v *Vu) SignCertificateFirstGen() CertificateFirstGen {
	dc := CertificateFirstGen(v.VuOverviewFirstGen.MemberStateCertificate)
	if err := dc.Decode(); err == nil {
		if _, ok := PKsFirstGen[dc.DecodedCertificate.CertificateHolderReference]; !ok {
			PKsFirstGen[dc.DecodedCertificate.CertificateHolderReference] = *dc.DecodedCertificate
		}
	}
	cert := CertificateFirstGen(v.VuOverviewFirstGen.VuCertificate)
	if err := cert.Decode(); err == nil {
		if _, ok := PKsFirstGen[cert.DecodedCertificate.CertificateHolderReference]; !ok {
			PKsFirstGen[cert.DecodedCertificate.CertificateHolderReference] = *cert.DecodedCertificate
		}
	}
	return cert
}

// SignCertificateSecondGen returns the CertificateSecondGen to verify the signature of the second generation blocks in the Vu data
// it also decodes all known certificates and inserts them into the global certificate store PKsSecondGen
func (v *Vu) SignCertificateSecondGen() CertificateSecondGen {
	if len(v.VuOverviewSecondGen.VuCertificateRecordArray.Records) == 0 && len(v.VuOverviewSecondGenV2.VuCertificateRecordArray.Records) == 0 {
		return CertificateSecondGen{}
	}
	if len(v.VuOverviewSecondGen.MemberStateCertificateRecordArray.Records) > 0 {
		// *SHOULD* be only one
		for _, c := range v.VuOverviewSecondGen.MemberStateCertificateRecordArray.Records {
			dc := CertificateSecondGen(c)
			if err := dc.Decode(); err == nil {
				if _, ok := PKsSecondGen[dc.DecodedCertificate.CertificateBody.CertificateHolderReference]; !ok { // we could check for validity here. However, the validity check seems broken, at least for the data tested (i.e. the member state certificate given here is signed, but the signature cannot be verified vs the ca).
					PKsSecondGen[dc.DecodedCertificate.CertificateBody.CertificateHolderReference] = *dc.DecodedCertificate
				}
			}
		}
	}
	if len(v.VuOverviewSecondGenV2.MemberStateCertificateRecordArray.Records) > 0 {
		// *SHOULD* be only one
		for _, c := range v.VuOverviewSecondGenV2.MemberStateCertificateRecordArray.Records {
			dc := CertificateSecondGen(c)
			if err := dc.Decode(); err == nil {
				if _, ok := PKsSecondGen[dc.DecodedCertificate.CertificateBody.CertificateHolderReference]; !ok { // we could check for validity here. However, the validity check seems broken, at least for the data tested (i.e. the member state certificate given here is signed, but the signature cannot be verified vs the ca).
					PKsSecondGen[dc.DecodedCertificate.CertificateBody.CertificateHolderReference] = *dc.DecodedCertificate
				}
			}
		}
	}
	var cert CertificateSecondGen
	for i, c := range v.VuOverviewSecondGen.VuCertificateRecordArray.Records {
		// *SHOULD* be only one
		dc := CertificateSecondGen(c)
		if err := dc.Decode(); err == nil {
			if _, ok := PKsSecondGen[dc.DecodedCertificate.CertificateBody.CertificateHolderReference]; !ok {
				PKsSecondGen[dc.DecodedCertificate.CertificateBody.CertificateHolderReference] = *dc.DecodedCertificate
			}
		}
		if i == 0 {
			cert = dc
		}
	}
	for i, c := range v.VuOverviewSecondGenV2.VuCertificateRecordArray.Records {
		// *SHOULD* be only one
		dc := CertificateSecondGen(c)
		if err := dc.Decode(); err == nil {
			if _, ok := PKsSecondGen[dc.DecodedCertificate.CertificateBody.CertificateHolderReference]; !ok {
				PKsSecondGen[dc.DecodedCertificate.CertificateBody.CertificateHolderReference] = *dc.DecodedCertificate
			}
		}
		if i == 0 {
			cert = dc
		}
	}
	return cert
}

type VuOverviewFirstGen struct {
	Verified                          bool                              `aper:"-" json:"verified"`
	MemberStateCertificate            MemberStateCertificateFirstGen    `json:"member_state_certificate"`
	VuCertificate                     VuCertificateFirstGen             `json:"vu_certificate"`
	VehicleIdentificationNumber       VehicleIdentificationNumber       `json:"vehicle_identification_number"`
	VehicleRegistrationIdentification VehicleRegistrationIdentification `json:"vehicle_registration_identification"`
	CurrentDateTime                   CurrentDateTime                   `json:"current_date_time"`
	VuDownloadablePeriod              VuDownloadablePeriod              `json:"vu_downloadable_period"`
	CardSlotsStatus                   CardSlotsStatus                   `json:"card_slots_status"`
	VuDownloadActivityData            VuDownloadActivityDataFirstGen    `json:"vu_download_activity_data"`
	VuCompanyLocksData                VuCompanyLocksDataFirstGen        `json:"vu_company_locks_data"`
	VuControlActivityData             VuControlActivityDataFirstGen     `json:"vu_control_activity_data"`
	Signature                         SignatureFirstGen                 `json:"signature"`
}

func (ov VuOverviewFirstGen) VerifyFirstGen(cert CertificateFirstGen, data []byte) (bool, error) {
	if len(data) <= 2*194+128 {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), 2*194+128)
	}
	start := 2 * 194       // only the data between the 2 certificates and the signature is signed. 1st gen has fixed size: 194 per cert
	end := len(data) - 128 // 128 bytes signature
	signData := data[start:end]
	signature := ov.Signature
	return signature.Verify(cert, signData)
}

type VuOverviewSecondGen struct {
	Verified                               bool                                   `aper:"-" json:"verified"`
	MemberStateCertificateRecordArray      MemberStateCertificateRecordArray      `json:"member_state_certificate_record_array"`
	VuCertificateRecordArray               VuCertificateRecordArray               `json:"vu_certificate_record_array"`
	VehicleIdentificationNumberRecordArray VehicleIdentificationNumberRecordArray `json:"vehicle_identification_number_record_array"`
	VehicleRegistrationNumberRecordArray   VehicleRegistrationNumberRecordArray   `json:"vehicle_registration_number_record_array"`
	CurrentDateTimeRecordArray             CurrentDateTimeRecordArray             `json:"current_date_time_record_array"`
	VuDownloadablePeriodRecordArray        VuDownloadablePeriodRecordArray        `json:"vu_downloadable_period_record_array"`
	CardSlotsStatusRecordArray             CardSlotsStatusRecordArray             `json:"card_slots_status_record_array"`
	VuDownloadActivityDataRecordArray      VuDownloadActivityDataRecordArray      `json:"vu_download_activity_data_record_array"`
	VuCompanyLocksRecordArray              VuCompanyLocksRecordArray              `json:"vu_company_locks_record_array"`
	VuControlActivityRecordArray           VuControlActivityRecordArray           `json:"vu_control_activity_record_array"`
	SignatureRecordArray                   SignatureRecordArray                   `json:"signature_record_array"`
}

func (ov VuOverviewSecondGen) VerifySecondGen(cert CertificateSecondGen, data []byte) (bool, error) {
	if len(ov.SignatureRecordArray.Records) == 0 {
		return false, fmt.Errorf("no signature")
	}
	signature := ov.SignatureRecordArray.Records[0]
	/*
		// we could keep the overview verification self-contained, as the cert argument is actually the VuCertificate
		// make sure the certificates in this overview are decoded
		if len(ov.MemberStateCertificateRecordArray.Records) > 0 {
			msCert := ov.MemberStateCertificateRecordArray.Records[0]
			if msCert.DecodedCertificate == nil {
				msCert2 := CertificateSecondGen(msCert)
				msCert2.Decode()
				if msCert2.DecodedCertificate != nil {
					PKsSecondGen[msCert2.DecodedCertificate.CertificateBody.CertificateHolderReference] = *msCert2.DecodedCertificate
				}
			}
		}
		if len(ov.VuCertificateRecordArray.Records) > 0 {
			vuCert := ov.VuCertificateRecordArray.Records[0]
			if vuCert.DecodedCertificate == nil {
				vuCert2 := CertificateSecondGen(vuCert)
				vuCert2.Decode()
				if vuCert2.DecodedCertificate != nil {
					PKsSecondGen[vuCert2.DecodedCertificate.CertificateBody.CertificateHolderReference] = *vuCert2.DecodedCertificate
				}
			}
		}
	*/
	// signed data is the vu overview record without the certificates and the signature itself
	// the 5 bytes are record type (1 byte) + record size (2 bytes uint16) + no of records (2 bytes uint16)
	skipBegin := int(ov.MemberStateCertificateRecordArray.NoOfRecords)*int(ov.MemberStateCertificateRecordArray.RecordSize) + int(ov.VuCertificateRecordArray.NoOfRecords)*int(ov.VuCertificateRecordArray.RecordSize) + 5 + 5
	skipEnd := int(ov.SignatureRecordArray.NoOfRecords)*int(ov.SignatureRecordArray.RecordSize) + 5
	if len(data) <= skipBegin+skipEnd {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), skipBegin+skipEnd)
	}
	signData := data[skipBegin : len(data)-skipEnd]
	err := cert.Decode()
	if err != nil {
		return false, err
	}
	return signature.Verify(cert, signData)
}

// afaik no structural change except for VehicleRegistrationIdentificationRecordArray -> VehicleRegistrationNumberRecordArray
type VuOverviewSecondGenV2 struct {
	Verified                                     bool                                         `aper:"-" json:"verified"`
	MemberStateCertificateRecordArray            MemberStateCertificateRecordArray            `json:"member_state_certificate_record_array"`
	VuCertificateRecordArray                     VuCertificateRecordArray                     `json:"vu_certificate_record_array"`
	VehicleIdentificationNumberRecordArray       VehicleIdentificationNumberRecordArray       `json:"vehicle_identification_number_record_array"`
	VehicleRegistrationIdentificationRecordArray VehicleRegistrationIdentificationRecordArray `json:"vehicle_registration_identification_record_array"`
	CurrentDateTimeRecordArray                   CurrentDateTimeRecordArray                   `json:"current_date_time_record_array"`
	VuDownloadablePeriodRecordArray              VuDownloadablePeriodRecordArray              `json:"vu_downloadable_period_record_array"`
	CardSlotsStatusRecordArray                   CardSlotsStatusRecordArray                   `json:"card_slots_status_record_array"`
	VuDownloadActivityDataRecordArray            VuDownloadActivityDataRecordArray            `json:"vu_download_activity_data_record_array"`
	VuCompanyLocksRecordArray                    VuCompanyLocksRecordArray                    `json:"vu_company_locks_record_array"`
	VuControlActivityRecordArray                 VuControlActivityRecordArray                 `json:"vu_control_activity_record_array"`
	SignatureRecordArray                         SignatureRecordArray                         `json:"signature_record_array"`
}

func (ov VuOverviewSecondGenV2) VerifySecondGen(cert CertificateSecondGen, data []byte) (bool, error) {
	if len(ov.SignatureRecordArray.Records) == 0 {
		return false, fmt.Errorf("no signature")
	}
	signature := ov.SignatureRecordArray.Records[0]
	/*
		// we could keep the overview verification self-contained, as the cert argument is actually the VuCertificate
		// make sure the certificates in this overview are decoded
		if len(ov.MemberStateCertificateRecordArray.Records) > 0 {
			msCert := ov.MemberStateCertificateRecordArray.Records[0]
			if msCert.DecodedCertificate == nil {
				msCert2 := CertificateSecondGen(msCert)
				msCert2.Decode()
				if msCert2.DecodedCertificate != nil {
					PKsSecondGen[msCert2.DecodedCertificate.CertificateBody.CertificateHolderReference] = *msCert2.DecodedCertificate
				}
			}
		}
		if len(ov.VuCertificateRecordArray.Records) > 0 {
			vuCert := ov.VuCertificateRecordArray.Records[0]
			if vuCert.DecodedCertificate == nil {
				vuCert2 := CertificateSecondGen(vuCert)
				vuCert2.Decode()
				if vuCert2.DecodedCertificate != nil {
					PKsSecondGen[vuCert2.DecodedCertificate.CertificateBody.CertificateHolderReference] = *vuCert2.DecodedCertificate
				}
			}
		}
	*/
	// signed data is the vu overview record without the certificates and the signature itself
	// the 5 bytes are record type (1 byte) + record size (2 bytes uint16) + no of records (2 bytes uint16)
	skipBegin := int(ov.MemberStateCertificateRecordArray.NoOfRecords)*int(ov.MemberStateCertificateRecordArray.RecordSize) + int(ov.VuCertificateRecordArray.NoOfRecords)*int(ov.VuCertificateRecordArray.RecordSize) + 5 + 5
	skipEnd := int(ov.SignatureRecordArray.NoOfRecords)*int(ov.SignatureRecordArray.RecordSize) + 5
	if len(data) <= skipBegin+skipEnd {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), skipBegin+skipEnd)
	}
	signData := data[skipBegin : len(data)-skipEnd]
	err := cert.Decode()
	if err != nil {
		return false, err
	}
	return signature.Verify(cert, signData)
}

type VuActivitiesFirstGen struct {
	Verified                   bool                               `aper:"-" json:"verified"`
	TimeReal                   TimeReal                           `json:"time_real"`
	OdometerValueMidnight      OdometerValueMidnight              `json:"odometer_value_midnight"`
	VuCardIWData               VuCardIWData                       `json:"vu_card_iw_data"`
	VuActivityDailyData        VuActivityDailyDataFirstGen        `json:"vu_activity_daily_data"`
	VuPlaceDailyWorkPeriodData VuPlaceDailyWorkPeriodDataFirstGen `json:"vu_place_daily_work_period_data"`
	VuSpecificConditionData    VuSpecificConditionDataFirstGen    `json:"vu_specific_condition_data"`
	Signature                  SignatureFirstGen                  `json:"signature"`
}

func (a VuActivitiesFirstGen) VerifyFirstGen(cert CertificateFirstGen, data []byte) (bool, error) {
	if len(data) <= 128 {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), 128)
	}
	start := 0
	end := len(data) - 128 // 128 bytes signature
	signData := data[start:end]
	signature := a.Signature
	return signature.Verify(cert, signData)
}

type VuActivitiesSecondGen struct {
	Verified                          bool                              `aper:"-" json:"verified"`
	DateOfDayDownloadedRecordArray    DateOfDayDownloadedRecordArray    `json:"date_of_day_downloaded_record_array"`
	OdometerValueMidnightRecordArray  OdometerValueMidnightRecordArray  `json:"odometer_value_midnight_record_array"`
	VuCardIWRecordArray               VuCardIWRecordArray               `json:"vu_card_iw_record_array"`
	VuActivityDailyRecordArray        VuActivityDailyRecordArray        `json:"vu_activity_daily_record_array"`
	VuPlaceDailyWorkPeriodRecordArray VuPlaceDailyWorkPeriodRecordArray `json:"vu_place_daily_work_period_record_array"`
	VuGNSSADRecordArray               VuGNSSADRecordArray               `json:"vu_gnss_ad_record_array"`
	VuSpecificConditionRecordArray    VuSpecificConditionRecordArray    `json:"vu_specific_condition_record_array"`
	SignatureRecordArray              SignatureRecordArray              `json:"signature_record_array"`
}

func (a VuActivitiesSecondGen) VerifySecondGen(cert CertificateSecondGen, data []byte) (bool, error) {
	if len(a.SignatureRecordArray.Records) == 0 {
		return false, fmt.Errorf("no signature")
	}
	signature := a.SignatureRecordArray.Records[0]
	// signed data is the vu activity record without the c signature itself
	// the 5 bytes are record type (1 byte) + record size (2 bytes uint16) + no of records (2 bytes uint16)
	skipEnd := int(a.SignatureRecordArray.NoOfRecords)*int(a.SignatureRecordArray.RecordSize) + 5
	if len(data) <= skipEnd {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), skipEnd)
	}
	signData := data[0 : len(data)-skipEnd]
	return signature.Verify(cert, signData)
}

type VuActivitiesSecondGenV2 struct {
	Verified                          bool                                `aper:"-" json:"verified"`
	DateOfDayDownloadedRecordArray    DateOfDayDownloadedRecordArray      `json:"date_of_day_downloaded_record_array"`
	OdometerValueMidnightRecordArray  OdometerValueMidnightRecordArray    `json:"odometer_value_midnight_record_array"`
	VuCardIWRecordArray               VuCardIWRecordArray                 `json:"vu_card_iw_record_array"`
	VuActivityDailyRecordArray        VuActivityDailyRecordArray          `json:"vu_activity_daily_record_array"`
	VuPlaceDailyWorkPeriodRecordArray VuPlaceDailyWorkPeriodRecordArrayV2 `json:"vu_place_daily_work_period_record_array"`
	VuGNSSADRecordArray               VuGNSSADRecordArrayV2               `json:"vu_gnss_ad_record_array"`
	VuSpecificConditionRecordArray    VuSpecificConditionRecordArray      `json:"vu_specific_condition_record_array"`
	VuBorderCrossingRecordArray       VuBorderCrossingRecordArray         `json:"vu_border_crossing_record_array"`
	VuLoadUnloadRecordArray           VuLoadUnloadRecordArray             `json:"vu_load_unload_record_array"`
	SignatureRecordArray              SignatureRecordArray                `json:"signature_record_array"`
}

func (a VuActivitiesSecondGenV2) VerifySecondGen(cert CertificateSecondGen, data []byte) (bool, error) {
	if len(a.SignatureRecordArray.Records) == 0 {
		return false, fmt.Errorf("no signature")
	}
	signature := a.SignatureRecordArray.Records[0]
	// signed data is the vu activity record without the c signature itself
	// the 5 bytes are record type (1 byte) + record size (2 bytes uint16) + no of records (2 bytes uint16)
	skipEnd := int(a.SignatureRecordArray.NoOfRecords)*int(a.SignatureRecordArray.RecordSize) + 5
	if len(data) <= skipEnd {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), skipEnd)
	}
	signData := data[0 : len(data)-skipEnd]
	return signature.Verify(cert, signData)
}

type VuEventsAndFaultsFirstGen struct {
	Verified                  bool                      `aper:"-" json:"verified"`
	VuFaultData               VuFaultData               `json:"vu_fault_data"`
	VuEventData               VuEventData               `json:"vu_event_data"`
	VuOverSpeedingControlData VuOverSpeedingControlData `json:"vu_over_speeding_control_data"`
	VuOverSpeedingEventData   VuOverSpeedingEventData   `json:"vu_over_speeding_event_data"`
	VuTimeAdjustmentData      VuTimeAdjustmentData      `json:"vu_time_adjustment_data"`
	Signature                 SignatureFirstGen         `json:"signature"`
}

func (ef VuEventsAndFaultsFirstGen) VerifyFirstGen(cert CertificateFirstGen, data []byte) (bool, error) {
	if len(data) <= 128 {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), 128)
	}
	start := 0
	end := len(data) - 128 // 128 bytes signature
	signData := data[start:end]
	signature := ef.Signature
	return signature.Verify(cert, signData)
}

type VuEventsAndFaultsSecondGen struct {
	Verified                             bool                                 `aper:"-" json:"verified"`
	VuFaultRecordArray                   VuFaultRecordArray                   `json:"vu_fault_record_array"`
	VuEventRecordArray                   VuEventRecordArray                   `json:"vu_event_record_array"`
	VuOverSpeedingControlDataRecordArray VuOverSpeedingControlDataRecordArray `json:"vu_over_speeding_control_data_record_array"`
	VuOverSpeedingEventRecordArray       VuOverSpeedingEventRecordArray       `json:"vu_over_speeding_event_record_array"`
	VuTimeAdjustmentRecordArray          VuTimeAdjustmentRecordArray          `json:"vu_time_adjustment_record_array"`
	// VuTimeAdjustmentGNSSRecordArray      VuTimeAdjustmentGNSSRecordArray // change according to docs
	SignatureRecordArray SignatureRecordArray `json:"signature_record_array"`
}

func (ef VuEventsAndFaultsSecondGen) VerifySecondGen(cert CertificateSecondGen, data []byte) (bool, error) {
	if len(ef.SignatureRecordArray.Records) == 0 {
		return false, fmt.Errorf("no signature")
	}
	signature := ef.SignatureRecordArray.Records[0]
	// signed data is the vu activity record without the c signature itself
	// the 5 bytes are record type (1 byte) + record size (2 bytes uint16) + no of records (2 bytes uint16)
	skipEnd := int(ef.SignatureRecordArray.NoOfRecords)*int(ef.SignatureRecordArray.RecordSize) + 5
	if len(data) <= skipEnd {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), skipEnd)
	}
	signData := data[0 : len(data)-skipEnd]
	return signature.Verify(cert, signData)
}

// afaik there is no actual difference in the structure, only the EventFaultType has been extended in V2
type VuEventsAndFaultsSecondGenV2 struct {
	Verified                             bool                                 `aper:"-" json:"verified"`
	VuFaultRecordArray                   VuFaultRecordArray                   `json:"vu_fault_record_array"`
	VuEventRecordArray                   VuEventRecordArray                   `json:"vu_event_record_array"`
	VuOverSpeedingControlDataRecordArray VuOverSpeedingControlDataRecordArray `json:"vu_over_speeding_control_data_record_array"`
	VuOverSpeedingEventRecordArray       VuOverSpeedingEventRecordArray       `json:"vu_over_speeding_event_record_array"`
	VuTimeAdjustmentRecordArray          VuTimeAdjustmentRecordArray          `json:"vu_time_adjustment_record_array"`
	SignatureRecordArray                 SignatureRecordArray                 `json:"signature_record_array"`
}

func (ef VuEventsAndFaultsSecondGenV2) VerifySecondGen(cert CertificateSecondGen, data []byte) (bool, error) {
	if len(ef.SignatureRecordArray.Records) == 0 {
		return false, fmt.Errorf("no signature")
	}
	signature := ef.SignatureRecordArray.Records[0]
	// signed data is the vu activity record without the c signature itself
	// the 5 bytes are record type (1 byte) + record size (2 bytes uint16) + no of records (2 bytes uint16)
	skipEnd := int(ef.SignatureRecordArray.NoOfRecords)*int(ef.SignatureRecordArray.RecordSize) + 5
	if len(data) <= skipEnd {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), skipEnd)
	}
	signData := data[0 : len(data)-skipEnd]
	return signature.Verify(cert, signData)
}

type VuDetailedSpeedFirstGen struct {
	Verified            bool                `aper:"-" json:"verified"`
	VuDetailedSpeedData VuDetailedSpeedData `json:"vu_detailed_speed_data"`
	Signature           SignatureFirstGen   `json:"signature"`
}

func (s VuDetailedSpeedFirstGen) VerifyFirstGen(cert CertificateFirstGen, data []byte) (bool, error) {
	if len(data) <= 128 {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), 128)
	}
	start := 0
	end := len(data) - 128 // 128 bytes signature
	signData := data[start:end]
	signature := s.Signature
	return signature.Verify(cert, signData)
}

type VuDetailedSpeedSecondGen struct {
	Verified                        bool                            `aper:"-" json:"verified"`
	VuDetailedSpeedBlockRecordArray VuDetailedSpeedBlockRecordArray `json:"vu_detailed_speed_block_record_array"`
	SignatureRecordArray            SignatureRecordArray            `json:"signature_record_array"`
}

func (s VuDetailedSpeedSecondGen) VerifySecondGen(cert CertificateSecondGen, data []byte) (bool, error) {
	if len(s.SignatureRecordArray.Records) == 0 {
		return false, fmt.Errorf("no signature")
	}
	signature := s.SignatureRecordArray.Records[0]
	// signed data is the vu activity record without the c signature itself
	// the 5 bytes are record type (1 byte) + record size (2 bytes uint16) + no of records (2 bytes uint16)
	skipEnd := int(s.SignatureRecordArray.NoOfRecords)*int(s.SignatureRecordArray.RecordSize) + 5
	if len(data) <= skipEnd {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), skipEnd)
	}
	signData := data[0 : len(data)-skipEnd]
	return signature.Verify(cert, signData)
}

type VuTechnicalDataFirstGen struct {
	Verified          bool                     `aper:"-" json:"verified"`
	VuIdentification  VuIdentificationFirstGen `json:"vu_identification"`
	SensorPaired      SensorPaired             `json:"sensor_paired"`
	VuCalibrationData VuCalibrationData        `json:"vu_calibration_data"`
	Signature         SignatureFirstGen        `json:"signature"`
}

func (t VuTechnicalDataFirstGen) VerifyFirstGen(cert CertificateFirstGen, data []byte) (bool, error) {
	if len(data) <= 128 {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), 128)
	}
	start := 0
	end := len(data) - 128 // 128 bytes signature
	signData := data[start:end]
	signature := t.Signature
	return signature.Verify(cert, signData)
}

type VuTechnicalDataSecondGen struct {
	Verified                               bool                                   `aper:"-" json:"verified"`
	VuIdentificationRecordArray            VuIdentificationRecordArray            `json:"vu_identification_record_array"`
	VuSensorPairedRecordArray              VuSensorPairedRecordArray              `json:"vu_sensor_paired_record_array"`
	VuSensorExternalGNSSCoupledRecordArray VuSensorExternalGNSSCoupledRecordArray `json:"vu_sensor_external_gnss_coupled_record_array"`
	VuCalibrationRecordArray               VuCalibrationRecordArray               `json:"vu_calibration_record_array"`
	VuCardRecordArray                      VuCardRecordArray                      `json:"vu_card_record_array"`
	VuITSConsentRecordArray                VuITSConsentRecordArray                `json:"vu_its_consent_record_array"`
	VuPowerSupplyInterruptionRecordArray   VuPowerSupplyInterruptionRecordArray   `json:"vu_power_supply_interruption_record_array"`
	SignatureRecordArray                   SignatureRecordArray                   `json:"signature_record_array"`
}

func (t VuTechnicalDataSecondGen) VerifySecondGen(cert CertificateSecondGen, data []byte) (bool, error) {
	if len(t.SignatureRecordArray.Records) == 0 {
		return false, fmt.Errorf("no signature")
	}
	signature := t.SignatureRecordArray.Records[0]
	// signed data is the vu activity record without the c signature itself
	// the 5 bytes are record type (1 byte) + record size (2 bytes uint16) + no of records (2 bytes uint16)
	skipEnd := int(t.SignatureRecordArray.NoOfRecords)*int(t.SignatureRecordArray.RecordSize) + 5
	if len(data) <= skipEnd {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), skipEnd)
	}
	signData := data[0 : len(data)-skipEnd]
	return signature.Verify(cert, signData)
}

type VuTechnicalDataSecondGenV2 struct {
	Verified                               bool                                   `aper:"-" json:"verified"`
	VuIdentificationRecordArray            VuIdentificationRecordArrayV2          `json:"vu_identification_record_array"`
	VuSensorPairedRecordArray              VuSensorPairedRecordArray              `json:"vu_sensor_paired_record_array"`
	VuSensorExternalGNSSCoupledRecordArray VuSensorExternalGNSSCoupledRecordArray `json:"vu_sensor_external_gnss_coupled_record_array"`
	VuCalibrationRecordArray               VuCalibrationRecordArrayV2             `json:"vu_calibration_record_array"`
	VuCardRecordArray                      VuCardRecordArray                      `json:"vu_card_record_array"`
	VuITSConsentRecordArray                VuITSConsentRecordArray                `json:"vu_its_consent_record_array"`
	VuPowerSupplyInterruptionRecordArray   VuPowerSupplyInterruptionRecordArray   `json:"vu_power_supply_interruption_record_array"`
	SignatureRecordArray                   SignatureRecordArray                   `json:"signature_record_array"`
}

func (t VuTechnicalDataSecondGenV2) VerifySecondGen(cert CertificateSecondGen, data []byte) (bool, error) {
	if len(t.SignatureRecordArray.Records) == 0 {
		return false, fmt.Errorf("no signature")
	}
	signature := t.SignatureRecordArray.Records[0]
	// signed data is the vu activity record without the c signature itself
	// the 5 bytes are record type (1 byte) + record size (2 bytes uint16) + no of records (2 bytes uint16)
	skipEnd := int(t.SignatureRecordArray.NoOfRecords)*int(t.SignatureRecordArray.RecordSize) + 5
	if len(data) <= skipEnd {
		return false, fmt.Errorf("error: data too short: %d (expected > %d)", len(data), skipEnd)
	}
	signData := data[0 : len(data)-skipEnd]
	return signature.Verify(cert, signData)
}

/*
2nd generation record type values
*/

const (
	RecordTypeActivityChangeInfo                = 0x01
	RecordTypeCardSlotsStatus                   = 0x02
	RecordTypeCurrentDateTime                   = 0x03
	RecordTypeMemberStateCertificate            = 0x04
	RecordTypeOdometerValueMidnight             = 0x05
	RecordTypeDateOfDayDownloaded               = 0x06
	RecordTypeSensorPaired                      = 0x07
	RecordTypeSignature                         = 0x08
	RecordTypeSpecificConditionRecord           = 0x09
	RecordTypeVehicleIdentificationNumber       = 0x0a
	RecordTypeVehicleRegistrationNumber         = 0x0b
	RecordTypeVuCalibrationRecord               = 0x0c
	RecordTypeVuCardIWRecord                    = 0x0d
	RecordTypeVuCardRecord                      = 0x0e
	RecordTypeVuCertificate                     = 0x0f
	RecordTypeVuCompanyLocksRecord              = 0x10
	RecordTypeVuControlActivityRecord           = 0x11
	RecordTypeVuDetailedSpeedBlock              = 0x12
	RecordTypeVuDownloadablePeriod              = 0x13
	RecordTypeVuDownloadActivityData            = 0x14
	RecordTypeVuEventRecord                     = 0x15
	RecordTypeVuGNSSADRecord                    = 0x16
	RecordTypeVuITSConsentRecord                = 0x17
	RecordTypeVuFaultRecord                     = 0x18
	RecordTypeVuIdentification                  = 0x19
	RecordTypeVuOverSpeedingControlData         = 0x1a
	RecordTypeVuOverSpeedingEventRecord         = 0x1b
	RecordTypeVuPlaceDailyWorkPeriodRecord      = 0x1c
	RecordTypeVuTimeAdjustmentGNSSRecord        = 0x1d
	RecordTypeVuTimeAdjustmentRecord            = 0x1e
	RecordTypeVuPowerSupplyInterruptionRecord   = 0x1f
	RecordTypeSensorPairedRecord                = 0x20
	RecordTypeSensorExternalGNSSCoupledRecord   = 0x21
	RecordTypeVuBorderCrossingRecord            = 0x22
	RecordTypeVuLoadUnloadRecord                = 0x23
	RecordTypeVehicleRegistrationIdentification = 0x24
	// 0x25 -- 0x7f: reserved for future use
	// 0x80 -- 0xff: manufacturer specific
)

/*
All lower-level definitions
extracted from Appendix 1 (and Appendix 7 4.2)
Where needed, a json marshal / unmarshal function is provided
*/

// helper structure derived from Appendix 7 4.2
type CardIdentificationAndDriverCardHolderIdentification struct {
	Verified                       bool                           `aper:"-" json:"verified"`
	CardIdentification             CardIdentification             `json:"card_identification"`
	DriverCardHolderIdentification DriverCardHolderIdentification `json:"driver_card_holder_identification"`
}

// there is absolutely no information of how this looks like in the specs, so it is just a bunch of bytes
// the length is fixed according to the specs to 3072 bytes, which is the contents of the VuConfigurationLengthRange field
type VuConfiguration struct {
	Verified      bool   `aper:"-" json:"verified"`
	Configuration []byte `aper:"size=VuConfigurationLengthRange" json:"configuration"`
}

// Appendix 1 2.1
type ActivityChangeInfo [2]byte

type DecodedActivityChangeInfo struct {
	Driver      bool `json:"driver"`
	Team        bool `json:"team"`
	CardPresent bool `json:"card_present"`
	WorkType    byte `json:"work_type"` // 0 - break, 1 - on duty, 2 - work, 3 - drive
	Minutes     int  `json:"minutes"`
}

func (a ActivityChangeInfo) Decode() DecodedActivityChangeInfo {
	// this is a bit field
	// scpaattttttttttt
	// s - 0: driver, 1: codriver
	// c - 0: one man, 1: team
	// p - 0: data inserted, 1: no data
	// aa - 00: break, 01: on duty, 10: work, 11: drive
	// ttttttttttt - minutes since 0:00 that day
	var v uint16
	b := bytes.NewBuffer([]byte{a[0], a[1]})
	binary.Read(b, binary.BigEndian, &v)
	driver := (v & 0x8000) > 0
	team := (v & 0x4000) > 0
	cardPresent := (v & 0x2000) > 0
	workType := byte((v & 0x1800) >> 11) // 00011000 00000000
	minutes := int(v & 0x07FF)
	s := DecodedActivityChangeInfo{
		Driver:      driver,
		Team:        team,
		CardPresent: cardPresent,
		WorkType:    workType,
		Minutes:     minutes,
	}
	return s
}

func (a ActivityChangeInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.Decode())
}

// Appendix 1 2.2
type Address struct {
	CodePage byte
	Address  [35]byte
}

func (a Address) String() string {
	s, _ := decodeWithCodePage(a.CodePage, a.Address[:])
	return s
}

func (a Address) MarshalJSON() ([]byte, error) {
	s, err := decodeWithCodePage(a.CodePage, a.Address[:])
	if err != nil {
		return json.Marshal(nil)
	}
	return json.Marshal(s)
}

// Appendix 1 2.7
type BCDString []byte

func (bcd BCDString) Decode() (int, error) {
	if len(bcd) == 0 {
		return 0, nil
	}
	s := hex.EncodeToString(bcd)
	if s[len(s)-1] == 'f' {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return int(n), err
}

func (bcd BCDString) MarshalJSON() ([]byte, error) {
	v, err := bcd.Decode()
	if err != nil {
		log.Printf("warn: could not marshal bcd: %v", err)
		return json.Marshal(nil)
	}
	return json.Marshal(v)
}

// Appendix 1 2.8
type CalibrationPurpose byte

// Appendix 1 2.9
type CardActivityDailyRecord struct {
	ActivityPreviousRecordLength CardActivityLengthRange `json:"activity_previous_record_length"`
	ActivityRecordLength         CardActivityLengthRange `aper:"structuresize" json:"activity_record_length"`
	ActivityRecordDate           TimeReal                `json:"activity_record_date"`
	ActivityDailyPresenceCounter DailyPresenceCounter    `aper:"size=2" json:"activity_daily_presence_counter"`
	ActivityDayDistance          Distance                `json:"activity_day_distance"`
	ActivityChangeInfo           []ActivityChangeInfo    `aper:"size=1..1440" json:"activity_change_info"`
}

// Appendix 1 2.10
type CardActivityLengthRange uint16

// Appendix 1 2.11
type CardApprovalNumber [8]byte

func (n CardApprovalNumber) String() string {
	return bytesToString(n[:])
}

func (n CardApprovalNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(n[:]))
}

// Appendix 1 2.11a
type CardBorderCrossings struct {
	Verified                          bool                       `aper:"-" json:"verified"`
	BorderCrossingPointerNewestRecord NoOfBorderCrossingRecords  `json:"border_crossing_pointer_newest_record"`
	CardBorderCrossingRecords         []CardBorderCrossingRecord `aper:"size=NoOfBorderCrossingRecords" json:"card_border_crossing_records"`
}

// Appendix 1 2.11b
type CardBorderCrossingRecord struct {
	Verified             bool                `aper:"-" json:"verified"`
	CountryLeft          NationNumeric       `json:"country_left"`
	CountryEntered       NationNumeric       `json:"country_entered"`
	GNNSPlaceAuthRecord  GNSSPlaceAuthRecord `json:"gnss_place_auth_record"`
	VehicleOdometerValue OdometerShort       `json:"vehicle_odometer_value"`
}

// Appendix 1 2.13
type CardChipIdentification struct { // tag: 00 05 type: 00 (or 02, those are supposed to be identical)
	Verified                 bool    `aper:"-" json:"verified"`
	IcSerialNumber           [4]byte `json:"ic_serial_number"`           // tag with fixed len optional
	IcManufacturingReference [4]byte `json:"ic_manufacturing_reference"` // tag with fixed len optional
}

// Appendix 1 2.15
type CardControlActivityDataRecord struct {
	Verified                   bool                              `aper:"-" json:"verified"`
	ControlType                ControlType                       `json:"control_type"`
	ControlTime                TimeReal                          `json:"control_time"`
	ControlCardNumber          FullCardNumber                    `json:"control_card_number"`
	ControlVehicleRegistration VehicleRegistrationIdentification `json:"control_vehicle_registration"`
	ControlDownloadPeriodBegin TimeReal                          `json:"control_download_period_begin"`
	ControlDownloadPeriodEnd   TimeReal                          `json:"control_download_period_end"`
}

// Appendix 1 2.16
type CardCurrentUse struct {
	Verified           bool                              `aper:"-" json:"verified"`
	SessionOpenTime    TimeReal                          `json:"session_open_time"`
	SessionOpenVehicle VehicleRegistrationIdentification `json:"session_open_vehicle"`
}

// Appendix 1 2.17
type CardDriverActivityFirstGen struct {
	Verified                       bool                    `aper:"-" json:"verified"`
	ActivityPointerOldestDayRecord CardActivityLengthRange `json:"activity_pointer_oldest_day_record"`
	ActivityPointerNewestRecord    CardActivityLengthRange `json:"activity_pointer_newest_record"`
	ActivityDailyRecords           []byte                  `aper:"size=1..ActivityStructureLengthFirstGen" json:"activity_daily_records"` // actually, it is []CardActivityDailyRecord, but not aligned and cyclic (wrapping around at the end). The actual size is given by the outer structure (or by ActivityStructureLength, a global value)
}

func (a CardDriverActivityFirstGen) Decode() []CardActivityDailyRecord {
	// log.Println("in CardDriverActivityFirstGen.Decode")
	var records []CardActivityDailyRecord
	// oldestPos := int(a.ActivityPointerOldestDayRecord)
	currPos := int(a.ActivityPointerNewestRecord)
	if len(a.ActivityDailyRecords) < 4 {
		log.Printf("error: activity daily records length %v < 4", len(a.ActivityDailyRecords))
		return nil
	}
	var currLength uint16
	var prevLength uint16
	currDailyPresenceCounter := -1
	wrapped := false
	for counter := 0; counter < 240*28; counter++ {
		// log.Printf("current pos (going backwards): %v", currPos)
		if len(a.ActivityDailyRecords) <= currPos {
			log.Printf("error: activity daily records length %v <= newest pointer %v", len(a.ActivityDailyRecords), currPos)
			return nil
		}
		currPosTo := currPos + 4
		if currPosTo > len(a.ActivityDailyRecords) {
			currPosTo = len(a.ActivityDailyRecords)
		}
		currRecordBytes := a.ActivityDailyRecords[currPos:currPosTo]
		// currPos is in bytes. First we make sure to have the first 4 bytes
		if missing := 4 - len(currRecordBytes); missing > 0 {
			// log.Printf("wrap around 4 first bytes: %v", missing)
			currRecordBytes = append(currRecordBytes, a.ActivityDailyRecords[0:missing]...)
		}

		currLengthBytes := currRecordBytes[2:4]
		bCurrLength := bytes.NewBuffer([]byte{currLengthBytes[0], currLengthBytes[1]})
		binary.Read(bCurrLength, binary.BigEndian, &currLength)
		if prevLength > 0 && currLength != prevLength {
			log.Printf("warn: corrupted data, current length %v != previous %v - setting currLength, but further decoding will likely fail", currLength, prevLength)
			currLength = prevLength
		}

		prevLengthBytes := currRecordBytes[0:2]
		bPrevLength := bytes.NewBuffer([]byte{prevLengthBytes[0], prevLengthBytes[1]})
		binary.Read(bPrevLength, binary.BigEndian, &prevLength)

		if int(prevLength) >= len(a.ActivityDailyRecords) {
			log.Printf("warn: data corrupted, stop parsing")
			break
		}

		currPosTo = currPos + int(currLength)
		if currPosTo > len(a.ActivityDailyRecords) {
			currPosTo = len(a.ActivityDailyRecords)
		}
		currBytes := a.ActivityDailyRecords[currPos:currPosTo]
		if missing := int(currLength) - len(currBytes); missing > 0 {
			if len(a.ActivityDailyRecords) < missing {
				log.Printf("error: activity daily records length %v <= missing %v", len(a.ActivityDailyRecords), missing)
				return nil
			}
			currBytes = append(currBytes, a.ActivityDailyRecords[0:missing]...)
		}

		newRecord := &CardActivityDailyRecord{}
		field := reflect.ValueOf(newRecord)
		fieldType := reflect.TypeOf(newRecord)
		sizes := make(map[string]int)
		globalSizes := make(map[string]int)
		_, _, _, err := parseASN1Field(field, fieldType, 1, 0, 0, int(currLength), 0, currBytes, sizes, globalSizes)
		if err != nil {
			log.Printf("error: activity daily records parsing: %v", err)
			return nil
		}

		newDailyPresenceCounter, err := newRecord.ActivityDailyPresenceCounter.Decode()
		if err != nil {
			log.Printf("warn: could not decode daily presence counter, stop parsing: %v", err)
			break
		}

		if currDailyPresenceCounter >= 0 && currDailyPresenceCounter-1 != newDailyPresenceCounter {
			log.Printf("warn: new daily presence counter %v is not precessor of %v", newDailyPresenceCounter, currDailyPresenceCounter)
		}
		currDailyPresenceCounter = newDailyPresenceCounter

		records = append(records, *newRecord)
		currPos -= int(prevLength)
		if currPos < 0 {
			if wrapped {
				log.Printf("warn: trying to wrap around for the second time, stop parsing")
				break
			}
			wrapped = true
			currPos += len(a.ActivityDailyRecords)
			if currPos < 0 {
				log.Printf("warn: wrap around too large, stop parsing")
				break
			}
		}
		if prevLength == 0 {
			break
		}
	}
	return records
}

func (a CardDriverActivityFirstGen) DecodeForward() []CardActivityDailyRecord {
	// log.Println("in CardDriverActivityFirstGen.DecodeForward")
	var records []CardActivityDailyRecord
	currPos := int(a.ActivityPointerOldestDayRecord)
	lastPos := int(a.ActivityPointerNewestRecord)
	if len(a.ActivityDailyRecords) < 4 {
		log.Printf("error: activity daily records length %v < 4", len(a.ActivityDailyRecords))
		return nil
	}
	// log.Printf("len raw activity daily records: %v", len(a.ActivityDailyRecords))
	last := false
	for counter := 0; !last && counter < 240*28; counter++ { // make sure it eventually stops
		// log.Printf("current pos (going forward): %v", currPos)
		if len(a.ActivityDailyRecords) <= currPos {
			log.Printf("error: activity daily records length %v <= newest pointer %v", len(a.ActivityDailyRecords), currPos)
			return nil
		}
		currPosTo := currPos + 4
		if currPosTo > len(a.ActivityDailyRecords) {
			currPosTo = len(a.ActivityDailyRecords)
		}
		currRecordBytes := a.ActivityDailyRecords[currPos:currPosTo]
		// currPos is in bytes. First we make sure to have the first 4 bytes
		if missing := 4 - len(currRecordBytes); missing > 0 {
			// log.Printf("wrap around 4 first bytes: %v", missing)
			currRecordBytes = append(currRecordBytes, a.ActivityDailyRecords[0:missing]...)
		}
		prevLengthBytes := currRecordBytes[0:2]
		bPrevLength := bytes.NewBuffer([]byte{prevLengthBytes[0], prevLengthBytes[1]})
		var prevLength uint16
		binary.Read(bPrevLength, binary.BigEndian, &prevLength)
		currLengthBytes := currRecordBytes[2:4]
		bCurrLength := bytes.NewBuffer([]byte{currLengthBytes[0], currLengthBytes[1]})
		var currLength uint16
		binary.Read(bCurrLength, binary.BigEndian, &currLength)

		// log.Printf("current length 1st: %v", currLength)
		currPosTo = currPos + int(currLength)
		if currPosTo > len(a.ActivityDailyRecords) {
			// log.Printf("currPosTo %v > len, cutting to %v", currPosTo, len(a.ActivityDailyRecords))
			currPosTo = len(a.ActivityDailyRecords)
		}
		currBytes := a.ActivityDailyRecords[currPos:currPosTo]
		if missing := int(currLength) - len(currBytes); missing > 0 {
			// log.Printf("wrap around: %v", missing)
			if len(a.ActivityDailyRecords) < missing {
				log.Printf("error: activity daily records length %v <= missing %v", len(a.ActivityDailyRecords), missing)
				return nil
			}
			currBytes = append(currBytes, a.ActivityDailyRecords[0:missing]...)
		}

		newRecord := &CardActivityDailyRecord{}
		field := reflect.ValueOf(newRecord)
		fieldType := reflect.TypeOf(newRecord)
		sizes := make(map[string]int)
		globalSizes := make(map[string]int)
		_, _, _, err := parseASN1Field(field, fieldType, 1, 0, 0, int(currLength), 0, currBytes, sizes, globalSizes)
		if err != nil {
			log.Printf("error: activity daily records parsing: %v", err)
			return nil
		}

		records = append(records, *newRecord)
		currPos += int(currLength)
		for currPos > len(a.ActivityDailyRecords) {
			currPos -= len(a.ActivityDailyRecords)
		}
		if currPos == lastPos {
			last = true
		}
	}
	return records
}

func (a CardDriverActivityFirstGen) MarshalJSON() ([]byte, error) {
	// this is a bit complicated. ActivityDailyRecords is a cyclic buffer holding ActivityDailyRecord objects.
	type CardDriverActivityFirstGen2 CardDriverActivityFirstGen
	res := struct {
		CardDriverActivityFirstGen2
		DecodedActivityDailyRecords []CardActivityDailyRecord `json:"decoded_activity_daily_records"`
	}{
		CardDriverActivityFirstGen2: (CardDriverActivityFirstGen2)(a),
		DecodedActivityDailyRecords: a.Decode(),
	}
	return json.Marshal(res)
}

type CardDriverActivitySecondGen struct {
	Verified                       bool                    `aper:"-" json:"verified"`
	ActivityPointerOldestDayRecord CardActivityLengthRange `json:"activity_pointer_oldest_day_record"`
	ActivityPointerNewestRecord    CardActivityLengthRange `json:"activity_pointer_newest_record"`
	ActivityDailyRecords           []byte                  `aper:"size=1..ActivityStructureLengthSecondGen" json:"activity_daily_records"` // actually, it is []CardActivityDailyRecord, but not aligned and cyclic (wrapping around at the end). The actual size is given by the outer structure (or by ActivityStructureLength, a global value)
}

func (a CardDriverActivitySecondGen) Decode() []CardActivityDailyRecord {
	var records []CardActivityDailyRecord
	// oldestPos := int(a.ActivityPointerOldestDayRecord)
	currPos := int(a.ActivityPointerNewestRecord)
	if len(a.ActivityDailyRecords) < 4 {
		log.Printf("error: activity daily records length %v < 4", len(a.ActivityDailyRecords))
		return nil
	}
	var currLength uint16
	var prevLength uint16
	currDailyPresenceCounter := -1
	wrapped := false
	for counter := 0; counter < 240*28; counter++ { // make sure it eventually stops
		// log.Printf("current pos (going backwards): %v", currPos)
		if len(a.ActivityDailyRecords) <= currPos {
			log.Printf("error: activity daily records length %v <= newest pointer %v", len(a.ActivityDailyRecords), currPos)
			return nil
		}
		currPosTo := currPos + 4
		if currPosTo > len(a.ActivityDailyRecords) {
			currPosTo = len(a.ActivityDailyRecords)
		}
		currRecordBytes := a.ActivityDailyRecords[currPos:currPosTo]
		// currPos is in bytes. First we make sure to have the first 4 bytes
		if missing := 4 - len(currRecordBytes); missing > 0 {
			log.Printf("wrap around 4 first bytes: %v", missing)
			currRecordBytes = append(currRecordBytes, a.ActivityDailyRecords[0:missing]...)
		}
		currLengthBytes := currRecordBytes[2:4]
		bCurrLength := bytes.NewBuffer([]byte{currLengthBytes[0], currLengthBytes[1]})
		binary.Read(bCurrLength, binary.BigEndian, &currLength)

		if prevLength > 0 && currLength != prevLength {
			log.Printf("warn: corrupted data, current length %v != previous %v - setting currLength, but further decoding will likely fail", currLength, prevLength)
			currLength = prevLength
		}
		prevLengthBytes := currRecordBytes[0:2]
		bPrevLength := bytes.NewBuffer([]byte{prevLengthBytes[0], prevLengthBytes[1]})
		binary.Read(bPrevLength, binary.BigEndian, &prevLength)

		if int(prevLength) >= len(a.ActivityDailyRecords) {
			log.Printf("warn: data corrupted, stop parsing")
			break
		}

		currPosTo = currPos + int(currLength)
		if currPosTo > len(a.ActivityDailyRecords) {
			currPosTo = len(a.ActivityDailyRecords)
		}
		currBytes := a.ActivityDailyRecords[currPos:currPosTo]
		if missing := int(currLength) - len(currBytes); missing > 0 {
			if len(a.ActivityDailyRecords) < missing {
				log.Printf("error: activity daily records length %v <= missing %v", len(a.ActivityDailyRecords), missing)
				return nil
			}
			if wrapped {
				log.Printf("warn: trying to wrap around for the second time, stop parsing")
				break
			}
			wrapped = true
			currBytes = append(currBytes, a.ActivityDailyRecords[0:missing]...)
		}

		newRecord := &CardActivityDailyRecord{}
		field := reflect.ValueOf(newRecord)
		fieldType := reflect.TypeOf(newRecord)
		sizes := make(map[string]int)
		globalSizes := make(map[string]int)
		_, _, _, err := parseASN1Field(field, fieldType, 1, 0, 0, int(currLength), 0, currBytes, sizes, globalSizes)
		if err != nil {
			log.Printf("error: activity daily records 2ng gen parsing: %v", err)
			return nil
		}
		records = append(records, *newRecord)

		newDailyPresenceCounter, err := newRecord.ActivityDailyPresenceCounter.Decode()
		if err != nil {
			log.Printf("warn: could not decode daily presence counter: %v", err)
			break
		}

		if currDailyPresenceCounter >= 0 && currDailyPresenceCounter-1 != newDailyPresenceCounter {
			log.Printf("warn: new daily presence counter %v is not precessor of %v", newDailyPresenceCounter, currDailyPresenceCounter)
		}
		currDailyPresenceCounter = newDailyPresenceCounter

		currPos -= int(prevLength)
		if currPos < 0 {
			if wrapped {
				log.Printf("warn: trying to wrap around for the second time, stop parsing")
				break
			}
			wrapped = true
			currPos += len(a.ActivityDailyRecords)
			if currPos < 0 {
				log.Printf("warn: wrap around too large, stop parsing")
				break
			}
		}
		if prevLength == 0 {
			break
		}
	}
	return records
}

// theoretically, this also works. In practice, it seems this data may be corrupted and it is safer to start decoding from the end (method Decode()) backwards,
// since every record contains the current and the previous length
func (a CardDriverActivitySecondGen) DecodeForward() []CardActivityDailyRecord {
	var records []CardActivityDailyRecord
	currPos := int(a.ActivityPointerOldestDayRecord)
	lastPos := int(a.ActivityPointerNewestRecord)
	if len(a.ActivityDailyRecords) < 4 {
		log.Printf("error: activity daily records length %v < 4", len(a.ActivityDailyRecords))
		return nil
	}
	last := false
	for counter := 0; !last && counter < 240*28; counter++ {
		if len(a.ActivityDailyRecords) <= currPos {
			log.Printf("error: activity daily records length %v <= newest pointer %v", len(a.ActivityDailyRecords), currPos)
			return nil
		}
		currPosTo := currPos + 4
		if currPosTo > len(a.ActivityDailyRecords) {
			currPosTo = len(a.ActivityDailyRecords)
		}
		currRecordBytes := a.ActivityDailyRecords[currPos:currPosTo]
		// currPos is in bytes. First we make sure to have the first 4 bytes
		if missing := 4 - len(currRecordBytes); missing > 0 {
			currRecordBytes = append(currRecordBytes, a.ActivityDailyRecords[0:missing]...)
		}
		prevLengthBytes := currRecordBytes[0:2]
		bPrevLength := bytes.NewBuffer([]byte{prevLengthBytes[0], prevLengthBytes[1]})
		var prevLength uint16
		binary.Read(bPrevLength, binary.BigEndian, &prevLength)
		currLengthBytes := currRecordBytes[2:4]
		bCurrLength := bytes.NewBuffer([]byte{currLengthBytes[0], currLengthBytes[1]})
		var currLength uint16
		binary.Read(bCurrLength, binary.BigEndian, &currLength)

		// log.Printf("current length 1st: %v", currLength)
		currPosTo = currPos + int(currLength)
		if currPosTo > len(a.ActivityDailyRecords) {
			currPosTo = len(a.ActivityDailyRecords)
		}
		currBytes := a.ActivityDailyRecords[currPos:currPosTo]
		if missing := int(currLength) - len(currBytes); missing > 0 {
			if len(a.ActivityDailyRecords) < missing {
				log.Printf("error: activity daily records length %v <= missing %v", len(a.ActivityDailyRecords), missing)
				return nil
			}
			currBytes = append(currBytes, a.ActivityDailyRecords[0:missing]...)
		}

		newRecord := &CardActivityDailyRecord{}
		field := reflect.ValueOf(newRecord)
		fieldType := reflect.TypeOf(newRecord)
		sizes := make(map[string]int)
		globalSizes := make(map[string]int)
		_, _, _, err := parseASN1Field(field, fieldType, 1, 0, 0, int(currLength), 0, currBytes, sizes, globalSizes)
		if err != nil {
			log.Printf("error: activity daily records parsing: %v", err)
			return nil
		}

		records = append(records, *newRecord)
		currPos += int(currLength)
		for currPos > len(a.ActivityDailyRecords) {
			currPos -= len(a.ActivityDailyRecords)
		}
		if currPos == lastPos {
			last = true
		}
	}
	return records
}

func (a CardDriverActivitySecondGen) MarshalJSON() ([]byte, error) {
	// this is a bit complicated. ActivityDailyRecords is a cyclic buffer holding ActivityDailyRecord objects.
	type CardDriverActivitySecondGen2 CardDriverActivitySecondGen
	res := struct {
		CardDriverActivitySecondGen2
		DecodedActivityDailyRecords []CardActivityDailyRecord `json:"decoded_activity_daily_records"`
	}{
		CardDriverActivitySecondGen2: (CardDriverActivitySecondGen2)(a),
		DecodedActivityDailyRecords:  a.Decode(),
	}
	return json.Marshal(res)
}

// Appendix 1 2.18
type CardDrivingLicenceInformation struct {
	Verified                       bool                 `aper:"-" json:"verified"`
	DrivingLicenceIssuingAuthority Name                 `json:"driving_licence_issuing_authority"`
	DrivingLicenceIssuingNation    NationNumeric        `json:"driving_licence_issuing_nation"`
	DrivingLicenceNumber           DrivingLicenceNumber `json:"driving_licence_number"`
}
type DrivingLicenceNumber [16]byte // helper type to provide json marshal

func (n DrivingLicenceNumber) String() string {
	return bytesToString(n[:])
}

func (n DrivingLicenceNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(n[:]))
}

// Appendix 1 2.19
type CardEventDataFirstGen struct {
	Verified              bool `aper:"-" json:"verified"`
	CardEventRecordsArray [6]struct {
		CardEventRecords []CardEventRecord `aper:"size=NoOfEventsPerTypeFirstGen" json:"card_event_records"`
	} `json:"card_event_records_array"`
}

/*
type CardEventDataFirstGen [6]struct {
	CardEventRecords []CardEventRecord `aper:"size=NoOfEventsPerTypeFirstGen" json:"card_event_records"`
}
*/

type CardEventDataSecondGen struct { // different from original document, there is a correction
	Verified              bool `aper:"-" json:"verified"`
	CardEventRecordsArray [11]struct {
		CardEventRecords []CardEventRecord `aper:"size=NoOfEventsPerTypeSecondGen" json:"card_event_records"`
	} `json:"card_event_records_array"`
}

/*
type CardEventDataSecondGen [11]struct { // different from original document, there is a correction
	CardEventRecords []CardEventRecord `aper:"size=NoOfEventsPerTypeSecondGen" json:"card_event_records"`
}
*/

// Appendix 1 2.20
type CardEventRecord struct {
	EventType                byte                              `json:"event_type"`
	EventBeginTime           TimeReal                          `json:"event_begin_time"`
	EventEndTime             TimeReal                          `json:"event_end_time"`
	EventVehicleRegistration VehicleRegistrationIdentification `json:"event_vehicle_registration"`
}

// Appendix 1 2.21
type CardFaultDataFirstGen struct {
	Verified              bool `aper:"-" json:"verified"`
	CardFaultRecordsArray [2]struct {
		CardFaultRecords []CardFaultRecord `aper:"size=NoOfFaultsPerTypeFirstGen" json:"card_fault_records"`
	} `json:"card_fault_records_array"`
}

/*
type CardFaultDataFirstGen [2]struct {
	CardFaultRecords []CardFaultRecord `aper:"size=NoOfFaultsPerTypeFirstGen" json:"card_fault_records"`
}
*/

type CardFaultDataSecondGen struct {
	Verified              bool `aper:"-" json:"verified"`
	CardFaultRecordsArray [2]struct {
		CardFaultRecords []CardFaultRecord `aper:"size=NoOfFaultsPerTypeSecondGen" json:"card_fault_records"`
	} `json:"card_fault_records_array"`
}

/*
type CardFaultDataSecondGen [2]struct {
	CardFaultRecords []CardFaultRecord `aper:"size=NoOfFaultsPerTypeSecondGen" json:"card_fault_records"`
}
*/

// Appendix 1 2.22
type CardFaultRecord struct {
	FaultType                EventFaultType                    `json:"fault_type"`
	FaultBeginTime           TimeReal                          `json:"fault_begin_time"`
	FaultEndTime             TimeReal                          `json:"fault_end_time"`
	FaultVehicleRegistration VehicleRegistrationIdentification `json:"fault_vehicle_registration"`
}

// Appendix 1 2.23
type CardIccIdentificationFirstGen struct {
	Verified                 bool                         `aper:"-" json:"verified"`
	ClockStop                byte                         `json:"clock_stop"`
	CardExtendedSerialNumber ExtendedSerialNumberFirstGen `json:"card_extended_serial_number"`
	CardApprovalNumber       CardApprovalNumber           `json:"card_approval_number"`
	CardPersonaliserID       ManufacturerCode             `json:"card_personaliser_id"`
	EmbedderIcAssemblerId    EmbedderIcAssemblerId        `json:"embedder_ic_assembler_id"`
	IcIdentifier             [2]byte                      `json:"ic_identifier"`
}

// functionally identical to first gen, only the field "type" in the ExtendedSerialNumber struct is now of type "EquipmentType"
// (the underlying data is the same though, it is one byte)
type CardIccIdentificationSecondGen struct {
	Verified                 bool                          `aper:"-" json:"verified"`
	ClockStop                byte                          `json:"clock_stop"`
	CardExtendedSerialNumber ExtendedSerialNumberSecondGen `json:"card_extended_serial_number"`
	CardApprovalNumber       CardApprovalNumber            `json:"card_approval_number"`
	CardPersonaliserID       ManufacturerCode              `json:"card_personaliser_id"`
	EmbedderIcAssemblerId    EmbedderIcAssemblerId         `json:"embedder_ic_assembler_id"`
	IcIdentifier             [2]byte                       `json:"ic_identifier"`
}

// Appendix 1 2.24
type CardIdentification struct {
	CardIssuingMemberState   NationNumeric `json:"card_issuing_member_state"`
	CardNumber               CardNumber    `json:"card_number"`
	CardIssuingAuthorityName Name          `json:"card_issuing_authority_name"`
	CardIssueDate            TimeReal      `json:"card_issue_date"`
	CardValidityBegin        TimeReal      `json:"card_validity_begin"`
	CardExpiryDate           TimeReal      `json:"card_expiry_date"`
}

// Appendix 1 2.24a
type CardLoadTypeEntries struct {
	Verified                         bool                      `aper:"-" json:"verified"`
	LoadTypeEntryPointerNewestRecord NoOfLoadTypeEntryRecords  `json:"load_type_entry_pointer_newest_record"`
	CardLoadTypeEntryRecords         []CardLoadTypeEntryRecord `aper:"size=NoOfLoadTypeRecords" json:"card_load_type_entry_records"`
}

// Appendix 1 2.24b
type CardLoadTypeEntryRecord struct {
	Timestamp       TimeReal `json:"timestamp"`
	LoadTypeEntered LoadType `json:"load_type_entered"`
}

// Appendix 1 2.24c
type CardLoadUnloadOperations struct {
	Verified                      bool                   `aper:"-" json:"verified"`
	LoadUnloadPointerNewestRecord NoOfLoadUnloadRecords  `json:"load_unload_pointer_newest_record"`
	CardLoadUnloadRecords         []CardLoadUnloadRecord `aper:"size=NoOfLoadUnloadRecords" json:"card_load_unload_records"`
}

// Appendix 1 2.24d
type CardLoadUnloadRecord struct {
	Timestamp            TimeReal            `json:"timestamp"`
	OperationType        OperationType       `json:"operation_type"`
	GNSSPlaceAuthRecord  GNSSPlaceAuthRecord `json:"gnss_place_auth_record"`
	VehicleOdometerValue OdometerShort       `json:"vehicle_odometer_value"`
}

// Appendix 1 2.26
type CardNumber [16]byte // actually a choice of two 16 bytes structs which basically consist of the identification and 2 or 3 index numbers

func (n CardNumber) String() string {
	return bytesToString(n[:])
}

func (n CardNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.String())
}

// Appendix 1 2.26a
type CardPlaceAuthDailyWorkPeriod struct {
	Verified                     bool                          `aper:"-" json:"verified"`
	PlaceAuthPointerNewestRecord NoOfCardPlaceRecordsSecondGen `json:"place_auth_pointer_newest_record"`
	PlaceAuthStatusRecords       []PlaceAuthStatusRecord       `aper:"size=NoOfCardPlaceRecordsSecondGen" json:"place_auth_status_records"`
}

// Appendix 1 2.27
type CardPlaceDailyWorkPeriodFirstGen struct {
	Verified                 bool                         `aper:"-" json:"verified"`
	PlacePointerNewestRecord NoOfCardPlaceRecordsFirstGen `json:"place_pointer_newest_record"`
	PlaceRecords             []PlaceRecordFirstGen        `aper:"size=NoOfCardPlaceRecordsFirstGen" json:"place_records"`
}

type CardPlaceDailyWorkPeriodSecondGen struct {
	Verified                 bool                          `aper:"-" json:"verified"`
	PlacePointerNewestRecord NoOfCardPlaceRecordsSecondGen `json:"place_pointer_newest_record"`
	PlaceRecords             []PlaceRecordSecondGen        `aper:"size=NoOfCardPlaceRecordsSecondGen" json:"place_records"`
}

// Appendix 1 2.33
type CardSlotNumber byte

// Appendix 1 2.34
// B'ccccdddd'
// B'cccc' - codriver slot
// B'dddd' - driver slot
// B'0000' - no card is inserted
// B'0001' - a driver card is inserted
// B'0010' - a workshop card is inserted
// B'0011' - a control card is inserted
// B'0100' - a company card is inserted
type CardSlotsStatus byte

// Appendix 1 2.35
type CardSlotsStatusRecordArray struct {
	RecordType  RecordType        `json:"record_type"`
	RecordSize  uint16            `json:"record_size"`
	NoOfRecords uint16            `json:"no_of_records"`
	Records     []CardSlotsStatus `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.36
type CardStructureVersion [2]byte

// Appendix 1 2.37
type CardVehicleRecordFirstGen struct {
	VehicleOdometerBegin OdometerShort                     `json:"vehicle_odometer_begin"`
	VehicleOdometerEnd   OdometerShort                     `json:"vehicle_odometer_end"`
	VehicleFirstUse      TimeReal                          `json:"vehicle_first_use"`
	VehicleLastUse       TimeReal                          `json:"vehicle_last_use"`
	VehicleRegistration  VehicleRegistrationIdentification `json:"vehicle_registration"`
	VuDataBlockCounter   VuDataBlockCounter                `aper:"size=2" json:"vu_data_block_counter"`
}

type CardVehicleRecordSecondGen struct {
	VehicleOdometerBegin        OdometerShort                     `json:"vehicle_odometer_begin"`
	VehicleOdometerEnd          OdometerShort                     `json:"vehicle_odometer_end"`
	VehicleFirstUse             TimeReal                          `json:"vehicle_first_use"`
	VehicleLastUse              TimeReal                          `json:"vehicle_last_use"`
	VehicleRegistration         VehicleRegistrationIdentification `json:"vehicle_registration"`
	VuDataBlockCounter          VuDataBlockCounter                `aper:"size=2" json:"vu_data_block_counter"`
	VehicleIdentificationNumber VehicleIdentificationNumber       `json:"vehicle_identification_number"`
}

// Appendix 1 2.38
type CardVehiclesUsedFirstGen struct {
	Verified                   bool                        `aper:"-" json:"verified"`
	VehiclePointerNewestRecord NoOfCardVehicleRecords      `json:"vehicle_pointer_newest_record"`
	CardVehicleRecords         []CardVehicleRecordFirstGen `aper:"size=NoOfCardVehicleRecordsFirstGen" json:"card_vehicle_records"`
}

type CardVehiclesUsedSecondGen struct {
	Verified                   bool                         `aper:"-" json:"verified"`
	VehiclePointerNewestRecord NoOfCardVehicleRecords       `json:"vehicle_pointer_newest_record"`
	CardVehicleRecords         []CardVehicleRecordSecondGen `aper:"size=NoOfCardVehicleRecordsSecondGen" json:"card_vehicle_records"`
}

// Appendix 1 2.39
type CardVehicleUnitRecord struct {
	TimeStamp         TimeReal          `json:"time_stamp"`
	ManufacturerCode  ManufacturerCode  `json:"manufacturer_code"`
	DeviceID          byte              `json:"device_id"`
	VuSoftwareVersion VuSoftwareVersion `json:"vu_software_version"`
}

// Appendix 1 2.40
type CardVehicleUnitsUsed struct {
	Verified                       bool                       `aper:"-" json:"verified"`
	VehicleUnitPointerNewestRecord NoOfCardVehicleUnitRecords `json:"vehicle_unit_pointer_newest_record"`
	CardVehicleUnitRecords         []CardVehicleUnitRecord    `aper:"size=NoOfCardVehicleUnitRecords" json:"card_vehicle_unit_records"`
}

// Appendix 1 2.41
type CertificateFirstGen struct {
	DecodedCertificate *DecodedCertificateFirstGen `aper:"-" json:"-"`
	Certificate        [194]byte                   `json:"certificate,omitempty"`
}

// this is actually a usable version of CertificateContent (see below)
type DecodedCertificateFirstGen struct {
	CertificateHolderReference    uint64
	CertificateAuthorityReference uint64
	EndOfValidity                 time.Time
	RsaModulus                    *big.Int
	RsaExponent                   *big.Int
}

func (cert DecodedCertificateFirstGen) Perform(data []byte) []byte {
	sign := big.Int{}
	sign.SetBytes(data)
	z := big.Int{}
	z.Exp(&sign, cert.RsaExponent, cert.RsaModulus)
	return z.Bytes()
}

func (c *CertificateFirstGen) Decode() error {
	cert := new(DecodedCertificateFirstGen)
	// expected data
	// 0..127: sign
	// 128..185: Cn'
	// 186..193: CAR' (in case of member state certificates, this should refer to the root cert)
	data := c.Certificate
	CnPrime := data[128:186]
	var CARPrime uint64
	buf := bytes.NewBuffer(data[186:194])
	binary.Read(buf, binary.BigEndian, &CARPrime)
	if ca, ok := PKsFirstGen[CARPrime]; ok {
		SrPrime := ca.Perform(data[0:128])
		// Sr' has the structure 6A || Cr' || H' || BC
		if len(SrPrime) == 128 && SrPrime[0] == 0x6a && SrPrime[127] == 0xbc {
			CrPrime := SrPrime[1 : 1+106]
			HPrime := SrPrime[1+106 : 1+106+20]
			CPrime := append(CrPrime, CnPrime...)
			hash := sha1.Sum(CPrime)
			if !reflect.DeepEqual(HPrime, hash[:]) {
				return errors.New("certificate content hash mismatch")
			}
			if len(CPrime) != 164 {
				return errors.New("certificate length mismatch")
			}
			// C' has the structure
			// 0        CPI Certificate Profile Identifier (fix 0x01)
			// 1..8     CAR Certification Authority Reference
			// 9..15    CHA Certificate Holder Authorisation
			// 16..19   EOV End Of Validity (TimeReal), or 0xFFFFFFFF
			// 20..27   CHR Certificate Holder Reference
			// 28..155  n   RSA modulus
			// 156..163 e   RSA exponent
			var CAR, CHR uint64
			buf := bytes.NewBuffer(CPrime[1:9])
			binary.Read(buf, binary.BigEndian, &CAR)
			if CAR != CARPrime {
				log.Printf("warn: CAR %v != CAR' %v", CAR, CARPrime)
			}
			buf = bytes.NewBuffer(CPrime[20:28])
			binary.Read(buf, binary.BigEndian, &CHR)
			eov := TimeReal{}
			copy(eov.Timedata[:], CPrime[16:20])
			cert.EndOfValidity = eov.Decode()
			cert.CertificateAuthorityReference = CAR
			cert.CertificateHolderReference = CHR
			cert.RsaModulus = new(big.Int).SetBytes(CPrime[28:156])
			cert.RsaExponent = new(big.Int).SetBytes(CPrime[156:164])
			// we could add the cert to the global cert store, but probably this is not really necessary
			// PKsFirstGen[cert.CertificateHolderReference] = *cert
			c.DecodedCertificate = cert
			return nil
		}
	}
	return errors.New("could not extract certificate")
}

func (c CertificateFirstGen) MarshalJSON() ([]byte, error) {
	ok := false
	for i := 0; i < len(c.Certificate); i++ {
		if c.Certificate[i] > 0 && c.Certificate[i] < 255 {
			ok = true
			break
		}
	}
	if !ok {
		return json.Marshal(nil)
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(c.Certificate[:]))
}

func (c *CertificateFirstGen) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	copy(c.Certificate[:], b)
	return nil
}

type CertificateSecondGen struct {
	DecodedCertificate *DecodedCertificateSecondGen `aper:"-" json:"-"`                                 // make sure this is not the last field in the struct
	Certificate        []byte                       `aper:"size=204..341" json:"certificate,omitempty"` // see 2.41.: 204..341 bytes
}

type DecodedCertificateSecondGen struct {
	CertificateBody struct {
		CertificateProfileIdentifier   byte
		CertificateAuthorityReference  uint64
		CertificateHolderAuthorisation [7]byte
		PublicKey                      struct {
			DomainParameters asn1.ObjectIdentifier
			PublicPoint      struct {
				X *big.Int
				Y *big.Int
			}
		}
		CertificateHolderReference uint64
		CertificateEffectiveDate   time.Time
		CertificateExpirationDate  time.Time
	}
	ECCCertificateSignature struct {
		R *big.Int
		S *big.Int
	}
	Valid bool
}

// dpToCurve returns the signature hash length (bits) and the elliptic.Curve associated with the given domain parameters
// (one of brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, nistP256, nistP384, nistP521)
func dpToCurve(dp asn1.ObjectIdentifier) (int, elliptic.Curve, error) {
	var curve elliptic.Curve
	brainpoolP256r1Id := asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	brainpoolP384r1Id := asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	brainpoolP512r1Id := asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}
	nistP256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	nistP384 := asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	nistP521 := asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	hashBits := 0
	switch {
	case dp.Equal(brainpoolP256r1Id):
		curve = brainpool.P256r1()
		hashBits = 256
	case dp.Equal(brainpoolP384r1Id):
		curve = brainpool.P384r1()
		hashBits = 384
	case dp.Equal(brainpoolP512r1Id):
		curve = brainpool.P512r1()
		hashBits = 512
	case dp.Equal(nistP256):
		curve = elliptic.P256()
		hashBits = 256
	case dp.Equal(nistP384):
		curve = elliptic.P384()
		hashBits = 384
	case dp.Equal(nistP521):
		curve = elliptic.P521()
		hashBits = 512
	default:
		return 0, nil, fmt.Errorf("unknown domain parameter %s", dp.String())
	}
	return hashBits, curve, nil
}

func (c *CertificateSecondGen) Decode() error {
	decodedCertificate := DecodedCertificateSecondGen{}
	var asn1Cert asn1.RawValue
	_, err := asn1.Unmarshal(c.Certificate, &asn1Cert)
	if err != nil {
		return err
	}
	var asn1Body asn1.RawValue
	restBody, err := asn1.Unmarshal(asn1Cert.Bytes, &asn1Body)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate body: %v", err)
		return err
	}

	var asn1CPI asn1.RawValue
	restCPI, err := asn1.Unmarshal(asn1Body.Bytes, &asn1CPI)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate CPI: %v", err)
		return err
	}
	if len(asn1CPI.Bytes) != 1 {
		return fmt.Errorf("error: wrong CPI length: %d", len(asn1CPI.Bytes))
	}
	decodedCertificate.CertificateBody.CertificateProfileIdentifier = asn1CPI.Bytes[0]
	var asn1CAR asn1.RawValue
	restCAR, err := asn1.Unmarshal(restCPI, &asn1CAR)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate CAR: %v", err)
		return err
	}
	if len(asn1CAR.Bytes) != 8 {
		return fmt.Errorf("error: wrong CAR length: %d", len(asn1CAR.Bytes))
	}
	var car uint64
	buf := bytes.NewBuffer(asn1CAR.Bytes)
	binary.Read(buf, binary.BigEndian, &car)
	decodedCertificate.CertificateBody.CertificateAuthorityReference = car
	var asn1CHA asn1.RawValue
	restCHA, err := asn1.Unmarshal(restCAR, &asn1CHA)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate CHA: %v", err)
		return err
	}
	if len(asn1CHA.Bytes) != 7 {
		return fmt.Errorf("error: wrong CHA length: %d", len(asn1CAR.Bytes))
	}
	copy(decodedCertificate.CertificateBody.CertificateHolderAuthorisation[:], asn1CHA.Bytes)
	var asn1PK asn1.RawValue
	restPK, err := asn1.Unmarshal(restCHA, &asn1PK)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate PK: %v", err)
		return err
	}
	// public key consists of DP and PP
	var asn1DP asn1.ObjectIdentifier
	restDP, err := asn1.Unmarshal(asn1PK.Bytes, &asn1DP)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate DP: %v", err)
		return err
	}
	decodedCertificate.CertificateBody.PublicKey.DomainParameters = asn1DP
	var asn1PP asn1.RawValue
	restPP, err := asn1.Unmarshal(restDP, &asn1PP)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate PP: %v", err)
		return err
	}
	if len(restPP) > 0 {
		log.Printf("warn: %d additional bytes after the public key", len(restPP))
	}
	hashBits, curve, err := dpToCurve(asn1DP)

	byteLen := (curve.Params().BitSize + 7) >> 3

	x, y := elliptic.Unmarshal(curve, asn1PP.Bytes)
	if x == nil || y == nil {
		return fmt.Errorf("could not decode public point")
	}

	decodedCertificate.CertificateBody.PublicKey.PublicPoint.X = x
	decodedCertificate.CertificateBody.PublicKey.PublicPoint.Y = y
	//
	var asn1CHR asn1.RawValue
	restCHR, err := asn1.Unmarshal(restPK, &asn1CHR)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate CHR: %v", err)
		return err
	}
	if len(asn1CHR.Bytes) != 8 {
		return fmt.Errorf("error: wrong CHR length: %d", len(asn1CHR.Bytes))
	}

	var chr uint64
	bufCHR := bytes.NewBuffer(asn1CHR.Bytes)
	binary.Read(bufCHR, binary.BigEndian, &chr)
	decodedCertificate.CertificateBody.CertificateHolderReference = chr

	var asn1CEfD asn1.RawValue
	restCEfD, err := asn1.Unmarshal(restCHR, &asn1CEfD)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate CEfD: %v", err)
		return err
	}
	if len(asn1CEfD.Bytes) != 4 {
		return fmt.Errorf("error: wrong CEfD length: %d", len(asn1CEfD.Bytes))
	}

	var td [4]byte
	copy(td[:], asn1CEfD.Bytes)
	cefdTR := TimeReal{
		Timedata: td,
	}
	cefd := cefdTR.Decode()
	decodedCertificate.CertificateBody.CertificateEffectiveDate = cefd

	var asn1CExD asn1.RawValue
	restCExD, err := asn1.Unmarshal(restCEfD, &asn1CExD)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate CExD: %v", err)
		return err
	}
	if len(asn1CExD.Bytes) != 4 {
		return fmt.Errorf("error: wrong CExD length: %d", len(asn1CExD.Bytes))
	}
	if len(restCExD) > 0 {
		log.Printf("warn: %d additional bytes after the certificate body", len(restCExD))
	}
	copy(td[:], asn1CExD.Bytes)
	cexdTR := TimeReal{
		Timedata: td,
	}
	cexd := cexdTR.Decode()
	decodedCertificate.CertificateBody.CertificateExpirationDate = cexd

	if decodedCertificate.CertificateBody.CertificateHolderReference != decodedCertificate.CertificateBody.CertificateAuthorityReference {
		// only root certificates are self-signed, we have to look up the ca certificate
		if caPK, ok := PKsSecondGen[decodedCertificate.CertificateBody.CertificateAuthorityReference]; ok {
			hashBits, curve, err = dpToCurve(caPK.CertificateBody.PublicKey.DomainParameters)
			if err != nil {
				log.Printf("error: could not create ca curve: %v", err)
				return err
			}
			x = caPK.CertificateBody.PublicKey.PublicPoint.X
			y = caPK.CertificateBody.PublicKey.PublicPoint.Y
			byteLen = (curve.Params().BitSize + 7) >> 3
		} else {
			c.DecodedCertificate = &decodedCertificate
			log.Printf("warn: could not find ca pk %x, cannot verify", decodedCertificate.CertificateBody.CertificateAuthorityReference)
			return nil
		}
	}

	// restBody contains the signature
	var asn1Signature asn1.RawValue
	restSignature, err := asn1.Unmarshal(restBody, &asn1Signature)
	if err != nil {
		log.Printf("error: could not decode 2nd gen certificate signature: %v", err)
		return err
	}
	// len of decoded signature should be 2 * byteLen (as there are two big ints)
	if len(restSignature) > 0 {
		log.Printf("warn: %d additional bytes after the signature", len(restSignature))
	}
	// this is the raw signature "ECC Certificate Signature" "S"
	S := asn1Signature.Bytes
	if len(S) != 2*byteLen {
		return fmt.Errorf("signature length mismatch: %d (expected: %d)", len(S), 2*byteLen)
	}
	// signature in plain format according to TR-03111, i.e. r and s are concatenated, length is 2 * byteLen
	r := new(big.Int).SetBytes(S[:byteLen])
	s := new(big.Int).SetBytes(S[byteLen:])
	decodedCertificate.ECCCertificateSignature.R = r
	decodedCertificate.ECCCertificateSignature.S = s

	c.DecodedCertificate = &decodedCertificate

	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	hashData := asn1Body.FullBytes // hash is computed including the certificate body tag and length
	hash := make([]byte, 64)
	switch hashBits {
	case 256:
		hash256 := sha256.Sum256(hashData)
		copy(hash, hash256[:])
		hash = hash[0:32]
	case 384:
		hash384 := sha512.Sum384(hashData)
		copy(hash, hash384[:])
		hash = hash[0:48]
	case 512:
		hash512 := sha512.Sum512(hashData)
		copy(hash, hash512[:])
	default:
		return fmt.Errorf("unknown hash bit size: %d", hashBits)
	}
	valid := ecdsa.Verify(&pub, hash, r, s)
	decodedCertificate.Valid = valid
	return nil
}

func (c CertificateSecondGen) MarshalJSON() ([]byte, error) {
	ok := false
	for i := 0; i < len(c.Certificate); i++ {
		if c.Certificate[i] > 0 && c.Certificate[i] < 255 {
			ok = true
			break
		}
	}
	if !ok {
		return json.Marshal(nil)
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(c.Certificate))
}

func (c *CertificateSecondGen) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	c.Certificate = make([]byte, len(b))
	copy(c.Certificate, b)
	return nil
}

// Appendix 1 2.42
type CertificateContent struct {
	CertificateProfileIdentifier    byte
	CertificationAuthorityReference KeyIdentifier
	CertificateHolderAuthorisation  CertificateHolderAuthorisation
	CertificateEndOfValidity        TimeReal
	CertificateHolderReference      KeyIdentifier
	PublicKey                       PublicKey
}

// Appendix 1 2.43
type CertificateHolderAuthorisation struct {
	TachographApplicationID [6]byte       // fix: 1st gen: FF 54 41 43 48 4F 2nd gen: FF 53 4D 52 44 54
	EquipmentType           EquipmentType // 0 for member state certificate
}

// Appendix 1 2.45
type CertificationAuthorityKID struct {
	NationNumeric   NationNumeric
	NationAlpha     NationAlpha
	KeySerialNumber byte
	AdditionalInfo  [2]byte // or FF FF
	CaIdentifier    byte    // fix 01
}

// Appendix 1 2.53
type ControlType byte

// Appendix 1 2.54
type CurrentDateTime TimeReal

func (d CurrentDateTime) Decode() time.Time {
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return r.Decode()
}

func (d CurrentDateTime) MarshalJSON() ([]byte, error) {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return json.Marshal(r)
}

// Appendix 1 2.55
type CurrentDateTimeRecordArray struct {
	RecordType  RecordType        `json:"record_type"`
	RecordSize  uint16            `json:"record_size"`
	NoOfRecords uint16            `json:"no_of_records"`
	Records     []CurrentDateTime `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.56
type DailyPresenceCounter BCDString

func (c DailyPresenceCounter) Decode() (int, error) {
	b := make(BCDString, len(c))
	copy(b, c)
	return b.Decode()
}

func (c DailyPresenceCounter) MarshalJSON() ([]byte, error) {
	// workaround since "aliased" types seem not to inherit the marshal function
	b := make(BCDString, len(c))
	copy(b, c)
	return json.Marshal(b)
}

// Appendix 1 2.57
type Datef struct {
	Year  BCDString `aper:"size=2" json:"year"`
	Month BCDString `aper:"size=1" json:"month"`
	Day   BCDString `aper:"size=1" json:"day"`
}

// Appendix 1 2.58
type DateOfDayDownloaded TimeReal

func (d DateOfDayDownloaded) Decode() time.Time {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return r.Decode()
}

func (d DateOfDayDownloaded) MarshalJSON() ([]byte, error) {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return json.Marshal(r)
}

// Appendix 1 2.59
type DateOfDayDownloadedRecordArray struct {
	RecordType  RecordType            `json:"record_type"`
	RecordSize  uint16                `json:"record_size"`
	NoOfRecords uint16                `json:"no_of_records"`
	Records     []DateOfDayDownloaded `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.60
type Distance uint16 // km

// Appendix 1 2.60a
type DownloadInterfaceVersion struct {
	Verified                 bool    `aper:"-" json:"verified"`
	DownloadInterfaceVersion [2]byte `aper:"global" json:"download_interface_version"`
}

// Appendix 1 2.61
type DriverCardApplicationIdentificationFirstGen struct {
	Verified                        bool                         `aper:"-" json:"verified"`
	TypeOfTachographCardId          EquipmentType                `json:"type_of_tachograph_card_id"`
	CardStructureVersion            CardStructureVersion         `json:"card_structure_version"`
	NoOfEventsPerTypeFirstGen       NoOfEventsPerType            `aper:"global" json:"no_of_events_per_type"`
	NoOfFaultsPerTypeFirstGen       NoOfFaultsPerType            `aper:"global" json:"no_of_faults_per_type"`
	ActivityStructureLengthFirstGen CardActivityLengthRange      `aper:"global" json:"activity_structure_length"` // this is actually a data-global value and needs to be accessed from other blocks
	NoOfCardVehicleRecordsFirstGen  NoOfCardVehicleRecords       `aper:"global" json:"no_of_card_vehicle_records"`
	NoOfCardPlaceRecordsFirstGen    NoOfCardPlaceRecordsFirstGen `aper:"global" json:"no_of_card_place_records"`
}

type DriverCardApplicationIdentificationSecondGen struct {
	Verified                         bool                          `aper:"-" json:"verified"`
	TypeOfTachographCardId           EquipmentType                 `json:"type_of_tachograph_card_id"`
	CardStructureVersion             CardStructureVersion          `json:"card_structure_version"`
	NoOfEventsPerTypeSecondGen       NoOfEventsPerType             `aper:"global" json:"no_of_events_per_type"`
	NoOfFaultsPerTypeSecondGen       NoOfFaultsPerType             `aper:"global" json:"no_of_faults_per_type"`
	ActivityStructureLengthSecondGen CardActivityLengthRange       `aper:"global" json:"activity_structure_length"`
	NoOfCardVehicleRecordsSecondGen  NoOfCardVehicleRecords        `aper:"global" json:"no_of_card_vehicle_records"`
	NoOfCardPlaceRecordsSecondGen    NoOfCardPlaceRecordsSecondGen `aper:"global" json:"no_of_card_place_records"`
	NoOfGNSSADRecords                NoOfGNSSADRecords             `aper:"global" json:"no_of_gnss_ad_records"`
	NoOfSpecificConditionRecords     NoOfSpecificConditionRecords  `aper:"global" json:"no_of_specific_condition_records"`
	NoOfCardVehicleUnitRecords       NoOfCardVehicleUnitRecords    `aper:"global" json:"no_of_card_vehicle_unit_records"`
}

// Appendix 1 2.61a
type DriverCardApplicationIdentificationSecondGenV2 struct {
	Verified                   bool                       `aper:"-" json:"verified"`
	LengthOfFollowingData      LengthOfFollowingData      `aper:"global" json:"length_of_following_data"`
	NoOfBorderCrossingRecords  NoOfBorderCrossingRecords  `aper:"global" json:"no_of_border_crossing_records"`
	NoOfLoadUnloadRecords      NoOfLoadUnloadRecords      `aper:"global" json:"no_of_load_unload_records"`
	NoOfLoadTypeEntryRecords   NoOfLoadTypeEntryRecords   `aper:"global" json:"no_of_load_type_entry_records"`
	VuConfigurationLengthRange VuConfigurationLengthRange `aper:"global" json:"vu_configuration_length_range"`
}

// Appendix 1 2.62
type DriverCardHolderIdentification struct {
	CardHolderName              HolderName `json:"card_holder_name"`
	CardHolderBirthDate         Datef      `json:"card_holder_birth_date"`
	CardHolderPreferredLanguage Language   `json:"card_holder_preferred_language"`
}

// Appendix 1 2.65
type EmbedderIcAssemblerId struct {
	CountryCode             CountryCode `json:"country_code"`
	ModuleEmbedder          BCDString   `aper:"size=2" json:"module_embedder"`
	ManufacturerInformation byte        `json:"manufacturer_information"`
}

type CountryCode [2]byte // helper type for json marshaling

func (c CountryCode) String() string {
	return bytesToString(c[:])
}

func (c CountryCode) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(c[:]))
}

// Appendix 1 2.66
type EntryTypeDailyWorkPeriodFirstGen byte
type EntryTypeDailyWorkPeriodSecondGen byte // same as first gen, but 2 additional values for gnss

// Appendix 1 2.67
type EquipmentType byte

// Appendix 1 2.69
type EventFaultRecordPurpose byte

// Appendix 1 2.70
type EventFaultType byte

// Appendix 1 2.71
type ExtendedSealIdentifier struct {
	ManufacturerCode [2]byte `json:"manufacturer_code"`
	SealIdentifier   [8]byte `json:"seal_identifier"` // according to changes doc
}

// Appendix 1 2.72
type ExtendedSerialNumberFirstGen struct {
	SerialNumber     uint32           `json:"serial_number"`
	MonthYear        MonthYear        `aper:"size=2" json:"month_year"`
	Type             byte             `json:"type"`
	ManufacturerCode ManufacturerCode `json:"manufacturer_code"`
}

type ExtendedSerialNumberSecondGen struct {
	SerialNumber     uint32           `json:"serial_number"`
	MonthYear        MonthYear        `aper:"size=2" json:"month_year"`
	Type             EquipmentType    `json:"type"`
	ManufacturerCode ManufacturerCode `json:"manufacturer_code"`
}

type MonthYear BCDString // helper type for json marshaling

func (my MonthYear) Decode() (month int, year int) {
	b := make(BCDString, len(my))
	copy(b, my)
	myi, _ := b.Decode()
	month = myi / 100
	year = myi % 100
	return
}

func (my MonthYear) MarshalJSON() ([]byte, error) {
	b := make(BCDString, len(my))
	copy(b, my)
	myi, err := b.Decode()
	if err != nil {
		log.Printf("warn: could not decode month year: %v", err)
		// return []byte{}, err
	}
	s := struct {
		Month int `json:"month"`
		Year  int `json:"year"`
	}{
		Month: myi / 100,
		Year:  myi % 100,
	}
	return json.Marshal(s)
}

// Appendix 1 2.73
type FullCardNumber struct {
	CardType               EquipmentType `json:"card_type"`
	CardIssuingMemberState NationNumeric `json:"card_issuing_member_state"`
	CardNumber             CardNumber    `json:"card_number"`
}

// Appendix 1 2.74
type FullCardNumberAndGeneration struct {
	FullCardNumber FullCardNumber `json:"full_card_number"`
	Generation     Generation     `json:"generation"`
}

// Appendix 1 2.75
type Generation byte

// Appendix 1 2.76
type GeoCoordinates struct {
	Latitude  [3]byte
	Longitude [3]byte
}

func (g GeoCoordinates) Decode() (lon float64, lat float64) {
	fillByte := byte(0x00)
	if (g.Latitude[0] & 0x80) > 0 {
		fillByte = 0xff
	}
	bLat := bytes.NewBuffer([]byte{fillByte, g.Latitude[0], g.Latitude[1], g.Latitude[2]})
	var latVal int32
	binary.Read(bLat, binary.BigEndian, &latVal)
	fillByte = byte(0x00)
	if (g.Longitude[0] & 0x80) > 0 {
		fillByte = 0xff
	}
	bLon := bytes.NewBuffer([]byte{fillByte, g.Longitude[0], g.Longitude[1], g.Longitude[2]})
	var lonVal int32
	binary.Read(bLon, binary.BigEndian, &lonVal)

	// lon and lat are encoded as integers multiples of ±DDDMM.M (longitude) and ±DDMM.M (latitude)
	// where ±DDD/±DD denotes degrees and MM.M denotes minutes
	// Use absolute values for string parsing, then apply original sign
	lonStr := fmt.Sprintf("%06d", int32(math.Abs(float64(lonVal)))) // DDDMMM format (6 digits)
	latStr := fmt.Sprintf("%05d", int32(math.Abs(float64(latVal)))) // DDMMM format (5 digits)

	// Remember the original signs
	lonNegative := lonVal < 0
	latNegative := latVal < 0

	// log.Printf("lonstr: %v", lonStr)
	// Parse longitude: DDDMM.M format (DDD degrees + MM.M minutes)
	if len(lonStr) == 6 {
		if deg, err := strconv.ParseInt(lonStr[0:3], 10, 32); err == nil {
			if minTen, err := strconv.ParseInt(lonStr[3:6], 10, 32); err == nil {
				lon = float64(deg) + (float64(minTen)/10.0)/60.0
				if lonNegative {
					lon = -lon
				}
			}
		}
	}

	// Parse latitude: DDMM.M format (DD degrees + MM.M minutes)
	if len(latStr) == 5 {
		if deg, err := strconv.ParseInt(latStr[0:2], 10, 32); err == nil {
			if minTen, err := strconv.ParseInt(latStr[2:5], 10, 32); err == nil {
				lat = float64(deg) + (float64(minTen)/10.0)/60.0
				if latNegative {
					lat = -lat
				}
			}
		}
	}

	return
}

func (g GeoCoordinates) MarshalJSON() ([]byte, error) {
	lon, lat := g.Decode()
	return json.Marshal(struct {
		Longitude float64 `json:"longitude"`
		Latitude  float64 `json:"latitude"`
	}{
		Longitude: lon,
		Latitude:  lat,
	})
}

func (g *GeoCoordinates) UnmarshalJSON(data []byte) error {
	s := struct {
		Longitude float64 `json:"longitude"`
		Latitude  float64 `json:"latitude"`
	}{}
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	degLon := int(math.Trunc(s.Longitude))
	degLat := int(math.Trunc(s.Latitude))
	minTenLon := int(math.Round((s.Longitude - math.Trunc(s.Longitude)) * 600))
	minTenLat := int(math.Round((s.Latitude - math.Trunc(s.Latitude)) * 600))
	lon := degLon*1000 + minTenLon
	lat := degLat*1000 + minTenLat

	if lat >= -90000 && lat <= 180001 && lon >= -180000 && lon <= 180001 {
		valLon := int32(lon)
		valLat := int32(lat)
		bufLon := make([]byte, 0, 4)
		bLon := bytes.NewBuffer(bufLon)
		binary.Write(bLon, binary.BigEndian, valLon)
		resBytesLon := bLon.Bytes()
		if len(resBytesLon) < 3 {
			return errors.New("could not decode geo lon value")
		}
		g.Longitude[0] = resBytesLon[1]
		g.Longitude[1] = resBytesLon[2]
		g.Longitude[2] = resBytesLon[3]
		bufLat := make([]byte, 0, 4)
		bLat := bytes.NewBuffer(bufLat)
		binary.Write(bLat, binary.BigEndian, valLat)
		resBytesLat := bLon.Bytes()
		if len(resBytesLat) < 3 {
			return errors.New("could not decode geo lat value")
		}
		g.Latitude[0] = resBytesLat[1]
		g.Latitude[1] = resBytesLat[2]
		g.Latitude[2] = resBytesLat[3]
	}

	return nil
}

// Appendix 1 2.77
type GNSSAccuracy byte

// Appendix 1 2.78
type GNSSAccumulatedDriving struct {
	Verified                      bool                           `aper:"-" json:"verified"`
	GNSSADPointerNewestRecord     NoOfGNSSADRecords              `json:"gnss_ad_pointer_newest_record"`
	GNSSAccumulatedDrivingRecords []GNSSAccumulatedDrivingRecord `aper:"size=NoOfGNSSADRecords" json:"gnss_accumulated_driving_records"`
}

// Appendix 1 2.79
type GNSSAccumulatedDrivingRecord struct {
	TimeStamp            TimeReal        `json:"time_stamp"`
	GNSSPlaceRecord      GNSSPlaceRecord `json:"gnss_place_record"`
	VehicleOdometerValue OdometerShort   `json:"vehicle_odometer_value"`
}

// Appendix 1 2.79a
type GNSSAuthAccumulatedDriving struct {
	Verified                      bool                     `aper:"-" json:"verified"`
	GNSSAuthADPointerNewestRecord NoOfGNSSADRecords        `json:"gnss_auth_ad_pointer_newest_record"`
	GNSSAuthStatusADRecords       []GNSSAuthStatusADRecord `aper:"size=NoOfGNSSADRecords" json:"gnss_auth_status_ad_records"`
}

// Appendix 1 2.79b
type GNSSAuthStatusADRecord struct {
	TimeStamp            TimeReal                     `json:"time_stamp"`
	AuthenticationStatus PositionAuthenticationStatus `json:"authentication_status"`
}

// Appendix 1 2.79c
type GNSSPlaceAuthRecord struct {
	TimeStamp            TimeReal                     `json:"time_stamp"`
	GNSSAccuracy         GNSSAccuracy                 `json:"gnss_accuracy"`
	GeoCoordinates       GeoCoordinates               `json:"geo_coordinates"`
	AuthenticationStatus PositionAuthenticationStatus `json:"authentication_status"`
}

// Appendix 1 2.80
type GNSSPlaceRecord struct {
	TimeStamp      TimeReal       `json:"time_stamp"`
	GNSSAccuracy   GNSSAccuracy   `json:"gnss_accuracy"`
	GeoCoordinates GeoCoordinates `json:"geo_coordinates"`
}

// Appendix 1 2.83
type HolderName struct {
	HolderSurname    Name `json:"holder_surname"`
	HolderFirstNames Name `json:"holder_first_names"`
}

// Appendix 1 2.85
type KConstantOfRecordingEquipment uint16

// Appendix 1 2.86
type KeyIdentifier struct {
	CertificationAuthorityKID CertificationAuthorityKID
}

// this is actually a "choice" object. We confine to the CertificationAuthorityKID here, since this is currently our only usage

// Appendix 1 2.88
type Language [2]byte

func (l Language) String() string {
	return bytesToString(l[:])
}

func (l Language) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(l[:]))
}

func (l *Language) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	if len(str) == 0 {
		return nil
	}
	b := []byte(str)
	if len(b) != 2 {
		return fmt.Errorf("wrong string length: %v (should be 2)", len(b))
	}
	copy(l[:], b)
	return nil
}

// Appendix 1 2.89
type LastCardDownload struct {
	Verified         bool     `aper:"-" json:"verified"`
	LastCardDownLoad TimeReal `json:"last_card_download"`
}

// type LastCardDownload TimeReal
/*
func (l LastCardDownload) MarshalJSON() ([]byte, error) {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = l.Timedata[0]
	r.Timedata[1] = l.Timedata[1]
	r.Timedata[2] = l.Timedata[2]
	r.Timedata[3] = l.Timedata[3]
	return json.Marshal(r)
}
*/

// Appendix 1 2.89a
type LengthOfFollowingData uint16

// Appendix 1 2.90a
type LoadType uint8

// Appendix 1 2.91
type LTyreCircumference uint16

// Appendix 1 2.93
type ManualInputFlag byte

// Appendix 1 2.94
type ManufacturerCode byte

// Appendix 1 2.95
type ManufacturerSpecificEventFaultData struct {
	ManufacturerCode              ManufacturerCode `json:"manufacturer_code"`
	ManufacturerSpecificErrorCode [3]byte          `json:"manufacturer_specific_error_code"`
}

// Appendix 1 2.96
type MemberStateCertificateFirstGen CertificateFirstGen
type MemberStateCertificateSecondGen CertificateSecondGen

func (c MemberStateCertificateFirstGen) MarshalJSON() ([]byte, error) {
	nc := CertificateFirstGen{
		Certificate: c.Certificate,
	}
	return json.Marshal(nc)
}

func (c MemberStateCertificateSecondGen) MarshalJSON() ([]byte, error) {
	return json.Marshal(CertificateSecondGen{
		Certificate: c.Certificate,
	})
}

// Appendix 1 2.97
type MemberStateCertificateRecordArray struct {
	RecordType  RecordType                        `json:"record_type"`
	RecordSize  uint16                            `json:"record_size"`
	NoOfRecords uint16                            `json:"no_of_records"`
	Records     []MemberStateCertificateSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.99
type Name struct {
	CodePage byte
	Name     [35]byte
}

func (n Name) String() string {
	s, _ := decodeWithCodePage(n.CodePage, n.Name[:])
	return s
}

func (n Name) MarshalJSON() ([]byte, error) {
	s, err := decodeWithCodePage(n.CodePage, n.Name[:])
	if err != nil {
		return json.Marshal(nil)
	}
	return json.Marshal(s)
}

// Appendix 1 2.100
type NationAlpha [3]byte

func (n NationAlpha) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(n[:]))
}

// Appendix 1 2.101
type NationNumeric byte

// Appendix 1 2.101a
type NoOfBorderCrossingRecords uint16

// Appendix 1 2.104
type NoOfCardPlaceRecordsFirstGen byte
type NoOfCardPlaceRecordsSecondGen uint16

// Appendix 1 2.105
type NoOfCardVehicleRecords uint16

// Appendix 1 2.106
type NoOfCardVehicleUnitRecords uint16

// Appendix 1 2.109
type NoOfEventsPerType byte

// Appendix 1 2.110
type NoOfFaultsPerType byte

// Appendix 1 2.111
type NoOfGNSSADRecords uint16

// Appendix 1 2.111a
type NoOfLoadUnloadRecords uint16

// Appendix 1 2.112
type NoOfSpecificConditionRecords uint16

// Appendix 1 2.112a
type NoOfLoadTypeEntryRecords uint16

// Appendix 1 2.113
type OdometerShort [3]byte

func (o OdometerShort) Decode() int {
	b := bytes.NewBuffer([]byte{0x00, o[0], o[1], o[2]})
	var tVal uint32
	binary.Read(b, binary.BigEndian, &tVal)
	return int(tVal)
}

func (o OdometerShort) MarshalJSON() ([]byte, error) {
	if o[0] == 255 && o[1] == 255 && o[2] == 255 {
		return json.Marshal(nil)
	}
	return json.Marshal(o.Decode())
}

func (o *OdometerShort) UnmarshalJSON(data []byte) error {
	var val uint32
	err := json.Unmarshal(data, &val)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, 4)
	b := bytes.NewBuffer(buf)
	binary.Write(b, binary.BigEndian, val)
	resBytes := b.Bytes()
	if len(resBytes) < 3 {
		return errors.New("could not decode odometer short value")
	}
	o[0] = resBytes[1]
	o[1] = resBytes[2]
	o[2] = resBytes[3]
	return nil
}

// Appendix 1 2.114
type OdometerValueMidnight OdometerShort

func (v OdometerValueMidnight) Decode() int {
	o := OdometerShort{}
	o[0] = v[0]
	o[1] = v[1]
	o[2] = v[2]
	return o.Decode()
}

func (v OdometerValueMidnight) MarshalJSON() ([]byte, error) {
	o := OdometerShort{}
	o[0] = v[0]
	o[1] = v[1]
	o[2] = v[2]
	return json.Marshal(o)
}

func (v *OdometerValueMidnight) UnmarshalJSON(data []byte) error {
	var o OdometerShort
	err := json.Unmarshal(data, &o)
	if err != nil {
		return err
	}
	v[0] = o[0]
	v[1] = o[1]
	v[2] = o[2]
	return nil
}

// Appendix 1 2.114a
type OperationType uint8

// Appendix 1 2.115
type OdometerValueMidnightRecordArray struct {
	RecordType  RecordType              `json:"record_type"`
	RecordSize  uint16                  `json:"record_size"`
	NoOfRecords uint16                  `json:"no_of_records"`
	Records     []OdometerValueMidnight `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.116
type OverspeedNumber byte

// Appendix 1 2.116a
type PlaceAuthRecord struct {
	EntryTime                TimeReal                         `json:"entry_time"`
	EntryTypeDailyWorkPeriod EntryTypeDailyWorkPeriodFirstGen `json:"entry_type_daily_work_period"`
	DailyWorkPeriodCountry   NationNumeric                    `json:"daily_work_period_country"`
	DailyWorkPeriodRegion    RegionNumeric                    `json:"daily_work_period_region"`
	VehicleOdometerValue     OdometerShort                    `json:"vehicle_odometer_value"`
	EntryGNSSPlaceAuthRecord GNSSPlaceAuthRecord              `json:"entry_gnss_place_auth_record"`
}

// Appendix 1 2.116b
type PlaceAuthStatusRecord struct {
	EntryTime            TimeReal                     `json:"entry_time"`
	AuthenticationStatus PositionAuthenticationStatus `json:"authentication_status"`
}

// Appendix 1 2.117
type PlaceRecordFirstGen struct {
	EntryTime                TimeReal                         `json:"entry_time"`
	EntryTypeDailyWorkPeriod EntryTypeDailyWorkPeriodFirstGen `json:"entry_type_daily_work_period"`
	DailyWorkPeriodCountry   NationNumeric                    `json:"daily_work_period_country"`
	DailyWorkPeriodRegion    RegionNumeric                    `json:"daily_work_period_region"`
	VehicleOdometerValue     OdometerShort                    `json:"vehicle_odometer_value"`
}

type PlaceRecordSecondGen struct {
	EntryTime                TimeReal                         `json:"entry_time"`
	EntryTypeDailyWorkPeriod EntryTypeDailyWorkPeriodFirstGen `json:"entry_type_daily_work_period"`
	DailyWorkPeriodCountry   NationNumeric                    `json:"daily_work_period_country"`
	DailyWorkPeriodRegion    RegionNumeric                    `json:"daily_work_period_region"`
	VehicleOdometerValue     OdometerShort                    `json:"vehicle_odometer_value"`
	EntryGNSSPlaceRecord     GNSSPlaceRecord                  `json:"entry_gnss_place_record"`
}

// Appendix 1 2.117a
type PositionAuthenticationStatus byte

// Appendix 1 2.118
type PreviousVehicleInfoFirstGen struct {
	VehicleRegistrationIdentification VehicleRegistrationIdentification `json:"vehicle_registration_identification"`
	CardWithdrawalTime                TimeReal                          `json:"card_withdrawal_time"`
}

type PreviousVehicleInfoSecondGen struct {
	VehicleRegistrationIdentification VehicleRegistrationIdentification `json:"vehicle_registration_identification"`
	CardWithdrawalTime                TimeReal                          `json:"card_withdrawal_time"`
	VuGeneration                      Generation                        `json:"vu_generation"`
}

// Appendix 1 2.119
type PublicKey struct {
	RsaKeyModulus        RSAKeyModulus
	RsaKeyPublicExponent RSAKeyPublicExponent
}

// Appendix 1 2.120
type RecordType byte

// Appendix 1 2.122
type RegionNumeric byte

// Appendix 1 2.123
type RemoteCommunicationModuleSerialNumber ExtendedSerialNumberSecondGen

// Appendix 1 2.124
type RSAKeyModulus [128]byte

// Appendix 1 2.125
type RSAKeyPrivateExponent [128]byte

// Appendix 1 2.126
type RSAKeyPublicExponent [8]byte

// Appendix 1 2.129
type SealDataVu [5]struct {
	SealRecord SealRecord `json:"seal_record"`
}

// Appendix 1 2.130
type SealRecord struct {
	EquipmentType          EquipmentType          `json:"equipment_type"`
	ExtendedSealIdentifier ExtendedSealIdentifier `json:"extended_seal_identifier"`
}

// Appendix 1 2.131
type SensorApprovalNumberFirstGen [8]byte
type SensorApprovalNumberSecondGen [16]byte

// Appendix 1 2.132
type SensorExternalGNSSApprovalNumber [16]byte

func (n SensorExternalGNSSApprovalNumber) String() string {
	return bytesToString(n[:])
}

func (n SensorExternalGNSSApprovalNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(n[:]))
}

// Appendix 1 2.133
type SensorExternalGNSSCoupledRecord struct {
	SensorSerialNumber   SensorGNSSSerialNumber           `json:"sensor_serial_number"`
	SensorApprovalNumber SensorExternalGNSSApprovalNumber `json:"sensor_approval_number"`
	SensorCouplingDate   SensorGNSSCouplingDate           `json:"sensor_coupling_date"`
}

// Appendix 1 2.138
type SensorGNSSCouplingDate TimeReal

func (d SensorGNSSCouplingDate) Decode() time.Time {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return r.Decode()
}

func (d SensorGNSSCouplingDate) MarshalJSON() ([]byte, error) {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return json.Marshal(r)
}

// Appendix 1 2.139
type SensorGNSSSerialNumber ExtendedSerialNumberSecondGen

// Appendix 1 2.144
type SensorPaired struct {
	SensorSerialNumber     SensorSerialNumberFirstGen   `json:"sensor_serial_number"`
	SensorApprovalNumber   SensorApprovalNumberFirstGen `json:"sensor_approval_number"`
	SensorPairingDateFirst SensorPairingDate            `json:"sensor_pairing_date_first"`
}

// Appendix 1 2.145
type SensorPairedRecord struct {
	SensorSerialNumber   SensorSerialNumberSecondGen   `json:"sensor_serial_number"`
	SensorApprovalNumber SensorApprovalNumberSecondGen `json:"sensor_approval_number"`
	SensorPairingDate    SensorPairingDate             `json:"sensor_pairing_date"`
}

// Appendix 1 2.146
type SensorPairingDate TimeReal

func (d SensorPairingDate) Decode() time.Time {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return r.Decode()
}

func (d SensorPairingDate) MarshalJSON() ([]byte, error) {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return json.Marshal(r)
}

// Appendix 1 2.148
type SensorSerialNumberFirstGen ExtendedSerialNumberFirstGen
type SensorSerialNumberSecondGen ExtendedSerialNumberSecondGen

// Appendix 1 2.149
type SignatureFirstGen struct {
	DecodedSignature *DecodedSignatureFirstGen `aper:"-" json:"-"`
	Signature        [128]byte                 `json:"signature,omitempty"` // tag with fixed len optional
}

type DecodedSignatureFirstGen struct {
	Sha1 [20]byte `json:"sha1"` // we only keep the sha1 of a correctly decoded signature
}

func (s *SignatureFirstGen) Decode(cert CertificateFirstGen) error {
	if cert.DecodedCertificate == nil {
		return errors.New("no decoded certificate")
	}
	signature := cert.DecodedCertificate.Perform(s.Signature[:])
	if len(signature) > 0 && len(signature) < 128 {
		// pad with leading zeros
		signature = append(make([]byte, 128-len(signature)), signature...)
	}
	if len(signature) != 128 {
		log.Printf("signature length: %v", len(signature))
		return errors.New("signature length mismatch")
	}
	// here, the documentation (even in the newest version as of 2020-02) is a bit misleading
	// Appendix 11 6.1 (CSM_034) states that the signature should have the form
	// 0x00 || 0x01 || PS || 0x00 || DER(SHA-1(data))
	// (PS = fill bytes 0xFF to have 128 bytes in total)
	// but really when using standard sha1 library functions, the leading zero byte is trimmed:
	// 0x01 || PS || 0x00 || DER(SHA-1(data))
	// (the same issue is also mentioned in the readesm source comments, so it seems common problem)
	// DER(SHA-1(data)) has the form
	// 0x30 0x21 0x30 0x09 0x06 0x05 0x2b 0x0e 0x03 0x02 0x1a 0x05 0x00 0x04 0x14 + 20 bytes sha-1 hash
	// so we check only that starting from byte 3 the data has the correct format
	derStart := len(signature) - 35
	sha1Start := len(signature) - 20
	valid := true
	if signature[0] != 0x00 || signature[1] != 0x01 {
		valid = false
	}
	for i := 2; i < derStart-1; i++ {
		if signature[i] != 0xff {
			valid = false
			break
		}
	}
	if signature[derStart-1] != 0 {
		valid = false
	}
	der := []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}
	if !reflect.DeepEqual(signature[derStart:derStart+len(der)], der) {
		valid = false
	}
	if !valid {
		return errors.New("invalid signature")
	}
	decSig := new(DecodedSignatureFirstGen)
	copy(decSig.Sha1[:], signature[sha1Start:])
	s.DecodedSignature = decSig
	return nil
}

func (s *SignatureFirstGen) Verify(cert CertificateFirstGen, data []byte) (bool, error) {
	if cert.DecodedCertificate == nil {
		if err := cert.Decode(); err != nil {
			return false, err
		}
	}
	if s.DecodedSignature == nil {
		if err := s.Decode(cert); err != nil {
			return false, errors.New("could not decode signature")
		}
	}
	hash := sha1.Sum(data)
	if hash != s.DecodedSignature.Sha1 {
		return false, nil
	}
	return true, nil
}

/*
func (s SignatureFirstGen) MarshalJSON() ([]byte, error) {
	ok := false
	for i := 0; i < len(s.Signature); i++ {
		if s.Signature[i] > 0 && s.Signature[i] < 255 {
			ok = true
			break
		}
	}
	if !ok {
		return json.Marshal(nil)
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(s.Signature[:]))
}

func (s *SignatureFirstGen) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	copy(s.Signature[:], b)
	return nil
}
*/

type SignatureSecondGen struct {
	DecodedSignature *DecodedSignatureSecondGen `aper:"-" json:"-"`
	Signature        []byte                     `aper:"size=64..132" json:"signature,omitempty"`
}

type DecodedSignatureSecondGen struct {
	R *big.Int
	S *big.Int
}

func (s *SignatureSecondGen) Decode(byteLen int) error {
	if len(s.Signature) != 2*byteLen {
		return fmt.Errorf("signature length mismatch %d expected %d", len(s.Signature), 2*byteLen)
	}
	rVal := new(big.Int).SetBytes(s.Signature[:byteLen])
	sVal := new(big.Int).SetBytes(s.Signature[byteLen:])
	decodedSignature := DecodedSignatureSecondGen{
		R: rVal,
		S: sVal,
	}
	s.DecodedSignature = &decodedSignature
	return nil
}

func (s *SignatureSecondGen) Verify(cert CertificateSecondGen, data []byte) (bool, error) {
	if cert.DecodedCertificate == nil {
		if err := cert.Decode(); err != nil {
			return false, err
		}
	}
	hashBits, curve, err := dpToCurve(cert.DecodedCertificate.CertificateBody.PublicKey.DomainParameters)
	if err != nil {
		return false, err
	}
	x := cert.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.X
	y := cert.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.Y
	byteLen := (curve.Params().BitSize + 7) >> 3
	if s.DecodedSignature == nil {
		if err := s.Decode(byteLen); err != nil {
			return false, err
		}
	}
	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	hash := make([]byte, 64)
	switch hashBits {
	case 256:
		hash256 := sha256.Sum256(data)
		copy(hash, hash256[:])
		hash = hash[0:32]
	case 384:
		hash384 := sha512.Sum384(data)
		copy(hash, hash384[:])
		hash = hash[0:48]
	case 512:
		hash512 := sha512.Sum512(data)
		copy(hash, hash512[:])
	default:
		return false, fmt.Errorf("unknown hash bit size: %d", hashBits)
	}
	valid := ecdsa.Verify(&pub, hash, s.DecodedSignature.R, s.DecodedSignature.S)
	return valid, nil
}

/*
func (s SignatureSecondGen) MarshalJSON() ([]byte, error) {
	ok := false
	for i := 0; i < len(s.Signature); i++ {
		if s.Signature[i] > 0 && s.Signature[i] < 255 {
			ok = true
			break
		}
	}
	if !ok {
		return json.Marshal(nil)
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(s.Signature[:]))
}

func (s *SignatureSecondGen) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	s.Signature = make([]byte, len(b))
	copy(s.Signature, b)
	return nil
}
*/

// Appendix 1 2.150
type SignatureRecordArray struct {
	RecordType  RecordType           `json:"record_type"`
	RecordSize  uint16               `json:"record_size"`
	NoOfRecords uint16               `json:"no_of_records"`
	Records     []SignatureSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.151
type SimilarEventsNumber byte

// Appendix 1 2.152
type SpecificConditionRecord struct {
	EntryTime             TimeReal              `json:"entry_time"`
	SpecificConditionType SpecificConditionType `json:"specific_condition_type"`
}

// Appendix 1 2.153
type SpecificConditionsFirstGen struct {
	Verified                 bool                      `aper:"-" json:"verified"`
	SpecificConditionRecords []SpecificConditionRecord `aper:"size=56" json:"specific_condition_records"`
}

type SpecificConditionsSecondGen struct {
	Verified                     bool                         `aper:"-" json:"verified"`
	ConditionPointerNewestRecord NoOfSpecificConditionRecords `json:"condition_pointer_newest_record"`
	SpecificConditionRecords     []SpecificConditionRecord    `aper:"size=NoOfSpecificConditionRecords" json:"specific_condition_records"`
}

// Appendix 1 2.154
type SpecificConditionType byte

// Appendix 1 2.155
type Speed byte

// Appendix 1 2.156
type SpeedAuthorised Speed

// Appendix 1 2.157
type SpeedAverage Speed

// Appendix 1 2.158
type SpeedMax Speed

// Appendix 1 2.158a
type TachographCardsGen1Suppression uint16

// Appendix 1 2.162
type TimeReal struct {
	Timedata [4]byte
}

func (t TimeReal) Decode() time.Time {
	b := bytes.NewBuffer([]byte{t.Timedata[0], t.Timedata[1], t.Timedata[2], t.Timedata[3]})
	var tVal uint32
	binary.Read(b, binary.BigEndian, &tVal)

	return time.Unix(int64(tVal), 0).UTC()
}

func (t TimeReal) MarshalJSON() ([]byte, error) {
	if (t.Timedata[0] == 0 && t.Timedata[1] == 0 && t.Timedata[2] == 0 && t.Timedata[3] == 0) || (t.Timedata[0] == 255 && t.Timedata[1] == 255 && t.Timedata[2] == 255 && t.Timedata[3] == 255) {
		return json.Marshal(nil)
	}
	return json.Marshal(t.Decode())
}

// Appendix 1 2.163
type TyreSize [15]byte

func (t TyreSize) String() string {
	return bytesToString(t[:])
}

func (t TyreSize) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(t[:]))
}

// Appendix 1 2.164
type VehicleIdentificationNumber [17]byte

func (n VehicleIdentificationNumber) String() string {
	return bytesToString(n[:])
}

func (n VehicleIdentificationNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.String())
}

func (n *VehicleIdentificationNumber) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	copy(n[:], []byte(str))
	return nil
}

// Appendix 1 2.165
type VehicleIdentificationNumberRecordArray struct {
	RecordType  RecordType                    `json:"record_type"`
	RecordSize  uint16                        `json:"record_size"`
	NoOfRecords uint16                        `json:"no_of_records"`
	Records     []VehicleIdentificationNumber `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.166
type VehicleRegistrationIdentification struct {
	VehicleRegistrationNation NationNumeric             `json:"vehicle_registration_nation"`
	VehicleRegistrationNumber VehicleRegistrationNumber `json:"vehicle_registration_number"`
}

// Appendix 1 2.166a
type VehicleRegistrationIdentificationRecordArray struct {
	RecordType  RecordType                          `json:"record_type"`
	RecordSize  uint16                              `json:"record_size"`
	NoOfRecords uint16                              `json:"no_of_records"`
	Records     []VehicleRegistrationIdentification `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.167
type VehicleRegistrationNumber struct {
	CodePage         byte
	VehicleRegNumber [13]byte
}

// Appendix 1 2.168
type VehicleRegistrationNumberRecordArray struct {
	RecordType  RecordType                  `json:"record_type"`
	RecordSize  uint16                      `json:"record_size"`
	NoOfRecords uint16                      `json:"no_of_records"`
	Records     []VehicleRegistrationNumber `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// this is a terrible hack and workaround for the difference between
// the specs (as of July 2021 -> 2nd Gen has VehicleRegistrationIdentificationRecordArray, 2nd Gen V2 has VehicleRegistrationNumberRecordArray.
// Personally, I suppose it should be the other way around.)
// and the specs (as of February 2020 -> 2nd Gen has VehicleRegistrationNumberRecordArray, 2nd Gen V2 not there yet) and the actual data
// this array is supposed to support either VehicleRegistrationNumber or VehicleRegistrationIdentification
// and it marshals to one of the two types.
type VehicleRegistrationNumberOrIdentificationRecordArray struct {
	RecordType                        RecordType                          `json:"record_type"`
	RecordSize                        uint16                              `json:"record_size"`
	NoOfRecords                       uint16                              `json:"no_of_records"`
	RecordsRegistrationNumber         []VehicleRegistrationNumber         `aper:"cond=RecordType==11,size=NoOfRecords,elementsize=RecordSize" json:"records_registration_number"`
	RecordsRegistrationIdentification []VehicleRegistrationIdentification `aper:"cond=RecordType==36,size=NoOfRecords,elementsize=RecordSize" json:"records_registration_identification"`
}

func (v VehicleRegistrationNumberOrIdentificationRecordArray) MarshalJSON() ([]byte, error) {
	switch v.RecordType {
	case RecordTypeVehicleRegistrationNumber:
		n := VehicleRegistrationNumberRecordArray{
			RecordType:  v.RecordType,
			RecordSize:  v.RecordSize,
			NoOfRecords: v.NoOfRecords,
			Records:     v.RecordsRegistrationNumber,
		}
		return json.Marshal(n)
	case RecordTypeVehicleRegistrationIdentification:
		n := VehicleRegistrationIdentificationRecordArray{
			RecordType:  v.RecordType,
			RecordSize:  v.RecordSize,
			NoOfRecords: v.NoOfRecords,
			Records:     v.RecordsRegistrationIdentification,
		}
		return json.Marshal(n)
	}
	n := VehicleRegistrationNumberRecordArray{}
	return json.Marshal(n)
	// return nil, errors.New("invalid record type")
}

// Appendix 1 2.169
type VuAbility byte

func (n VehicleRegistrationNumber) String() string {
	s, _ := decodeWithCodePage(n.CodePage, n.VehicleRegNumber[:])
	return s
}

func (n VehicleRegistrationNumber) MarshalJSON() ([]byte, error) {
	s, err := decodeWithCodePage(n.CodePage, n.VehicleRegNumber[:])
	if err != nil {
		return json.Marshal(nil)
	}
	return json.Marshal(s)
}

// Appendix 1 2.170
type VuActivityDailyDataFirstGen struct {
	NoOfActivityChanges uint16               `json:"no_of_activity_changes"`
	ActivityChangeInfo  []ActivityChangeInfo `aper:"size=NoOfActivityChanges" json:"activity_change_info"`
}

// Appendix 1 2.171
type VuActivityDailyRecordArray struct {
	RecordType  RecordType           `json:"record_type"`
	RecordSize  uint16               `json:"record_size"`
	NoOfRecords uint16               `json:"no_of_records"`
	Records     []ActivityChangeInfo `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.172
type VuApprovalNumberFirstGen [8]byte
type VuApprovalNumberSecondGen [16]byte

func (n VuApprovalNumberFirstGen) String() string {
	return bytesToString(n[:])
}

func (n VuApprovalNumberSecondGen) String() string {
	return bytesToString(n[:])
}

func (n VuApprovalNumberFirstGen) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(n[:]))
}

func (n VuApprovalNumberSecondGen) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(n[:]))
}

// Appendix 1 2.173
type VuCalibrationData struct {
	NoOfVuCalibrationRecords byte                          `json:"no_of_vu_calibration_records"`
	VuCalibrationRecords     []VuCalibrationRecordFirstGen `aper:"size=NoOfVuCalibrationRecords" json:"vu_calibration_records"`
}

// Appendix 1 2.174
type VuCalibrationRecordFirstGen struct {
	CalibrationPurpose                CalibrationPurpose                `json:"calibration_purpose"`
	WorkshopName                      Name                              `json:"workshop_name"`
	WorkshopAddress                   Address                           `json:"workshop_address"`
	WorkshopCardNumber                FullCardNumber                    `json:"workshop_card_number"`
	WorkshopCardExpiryDate            TimeReal                          `json:"workshop_card_expiry_date"`
	VehicleIdentificationNumber       VehicleIdentificationNumber       `json:"vehicle_identification_number"`
	VehicleRegistrationIdentification VehicleRegistrationIdentification `json:"vehicle_registration_identification"`
	WVehicleCharacteristicConstant    WVehicleCharacteristicConstant    `json:"w_vehicle_characteristic_constant"`
	KConstantOfRecordingEquipment     KConstantOfRecordingEquipment     `json:"k_constant_of_recording_equipment"`
	LTyreCircumference                LTyreCircumference                `json:"l_tyre_circumference"`
	TyreSize                          TyreSize                          `json:"tyre_size"`
	AuthorisedSpeed                   SpeedAuthorised                   `json:"authorised_speed"`
	OldOdometerValue                  OdometerShort                     `json:"old_odometer_value"`
	NewOdometerValue                  OdometerShort                     `json:"new_odometer_value"`
	OldTimeValue                      TimeReal                          `json:"old_time_value"`
	NewTimeValue                      TimeReal                          `json:"new_time_value"`
	NextCalibrationDate               TimeReal                          `json:"next_calibration_date"`
}

type VuCalibrationRecordSecondGen struct {
	CalibrationPurpose                CalibrationPurpose                `json:"calibration_purpose"`
	WorkshopName                      Name                              `json:"workshop_name"`
	WorkshopAddress                   Address                           `json:"workshop_address"`
	WorkshopCardNumber                FullCardNumber                    `json:"workshop_card_number"`
	WorkshopCardExpiryDate            TimeReal                          `json:"workshop_card_expiry_date"`
	VehicleIdentificationNumber       VehicleIdentificationNumber       `json:"vehicle_identification_number"`
	VehicleRegistrationIdentification VehicleRegistrationIdentification `json:"vehicle_registration_identification"`
	WVehicleCharacteristicConstant    WVehicleCharacteristicConstant    `json:"w_vehicle_characteristic_constant"`
	KConstantOfRecordingEquipment     KConstantOfRecordingEquipment     `json:"k_constant_of_recording_equipment"`
	LTyreCircumference                LTyreCircumference                `json:"l_tyre_circumference"`
	TyreSize                          TyreSize                          `json:"tyre_size"`
	AuthorisedSpeed                   SpeedAuthorised                   `json:"authorised_speed"`
	OldOdometerValue                  OdometerShort                     `json:"old_odometer_value"`
	NewOdometerValue                  OdometerShort                     `json:"new_odometer_value"`
	OldTimeValue                      TimeReal                          `json:"old_time_value"`
	NewTimeValue                      TimeReal                          `json:"new_time_value"`
	NextCalibrationDate               TimeReal                          `json:"next_calibration_date"`
	SealDataVu                        SealDataVu                        `json:"seal_data_vu"`
}

type VuCalibrationRecordSecondGenV2 struct {
	CalibrationPurpose                CalibrationPurpose                    `json:"calibration_purpose"`
	WorkshopName                      Name                                  `json:"workshop_name"`
	WorkshopAddress                   Address                               `json:"workshop_address"`
	WorkshopCardNumber                FullCardNumber                        `json:"workshop_card_number"`
	WorkshopCardExpiryDate            TimeReal                              `json:"workshop_card_expiry_date"`
	VehicleIdentificationNumber       VehicleIdentificationNumber           `json:"vehicle_identification_number"`
	VehicleRegistrationIdentification VehicleRegistrationIdentification     `json:"vehicle_registration_identification"`
	WVehicleCharacteristicConstant    WVehicleCharacteristicConstant        `json:"w_vehicle_characteristic_constant"`
	KConstantOfRecordingEquipment     KConstantOfRecordingEquipment         `json:"k_constant_of_recording_equipment"`
	LTyreCircumference                LTyreCircumference                    `json:"l_tyre_circumference"`
	TyreSize                          TyreSize                              `json:"tyre_size"`
	AuthorisedSpeed                   SpeedAuthorised                       `json:"authorised_speed"`
	OldOdometerValue                  OdometerShort                         `json:"old_odometer_value"`
	NewOdometerValue                  OdometerShort                         `json:"new_odometer_value"`
	OldTimeValue                      TimeReal                              `json:"old_time_value"`
	NewTimeValue                      TimeReal                              `json:"new_time_value"`
	NextCalibrationDate               TimeReal                              `json:"next_calibration_date"`
	SensorSerialNumber                SensorSerialNumberSecondGen           `json:"sensor_serial_number"`
	SensorGNSSSerialNumber            SensorGNSSSerialNumber                `json:"sensor_gnss_serial_number"`
	RCMSerialNumber                   RemoteCommunicationModuleSerialNumber `json:"rcm_serial_number"`
	SealDataVu                        SealDataVu                            `json:"seal_data_vu"`
	ByDefaultLoadType                 LoadType                              `json:"by_default_load_type"`
	CalibrationCountry                NationNumeric                         `json:"calibration_country"`
	CalibrationCountryTimestamp       TimeReal                              `json:"calibration_country_timestamp"`
}

// Appendix 1 2.175
type VuCalibrationRecordArray struct {
	RecordType  RecordType                     `json:"record_type"`
	RecordSize  uint16                         `json:"record_size"`
	NoOfRecords uint16                         `json:"no_of_records"`
	Records     []VuCalibrationRecordSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// not explicitely defined, but since there is a VuCalibrationRecordsSecondGenV2, we need it
type VuCalibrationRecordArrayV2 struct {
	RecordType  RecordType                       `json:"record_type"`
	RecordSize  uint16                           `json:"record_size"`
	NoOfRecords uint16                           `json:"no_of_records"`
	Records     []VuCalibrationRecordSecondGenV2 `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.176
type VuCardIWData struct {
	NoOfIWRecords   uint16                   `json:"no_of_iw_records"`
	VuCardIWRecords []VuCardIWRecordFirstGen `aper:"size=NoOfIWRecords" json:"vu_card_iw_records"`
}

// Appendix 1 2.177
type VuCardIWRecordFirstGen struct {
	CardHolderName                   HolderName                  `json:"card_holder_name"`
	FullCardNumber                   FullCardNumber              `json:"full_card_number"`
	CardExpiryDate                   TimeReal                    `json:"card_expiry_date"`
	CardInsertionTime                TimeReal                    `json:"card_insertion_time"`
	VehicleOdometerValueAtInsertion  OdometerShort               `json:"vehicle_odometer_value_at_insertion"`
	CardSlotNumber                   CardSlotNumber              `json:"card_slot_number"`
	CardWithdrawalTime               TimeReal                    `json:"card_withdrawal_time"`
	VehicleOdometerValueAtWithdrawal OdometerShort               `json:"vehicle_odometer_value_at_withdrawal"`
	PreviousVehicleInfo              PreviousVehicleInfoFirstGen `json:"previous_vehicle_info"`
	ManualInputFlag                  ManualInputFlag             `json:"manual_input_flag"`
}

type VuCardIWRecordSecondGen struct {
	CardHolderName                   HolderName                   `json:"card_holder_name"`
	FullCardNumberAndGeneration      FullCardNumberAndGeneration  `json:"full_card_number_and_generation"`
	CardExpiryDate                   TimeReal                     `json:"card_expiry_date"`
	CardInsertionTime                TimeReal                     `json:"card_insertion_time"`
	VehicleOdometerValueAtInsertion  OdometerShort                `json:"vehicle_odometer_value_at_insertion"`
	CardSlotNumber                   CardSlotNumber               `json:"card_slot_number"`
	CardWithdrawalTime               TimeReal                     `json:"card_withdrawal_time"`
	VehicleOdometerValueAtWithdrawal OdometerShort                `json:"vehicle_odometer_value_at_withdrawal"`
	PreviousVehicleInfo              PreviousVehicleInfoSecondGen `json:"previous_vehicle_info"`
	ManualInputFlag                  ManualInputFlag              `json:"manual_input_flag"`
}

// Appendix 1 2.178
type VuCardIWRecordArray struct {
	RecordType  RecordType                `json:"record_type"`
	RecordSize  uint16                    `json:"record_size"`
	NoOfRecords uint16                    `json:"no_of_records"`
	Records     []VuCardIWRecordSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.179
type VuCardRecord struct {
	CardNumberAndGenerationInformation FullCardNumberAndGeneration   `json:"card_number_and_generation_information"`
	CardExtendedSerialNumber           ExtendedSerialNumberSecondGen `json:"card_extended_serial_number"`
	CardStructureVersion               CardStructureVersion          `json:"card_stucture_version"`
	CardNumber                         CardNumber                    `json:"card_number"`
}

/* old version
type VuCardRecord struct {
	CardExtendedSerialNumber ExtendedSerialNumberSecondGen
	CardPersonaliserID       byte
	TypeOfTachographCardID   EquipmentType
	CardStructureVersion     CardStructureVersion
	CardNumber               CardNumber
}
*/

// Appendix 1 2.180
type VuCardRecordArray struct {
	RecordType  RecordType     `json:"record_type"`
	RecordSize  uint16         `json:"record_size"`
	NoOfRecords uint16         `json:"no_of_records"`
	Records     []VuCardRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.181
type VuCertificateFirstGen CertificateFirstGen
type VuCertificateSecondGen CertificateSecondGen

func (c VuCertificateFirstGen) MarshalJSON() ([]byte, error) {
	nc := CertificateFirstGen{
		Certificate: c.Certificate,
	}
	return json.Marshal(nc)
}

func (c VuCertificateSecondGen) MarshalJSON() ([]byte, error) {
	return json.Marshal(CertificateSecondGen{
		Certificate: c.Certificate,
	})
}

// Appendix 1 2.182
type VuCertificateRecordArray struct {
	RecordType  RecordType               `json:"record_type"`
	RecordSize  uint16                   `json:"record_size"`
	NoOfRecords uint16                   `json:"no_of_records"`
	Records     []VuCertificateSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.183
type VuCompanyLocksDataFirstGen struct {
	NoOfLocks             byte                           `json:"no_of_locks"`
	VuCompanyLocksRecords []VuCompanyLocksRecordFirstGen `aper:"size=NoOfLocks" json:"vu_company_locks_records"`
}

// Appendix 1 2.184
type VuCompanyLocksRecordFirstGen struct {
	LockInTime        TimeReal       `json:"lock_in_time"`
	LockOutTime       TimeReal       `json:"lock_out_time"`
	CompanyName       Name           `json:"company_name"`
	CompanyAddress    Address        `json:"company_address"`
	CompanyCardNumber FullCardNumber `json:"company_card_number"`
}

type VuCompanyLocksRecordSecondGen struct {
	LockInTime                     TimeReal                    `json:"lock_in_time"`
	LockOutTime                    TimeReal                    `json:"lock_out_time"`
	CompanyName                    Name                        `json:"company_name"`
	CompanyAddress                 Address                     `json:"company_address"`
	CompanyCardNumberAndGeneration FullCardNumberAndGeneration `json:"company_card_number_and_generation"`
}

// Appendix 1 2.185
type VuCompanyLocksRecordArray struct {
	RecordType  RecordType                      `json:"record_type"`
	RecordSize  uint16                          `json:"record_size"`
	NoOfRecords uint16                          `json:"no_of_records"`
	Records     []VuCompanyLocksRecordSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.185a
type VuConfigurationLengthRange uint16

// Appendix 1 2.186
type VuControlActivityDataFirstGen struct {
	NoOfControls             byte                              `json:"no_of_controls"`
	VuControlActivityRecords []VuControlActivityRecordFirstGen `aper:"size=NoOfControls" json:"vu_control_activity_records"`
}

// Appendix 1 2.187
type VuControlActivityRecordFirstGen struct {
	ControlType             ControlType    `json:"control_type"`
	ControlTime             TimeReal       `json:"control_time"`
	ControlCardNumber       FullCardNumber `json:"control_card_number"`
	DownloadPeriodBeginTime TimeReal       `json:"download_period_begin_time"`
	DownloadPeriodEndTime   TimeReal       `json:"download_period_end_time"`
}

type VuControlActivityRecordSecondGen struct {
	ControlType                    ControlType                 `json:"control_type"`
	ControlTime                    TimeReal                    `json:"control_time"`
	ControlCardNumberAndGeneration FullCardNumberAndGeneration `json:"control_card_number_and_generation"`
	DownloadPeriodBeginTime        TimeReal                    `json:"download_period_begin_time"`
	DownloadPeriodEndTime          TimeReal                    `json:"download_period_end_time"`
}

// Appendix 1 2.188
type VuControlActivityRecordArray struct {
	RecordType  RecordType                         `json:"record_type"`
	RecordSize  uint16                             `json:"record_size"`
	NoOfRecords uint16                             `json:"no_of_records"`
	Records     []VuControlActivityRecordSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.189
type VuDataBlockCounter BCDString

func (bc VuDataBlockCounter) Decode() (int, error) {
	// workaround since "aliased" types seem not to inherit the marshal function
	b := make(BCDString, len(bc))
	copy(b, bc)
	return b.Decode()
}

func (bc VuDataBlockCounter) MarshalJSON() ([]byte, error) {
	// workaround since "aliased" types seem not to inherit the marshal function
	b := make(BCDString, len(bc))
	copy(b, bc)
	return json.Marshal(b)
}

func (bc *VuDataBlockCounter) UnmarshalJSON(data []byte) error {
	b := make(BCDString, 2)
	err := json.Unmarshal(data, &b)
	if err != nil {
		return err
	}
	// TODO is this the correct way?
	copy(*bc, b)
	return nil
}

// Appendix 1 2.190
type VuDetailedSpeedBlock struct {
	SpeedBlockBeginDate TimeReal  `json:"speed_block_begin_date"`
	SpeedsPerSecond     [60]Speed `json:"speeds_per_second"`
}

// Appendix 1 2.191
type VuDetailedSpeedBlockRecordArray struct {
	RecordType  RecordType             `json:"record_type"`
	RecordSize  uint16                 `json:"record_size"`
	NoOfRecords uint16                 `json:"no_of_records"`
	Records     []VuDetailedSpeedBlock `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.192
type VuDetailedSpeedData struct {
	NoOfSpeedBlocks       uint16                 `json:"no_of_speed_blocks"`
	VuDetailedSpeedBlocks []VuDetailedSpeedBlock `aper:"size=NoOfSpeedBlocks" json:"vu_detailed_speed_blocks"`
}

// Appendix 1 2.192a
type VuDigitalMapVersion [12]byte

func (m VuDigitalMapVersion) String() string {
	return bytesToString(m[:])
}

func (m VuDigitalMapVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(m[:]))
}

// Appendix 1 2.193
type VuDownloadablePeriod struct {
	MinDownloadableTime TimeReal `json:"min_downloadable_time"`
	MaxDownloadableTime TimeReal `json:"max_downloadable_time"`
}

// Appendix 1 2.194
type VuDownloadablePeriodRecordArray struct {
	RecordType  RecordType             `json:"record_type"`
	RecordSize  uint16                 `json:"record_size"`
	NoOfRecords uint16                 `json:"no_of_records"`
	Records     []VuDownloadablePeriod `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.195
type VuDownloadActivityDataFirstGen struct {
	DownloadingTime       TimeReal       `json:"downloading_time"`
	FullCardNumber        FullCardNumber `json:"full_card_number"`
	CompanyOrWorkshopName Name           `json:"company_or_workshop_name"`
}

type VuDownloadActivityDataSecondGen struct {
	DownloadingTime             TimeReal                    `json:"downloading_time"`
	FullCardNumberAndGeneration FullCardNumberAndGeneration `json:"full_card_number_and_generation"`
	CompanyOrWorkshopName       Name                        `json:"company_or_workshop_name"`
}

// Appendix 1 2.196
type VuDownloadActivityDataRecordArray struct {
	RecordType  RecordType                        `json:"record_type"`
	RecordSize  uint16                            `json:"record_size"`
	NoOfRecords uint16                            `json:"no_of_records"`
	Records     []VuDownloadActivityDataSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.197
type VuEventData struct {
	NoOfVuEvents   byte                    `json:"no_of_vu_events"`
	VuEventRecords []VuEventRecordFirstGen `aper:"size=NoOfVuEvents" json:"vu_event_records"`
}

// Appendix 1 2.198
type VuEventRecordFirstGen struct {
	EventType                   EventFaultType          `json:"event_type"`
	EventRecordPurpose          EventFaultRecordPurpose `json:"event_record_purpose"`
	EventBeginTime              TimeReal                `json:"event_begin_time"`
	EventEndTime                TimeReal                `json:"event_end_time"`
	CardNumberDriverSlotBegin   FullCardNumber          `json:"card_number_driver_slot_begin"`
	CardNumberCodriverSlotBegin FullCardNumber          `json:"card_number_codriver_slot_begin"`
	CardNumberDriverSlotEnd     FullCardNumber          `json:"card_number_driver_slot_end"`
	CardNumberCodriverSlotEnd   FullCardNumber          `json:"card_number_codriver_slot_end"`
	SimilarEventsNumber         SimilarEventsNumber     `json:"similar_events_number"`
}

type VuEventRecordSecondGen struct {
	EventType                          EventFaultType                     `json:"event_type"`
	EventRecordPurpose                 EventFaultRecordPurpose            `json:"event_record_purpose"`
	EventBeginTime                     TimeReal                           `json:"event_begin_time"`
	EventEndTime                       TimeReal                           `json:"event_end_time"`
	CardNumberAndGenDriverSlotBegin    FullCardNumberAndGeneration        `json:"card_number_and_gen_driver_slot_begin"`
	CardNumberAndGenCodriverSlotBegin  FullCardNumberAndGeneration        `json:"card_number_and_gen_codriver_slot_begin"`
	CardNumberAndGenDriverSlotEnd      FullCardNumberAndGeneration        `json:"card_number_and_gen_driver_slot_end"`
	CardNumberAndGenCodriverSlotEnd    FullCardNumberAndGeneration        `json:"card_number_and_gen_codriver_slot_end"`
	SimilarEventsNumber                SimilarEventsNumber                `json:"similar_events_number"`
	ManufacturerSpecificEventFaultData ManufacturerSpecificEventFaultData `json:"manufacturer_specific_event_fault_data"`
}

// Appendix 1 2.199
type VuEventRecordArray struct {
	RecordType  RecordType               `json:"record_type"`
	RecordSize  uint16                   `json:"record_size"`
	NoOfRecords uint16                   `json:"no_of_records"`
	Records     []VuEventRecordSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.200
type VuFaultData struct {
	NoOfVuFaults   byte                    `json:"no_of_vu_faults"`
	VuFaultRecords []VuFaultRecordFirstGen `aper:"size=NoOfVuFaults" json:"vu_fault_records"`
}

// Appendix 1 2.201
type VuFaultRecordFirstGen struct {
	FaultType                   EventFaultType          `json:"fault_type"`
	FaultRecordPurpose          EventFaultRecordPurpose `json:"fault_record_purpose"`
	FaultBeginTime              TimeReal                `json:"fault_begin_time"`
	FaultEndTime                TimeReal                `json:"fault_end_time"`
	CardNumberDriverSlotBegin   FullCardNumber          `json:"card_number_driver_slot_begin"`
	CardNumberCodriverSlotBegin FullCardNumber          `json:"card_number_codriver_slot_begin"`
	CardNumberDriverSlotEnd     FullCardNumber          `json:"card_number_driver_slot_end"`
	CardNumberCodriverSlotEnd   FullCardNumber          `json:"card_number_codriver_slot_end"`
}

type VuFaultRecordSecondGen struct {
	FaultType                          EventFaultType                     `json:"fault_type"`
	FaultRecordPurpose                 EventFaultRecordPurpose            `json:"fault_record_purpose"`
	FaultBeginTime                     TimeReal                           `json:"fault_begin_time"`
	FaultEndTime                       TimeReal                           `json:"fault_end_time"`
	CardNumberAndGenDriverSlotBegin    FullCardNumberAndGeneration        `json:"card_number_and_gen_driver_slot_begin"`
	CardNumberAndGenCodriverSlotBegin  FullCardNumberAndGeneration        `json:"card_number_and_gen_codriver_slot_begin"`
	CardNumberAndGenDriverSlotEnd      FullCardNumberAndGeneration        `json:"card_number_and_gen_driver_slot_end"`
	CardNumberAndGenCodriverSlotEnd    FullCardNumberAndGeneration        `json:"card_number_and_gen_codriver_slot_end"`
	ManufacturerSpecificEventFaultData ManufacturerSpecificEventFaultData `json:"manufacturer_specific_event_fault_data"`
}

// Appendix 1 2.202
type VuFaultRecordArray struct {
	RecordType  RecordType               `json:"record_type"`
	RecordSize  uint16                   `json:"record_size"`
	NoOfRecords uint16                   `json:"no_of_records"`
	Records     []VuFaultRecordSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.203
type VuGNSSADRecord struct {
	TimeStamp                    TimeReal                    `json:"time_stamp"`
	CardNumberAndGenDriverSlot   FullCardNumberAndGeneration `json:"card_number_and_gen_driver_slot"`
	CardNumberAndGenCodriverSlot FullCardNumberAndGeneration `json:"card_number_and_gen_codriver_slot"`
	GNSSPlaceRecord              GNSSPlaceRecord             `json:"gnss_place_record"`
	VehicleOdometerValue         OdometerShort               `json:"vehicle_odometer_value"` // addition from correction document
}

type VuGNSSADRecordV2 struct {
	TimeStamp                    TimeReal                    `json:"time_stamp"`
	CardNumberAndGenDriverSlot   FullCardNumberAndGeneration `json:"card_number_and_gen_driver_slot"`
	CardNumberAndGenCodriverSlot FullCardNumberAndGeneration `json:"card_number_and_gen_codriver_slot"`
	GNSSPlaceAuthRecord          GNSSPlaceAuthRecord         `json:"gnss_place_auth_record"`
	VehicleOdometerValue         OdometerShort               `json:"vehicle_odometer_value"` // addition from correction document
}

// Appendix 1 2.203a
type VuBorderCrossingRecord struct {
	CardNumberAndGenDriverSlot   FullCardNumberAndGeneration `json:"card_number_and_gen_driver_slot"`
	CardNumberAndGenCodriverSlot FullCardNumberAndGeneration `json:"card_number_and_gen_codriver_slot"`
	CountryLeft                  NationNumeric               `json:"country_left"`
	CountryEntered               NationNumeric               `json:"country_entered"`
	GNSSPlaceAuthRecord          GNSSPlaceAuthRecord         `json:"gnss_place_auth_record"`
	VehicleOdometerValue         OdometerShort               `json:"vehicle_odometer_value"`
}

// Appendix 1 2.203b
type VuBorderCrossingRecordArray struct {
	RecordType  RecordType               `json:"record_type"`
	RecordSize  uint16                   `json:"record_size"`
	NoOfRecords uint16                   `json:"no_of_records"`
	Records     []VuBorderCrossingRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.204
type VuGNSSADRecordArray struct {
	RecordType  RecordType       `json:"record_type"`
	RecordSize  uint16           `json:"record_size"`
	NoOfRecords uint16           `json:"no_of_records"`
	Records     []VuGNSSADRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// not explicitely mentioned, but VuGNSSADRecordV2 exists
type VuGNSSADRecordArrayV2 struct {
	RecordType  RecordType         `json:"record_type"`
	RecordSize  uint16             `json:"record_size"`
	NoOfRecords uint16             `json:"no_of_records"`
	Records     []VuGNSSADRecordV2 `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.204a
type VuGNSSMaximalTimeDifference uint16

// Appendix 1 2.205
type VuIdentificationFirstGen struct {
	VuManufacturerName       VuManufacturerName       `json:"vu_manufacturer_name"`
	VuManufacturerAddress    VuManufacturerAddress    `json:"vu_manufacturer_address"`
	VuPartNumber             VuPartNumber             `json:"vu_part_number"`
	VuSerialNumber           VuSerialNumberFirstGen   `json:"vu_serial_number"`
	VuSoftwareIdentification VuSoftwareIdentification `json:"vu_software_identification"`
	VuManufacturingDate      VuManufacturingDate      `json:"vu_manufacturing_date"`
	VuApprovalNumber         VuApprovalNumberFirstGen `json:"vu_approval_number"`
}

type VuIdentificationSecondGen struct {
	VuManufacturerName       VuManufacturerName        `json:"vu_manufacturer_name"`
	VuManufacturerAddress    VuManufacturerAddress     `json:"vu_manufacturer_address"`
	VuPartNumber             VuPartNumber              `json:"vu_part_number"`
	VuSerialNumber           VuSerialNumberSecondGen   `json:"vu_serial_number"`
	VuSoftwareIdentification VuSoftwareIdentification  `json:"vu_software_identification"`
	VuManufacturingDate      VuManufacturingDate       `json:"vu_manufacturing_date"`
	VuApprovalNumber         VuApprovalNumberSecondGen `json:"vu_approval_number"`
	VuGeneration             Generation                `json:"vu_generation"`
	VuAbility                VuAbility                 `json:"vu_ability"`
}

type VuIdentificationSecondGenV2 struct {
	VuManufacturerName       VuManufacturerName        `json:"vu_manufacturer_name"`
	VuManufacturerAddress    VuManufacturerAddress     `json:"vu_manufacturer_address"`
	VuPartNumber             VuPartNumber              `json:"vu_part_number"`
	VuSerialNumber           VuSerialNumberSecondGen   `json:"vu_serial_number"`
	VuSoftwareIdentification VuSoftwareIdentification  `json:"vu_software_identification"`
	VuManufacturingDate      VuManufacturingDate       `json:"vu_manufacturing_date"`
	VuApprovalNumber         VuApprovalNumberSecondGen `json:"vu_approval_number"`
	VuGeneration             Generation                `json:"vu_generation"`
	VuAbility                VuAbility                 `json:"vu_ability"`
	VuDigitalMapVersion      VuDigitalMapVersion       `json:"vu_digital_map_version"`
}

// Appendix 1 2.206
type VuIdentificationRecordArray struct {
	RecordType  RecordType                  `json:"record_type"`
	RecordSize  uint16                      `json:"record_size"`
	NoOfRecords uint16                      `json:"no_of_records"`
	Records     []VuIdentificationSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// not explicitely listed, but required since the is a "V2" version
type VuIdentificationRecordArrayV2 struct {
	RecordType  RecordType                    `json:"record_type"`
	RecordSize  uint16                        `json:"record_size"`
	NoOfRecords uint16                        `json:"no_of_records"`
	Records     []VuIdentificationSecondGenV2 `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.207
type VuITSConsentRecord struct {
	CardNumberAndGen FullCardNumberAndGeneration `json:"card_number_and_gen"`
	Consent          byte                        `json:"consent"` // boolean
}

// Appendix 1 2.208
type VuITSConsentRecordArray struct {
	RecordType  RecordType           `json:"record_type"`
	RecordSize  uint16               `json:"record_size"`
	NoOfRecords uint16               `json:"no_of_records"`
	Records     []VuITSConsentRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.208a
type VuLoadUnloadRecord struct {
	TimeStamp                    TimeReal                    `json:"time_stamp"`
	OperationType                OperationType               `json:"operation_type"`
	CardNumberAndGenDriverSlot   FullCardNumberAndGeneration `json:"card_number_and_gen_driver_slot"`
	CardNumberAndGenCodriverSlot FullCardNumberAndGeneration `json:"card_number_and_gen_codriver_slot"`
	GNSSPlaceAuthRecord          GNSSPlaceAuthRecord         `json:"gnss_place_auth_record"`
	VehicleOdometerValue         OdometerShort               `json:"vehicle_odometer_value"`
}

// Appendix 1 2.208b
type VuLoadUnloadRecordArray struct {
	RecordType  RecordType           `json:"record_type"`
	RecordSize  uint16               `json:"record_size"`
	NoOfRecords uint16               `json:"no_of_records"`
	Records     []VuLoadUnloadRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.209
type VuManufacturerAddress Address

func (a VuManufacturerAddress) String() string {
	ad := Address{
		CodePage: a.CodePage,
		Address:  a.Address,
	}
	return ad.String()
}

func (a VuManufacturerAddress) MarshalJSON() ([]byte, error) {
	ad := Address{
		CodePage: a.CodePage,
		Address:  a.Address,
	}
	return json.Marshal(ad)
}

// Appendix 1 2.210
type VuManufacturerName Name

func (n VuManufacturerName) String() string {
	na := Name{
		CodePage: n.CodePage,
		Name:     n.Name,
	}
	return na.String()
}

func (n VuManufacturerName) MarshalJSON() ([]byte, error) {
	na := Name{
		CodePage: n.CodePage,
		Name:     n.Name,
	}
	return json.Marshal(na)
}

// Appendix 1 2.211
type VuManufacturingDate TimeReal

func (d VuManufacturingDate) Decode() time.Time {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return r.Decode()
}

func (d VuManufacturingDate) MarshalJSON() ([]byte, error) {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return json.Marshal(r)
}

// Appendix 1 2.212
type VuOverSpeedingControlData struct {
	LastOverspeedControlTime TimeReal        `json:"last_overspeed_control_time"`
	FirstOverspeedSince      TimeReal        `json:"first_overspeed_since"`
	NumberOfOverspeedSince   OverspeedNumber `json:"number_of_overspeed_since"`
}

// Appendix 1 2.213
type VuOverSpeedingControlDataRecordArray struct {
	RecordType  RecordType                  `json:"record_type"`
	RecordSize  uint16                      `json:"record_size"`
	NoOfRecords uint16                      `json:"no_of_records"`
	Records     []VuOverSpeedingControlData `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.214
type VuOverSpeedingEventData struct {
	NoOfOvVuOverSpeedingEvents byte                                `json:"no_of_vu_over_speeding_events"`
	VuOverSpeedingEventRecords []VuOverSpeedingEventRecordFirstGen `aper:"size=NoOfOvVuOverSpeedingEvents" json:"vu_over_speeding_event_records"`
}

// Appendix 1 2.215
type VuOverSpeedingEventRecordFirstGen struct {
	EventType                 EventFaultType          `json:"event_type"`
	EventRecordPurpose        EventFaultRecordPurpose `json:"event_record_purpose"`
	EventBeginTime            TimeReal                `json:"event_begin_time"`
	EventEndTime              TimeReal                `json:"event_end_time"`
	MaxSpeedValue             SpeedMax                `json:"max_speed_value"`
	AverageSpeedValue         SpeedAverage            `json:"average_speed_value"`
	CardNumberDriverSlotBegin FullCardNumber          `json:"card_number_driver_slot_begin"`
	SimilarEventsNumber       SimilarEventsNumber     `json:"similar_events_number"`
}

type VuOverSpeedingEventRecordSecondGen struct {
	EventType                       EventFaultType              `json:"event_type"`
	EventRecordPurpose              EventFaultRecordPurpose     `json:"event_record_purpose"`
	EventBeginTime                  TimeReal                    `json:"event_begin_time"`
	EventEndTime                    TimeReal                    `json:"event_end_time"`
	MaxSpeedValue                   SpeedMax                    `json:"max_speed_value"`
	AverageSpeedValue               SpeedAverage                `json:"average_speed_value"`
	CardNumberAndGenDriverSlotBegin FullCardNumberAndGeneration `json:"card_number_and_gen_driver_slot_begin"`
	SimilarEventsNumber             SimilarEventsNumber         `json:"similar_events_number"`
}

// Appendix 1 2.216
type VuOverSpeedingEventRecordArray struct {
	RecordType  RecordType                           `json:"record_type"`
	RecordSize  uint16                               `json:"record_size"`
	NoOfRecords uint16                               `json:"no_of_records"`
	Records     []VuOverSpeedingEventRecordSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.217
type VuPartNumber [16]byte

func (n VuPartNumber) String() string {
	return bytesToString(n[:])
}

func (n VuPartNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(bytesToString(n[:]))
}

// Appendix 1 2.218
type VuPlaceDailyWorkPeriodDataFirstGen struct {
	NoOfPlaceRecords              byte                                   `json:"no_of_place_records"`
	VuPlaceDailyWorkPeriodRecords []VuPlaceDailyWorkPeriodRecordFirstGen `aper:"size=NoOfPlaceRecords" json:"vu_place_daily_work_period_records"`
}

// Appendix 1 2.219
type VuPlaceDailyWorkPeriodRecordFirstGen struct {
	FullCardNumber FullCardNumber      `json:"full_card_number"`
	PlaceRecord    PlaceRecordFirstGen `json:"place_record"`
}

type VuPlaceDailyWorkPeriodRecordSecondGen struct {
	FullCardNumberAndGeneration FullCardNumberAndGeneration `json:"full_card_number_and_generation"`
	PlaceRecord                 PlaceRecordSecondGen        `json:"place_record"`
}

type VuPlaceDailyWorkPeriodRecordSecondGenV2 struct {
	FullCardNumberAndGeneration FullCardNumberAndGeneration `json:"full_card_number_and_generation"`
	PlaceAuthRecord             PlaceAuthRecord             `json:"place_auth_record"`
}

// Appendix 1 2.220
type VuPlaceDailyWorkPeriodRecordArray struct {
	RecordType  RecordType                              `json:"record_type"`
	RecordSize  uint16                                  `json:"record_size"`
	NoOfRecords uint16                                  `json:"no_of_records"`
	Records     []VuPlaceDailyWorkPeriodRecordSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// not explicitely mentioned, but VuPlaceDailyWorkPeriodRecordSecondGenV2 exists
type VuPlaceDailyWorkPeriodRecordArrayV2 struct {
	RecordType  RecordType                                `json:"record_type"`
	RecordSize  uint16                                    `json:"record_size"`
	NoOfRecords uint16                                    `json:"no_of_records"`
	Records     []VuPlaceDailyWorkPeriodRecordSecondGenV2 `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.222a
type VuRtcTime TimeReal

// Appendix 1 2.223
type VuSerialNumberFirstGen ExtendedSerialNumberFirstGen
type VuSerialNumberSecondGen ExtendedSerialNumberSecondGen

// Appendix 1 2.224
type VuSoftInstallationDate TimeReal

func (d VuSoftInstallationDate) Decode() time.Time {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return r.Decode()
}

func (d VuSoftInstallationDate) MarshalJSON() ([]byte, error) {
	// workaround
	r := new(TimeReal)
	r.Timedata[0] = d.Timedata[0]
	r.Timedata[1] = d.Timedata[1]
	r.Timedata[2] = d.Timedata[2]
	r.Timedata[3] = d.Timedata[3]
	return json.Marshal(r)
}

// Appendix 1 2.225
type VuSoftwareIdentification struct {
	VuSoftwareVersion      VuSoftwareVersion      `json:"vu_software_version"`
	VuSoftInstallationDate VuSoftInstallationDate `json:"vu_soft_installation_date"`
}

// Appendix 1 2.226
type VuSoftwareVersion [4]byte

// Appendix 1 2.227
type VuSpecificConditionDataFirstGen struct {
	NoOfSpecificConditionRecords uint16                    `json:"no_of_specific_condition_records"`
	SpecificConditionRecords     []SpecificConditionRecord `aper:"size=NoOfSpecificConditionRecords" json:"specific_condition_records"`
}

// Appendix 1 2.228
type VuSpecificConditionRecordArray struct {
	RecordType  RecordType                `json:"record_type"`
	RecordSize  uint16                    `json:"record_size"`
	NoOfRecords uint16                    `json:"no_of_records"`
	Records     []SpecificConditionRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.229
type VuTimeAdjustmentData struct {
	NoOfVuTimeAdjRecords    byte                             `json:"no_of_vu_time_adj_records"`
	VuTimeAdjustmentRecords []VuTimeAdjustmentRecordFirstGen `aper:"size=NoOfVuTimeAdjRecords" json:"vu_time_adjustment_records"`
}

/*
// is now "reserved for future use"
// Appendix 1 2.230
type VuTimeAdjustmentGNSSRecord struct {
	OldTimeValue TimeReal `json:"old_time_value"`
	NewTimeValue TimeReal `json:"new_time_value"`
}

// Appendix 1 2.231
type VuTimeAdjustmentGNSSRecordArray struct {
	RecordType  RecordType                   `aper:"expected=0x1d" json:"record_type"`
	RecordSize  uint16                       `json:"record_size"`
	NoOfRecords uint16                       `json:"no_of_records"`
	Records     []VuTimeAdjustmentGNSSRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}
*/

// Appendix 1 2.232
type VuTimeAdjustmentRecordFirstGen struct {
	OldTimeValue       TimeReal       `json:"old_time_value"`
	NewTimeValue       TimeReal       `json:"new_time_value"`
	WorkshopName       Name           `json:"workshop_name"`
	WorkshopAddress    Address        `json:"workshop_address"`
	WorkshopCardNumber FullCardNumber `json:"workshop_card_number"`
}

type VuTimeAdjustmentRecordSecondGen struct {
	OldTimeValue                    TimeReal                    `json:"old_time_value"`
	NewTimeValue                    TimeReal                    `json:"new_time_value"`
	WorkshopName                    Name                        `json:"workshop_name"`
	WorkshopAddress                 Address                     `json:"workshop_address"`
	WorkshopCardNumberAndGeneration FullCardNumberAndGeneration `json:"workshop_card_number_and_generation"`
}

// Appendix 1 2.233
type VuTimeAdjustmentRecordArray struct {
	RecordType  RecordType                        `aper:"expected=0x1e" json:"record_type"`
	RecordSize  uint16                            `json:"record_size"`
	NoOfRecords uint16                            `json:"no_of_records"`
	Records     []VuTimeAdjustmentRecordSecondGen `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.239
type WVehicleCharacteristicConstant uint16

// Appendix 1 2.240
type VuPowerSupplyInterruptionRecord struct {
	EventType                         EventFaultType              `json:"event_type"`
	EventRecordPurpose                EventFaultRecordPurpose     `json:"event_record_purpose"`
	EventBeginTime                    TimeReal                    `json:"event_begin_time"`
	EventEndTime                      TimeReal                    `json:"event_end_time"`
	CardNumberAndGenDriverSlotBegin   FullCardNumberAndGeneration `json:"card_number_and_gen_driver_slot_begin"`
	CardNumberAndGenDriverSlotEnd     FullCardNumberAndGeneration `json:"card_number_and_gen_driver_slot_end"`
	CardNumberAndGenCodriverSlotBegin FullCardNumberAndGeneration `json:"card_number_and_gen_codriver_slot_begin"`
	CardNumberAndGenCodriverSlotEnd   FullCardNumberAndGeneration `json:"card_number_and_gen_codriver_slot_end"`
	SimilarEventsNumber               SimilarEventsNumber         `json:"similar_events_number"`
}

// Appendix 1 2.241
type VuPowerSupplyInterruptionRecordArray struct {
	RecordType  RecordType                        `json:"record_type"`
	RecordSize  uint16                            `json:"record_size"`
	NoOfRecords uint16                            `json:"no_of_records"`
	Records     []VuPowerSupplyInterruptionRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.242
type VuSensorExternalGNSSCoupledRecordArray struct {
	RecordType  RecordType                        `json:"record_type"`
	RecordSize  uint16                            `json:"record_size"`
	NoOfRecords uint16                            `json:"no_of_records"`
	Records     []SensorExternalGNSSCoupledRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// Appendix 1 2.243
type VuSensorPairedRecordArray struct {
	RecordType  RecordType           `json:"record_type"`
	RecordSize  uint16               `json:"record_size"`
	NoOfRecords uint16               `json:"no_of_records"`
	Records     []SensorPairedRecord `aper:"size=NoOfRecords,elementsize=RecordSize" json:"records"`
}

// global map of all decoded certificates by the key identification
var PKsFirstGen = make(map[uint64]DecodedCertificateFirstGen)
var PKsSecondGen = make(map[uint64]DecodedCertificateSecondGen)
