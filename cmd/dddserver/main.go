package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	consul "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-sockaddr/template"
	_ "github.com/traconiq/tachoparser/internal/pkg/certificates"
	"github.com/traconiq/tachoparser/pkg/decoder"
	pb "github.com/traconiq/tachoparser/pkg/proto"
	"google.golang.org/grpc"
	"gopkg.in/alexcesaro/statsd.v2"
)

var (
	listen     = flag.String("listen", ":50055", "Listen address for grpc service")
	statsdAddr = flag.String("statsd", "", "The address of the statsd server to use")
)

type server struct {
	pb.UnimplementedDDDParserServer
	statsdClient *statsd.Client
}

// global lock. only 1 parsing at a time...
var mutex sync.Mutex

func (s *server) ParseVu(ctx context.Context, req *pb.ParseVuRequest) (*pb.ParseVuResponse, error) {
	mutex.Lock()
	defer mutex.Unlock()
	var v decoder.Vu
	_, err := decoder.UnmarshalTV(req.Data, &v)
	if err != nil {
		log.Printf("error: could not parse vu data: %v", err)
		return nil, err
	}
	vuOverview1MemberStateCertificate := &pb.CertificateFirstGen{}
	vuOverview1MemberStateCertificate.Certificate = v.VuOverviewFirstGen.MemberStateCertificate.Certificate[:]
	vuOverview1MemberStateCertificate.DecodedCertificate = &pb.DecodedCertificateFirstGen{}
	if v.VuOverviewFirstGen.MemberStateCertificate.DecodedCertificate != nil {
		vuOverview1MemberStateCertificate.DecodedCertificate.CertificateHolderReference = v.VuOverviewFirstGen.MemberStateCertificate.DecodedCertificate.CertificateHolderReference
		vuOverview1MemberStateCertificate.DecodedCertificate.CertificateAuthorityReference = v.VuOverviewFirstGen.MemberStateCertificate.DecodedCertificate.CertificateAuthorityReference
		vuOverview1MemberStateCertificate.DecodedCertificate.EndOfValidity = v.VuOverviewFirstGen.MemberStateCertificate.DecodedCertificate.EndOfValidity.Unix()
		if v.VuOverviewFirstGen.MemberStateCertificate.DecodedCertificate.RsaModulus != nil && v.VuOverviewFirstGen.MemberStateCertificate.DecodedCertificate.RsaExponent != nil {
			vuOverview1MemberStateCertificate.DecodedCertificate.RsaModulus = v.VuOverviewFirstGen.MemberStateCertificate.DecodedCertificate.RsaModulus.String()
			vuOverview1MemberStateCertificate.DecodedCertificate.RsaExponent = v.VuOverviewFirstGen.MemberStateCertificate.DecodedCertificate.RsaExponent.String()
		}
	}
	vuOverview1VuCertificate := &pb.CertificateFirstGen{}
	vuOverview1VuCertificate.Certificate = v.VuOverviewFirstGen.VuCertificate.Certificate[:]
	vuOverview1VuCertificate.DecodedCertificate = &pb.DecodedCertificateFirstGen{}
	if v.VuOverviewFirstGen.VuCertificate.DecodedCertificate != nil {
		vuOverview1VuCertificate.DecodedCertificate.CertificateHolderReference = v.VuOverviewFirstGen.VuCertificate.DecodedCertificate.CertificateHolderReference
		vuOverview1VuCertificate.DecodedCertificate.CertificateAuthorityReference = v.VuOverviewFirstGen.VuCertificate.DecodedCertificate.CertificateAuthorityReference
		vuOverview1VuCertificate.DecodedCertificate.EndOfValidity = v.VuOverviewFirstGen.VuCertificate.DecodedCertificate.EndOfValidity.Unix()
		if v.VuOverviewFirstGen.VuCertificate.DecodedCertificate.RsaModulus != nil && v.VuOverviewFirstGen.VuCertificate.DecodedCertificate.RsaExponent != nil {
			vuOverview1VuCertificate.DecodedCertificate.RsaModulus = v.VuOverviewFirstGen.VuCertificate.DecodedCertificate.RsaModulus.String()
			vuOverview1VuCertificate.DecodedCertificate.RsaExponent = v.VuOverviewFirstGen.VuCertificate.DecodedCertificate.RsaExponent.String()
		}
	}
	vuOverviewFirstGenVuCompanyLocksRecords := make([]*pb.VuCompanyLocksRecordFirstGen, len(v.VuOverviewFirstGen.VuCompanyLocksData.VuCompanyLocksRecords))
	for i, l := range v.VuOverviewFirstGen.VuCompanyLocksData.VuCompanyLocksRecords {
		vuOverviewFirstGenVuCompanyLocksRecords[i] = &pb.VuCompanyLocksRecordFirstGen{
			LockInTime:     l.LockInTime.Decode().Unix(),
			LockOutTime:    l.LockOutTime.Decode().Unix(),
			CompanyName:    l.CompanyName.String(),
			CompanyAddress: l.CompanyAddress.String(),
			CompanyCardNumber: &pb.FullCardNumber{
				CardType:               uint32(l.CompanyCardNumber.CardType),
				CardIssuingMemberState: uint32(l.CompanyCardNumber.CardIssuingMemberState),
				CardNumber:             l.CompanyCardNumber.CardNumber.String(),
			},
		}
	}
	vuOverviewFirstGenVuControlActivityRecords := make([]*pb.VuControlActivityRecordFirstGen, len(v.VuOverviewFirstGen.VuControlActivityData.VuControlActivityRecords))
	for i, c := range v.VuOverviewFirstGen.VuControlActivityData.VuControlActivityRecords {
		vuOverviewFirstGenVuControlActivityRecords[i] = &pb.VuControlActivityRecordFirstGen{
			ControlType: uint32(c.ControlType),
			ControlTime: c.ControlTime.Decode().Unix(),
			ControlCardNumber: &pb.FullCardNumber{
				CardType:               uint32(c.ControlCardNumber.CardType),
				CardIssuingMemberState: uint32(c.ControlCardNumber.CardIssuingMemberState),
				CardNumber:             c.ControlCardNumber.CardNumber.String(),
			},
			DownloadPeriodBeginTime: c.DownloadPeriodBeginTime.Decode().Unix(),
			DownloadPeriodEndTime:   c.DownloadPeriodEndTime.Decode().Unix(),
		}
	}
	vuOverview2MemberStateCertificateRecords := make([]*pb.CertificateSecondGen, len(v.VuOverviewSecondGen.MemberStateCertificateRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.MemberStateCertificateRecordArray.Records {
		decodedCertificate := &pb.DecodedCertificateSecondGen{}
		if r.DecodedCertificate != nil {
			decodedCertificate.CertificateBody = &pb.DecodedCertificateSecondGen_CertificateBody{
				CertificateProfileIdentifier:   uint32(r.DecodedCertificate.CertificateBody.CertificateProfileIdentifier),
				CertificateAuthorityReference:  r.DecodedCertificate.CertificateBody.CertificateAuthorityReference,
				CertificateHolderAuthorisation: r.DecodedCertificate.CertificateBody.CertificateHolderAuthorisation[:],
				PublicKey:                      &pb.DecodedCertificateSecondGen_CertificateBody_PublicKey{},
				CertificateHolderReference:     r.DecodedCertificate.CertificateBody.CertificateHolderReference,
				CertificateEffectiveDate:       r.DecodedCertificate.CertificateBody.CertificateEffectiveDate.Unix(),
				CertificateExpirationDate:      r.DecodedCertificate.CertificateBody.CertificateExpirationDate.Unix(),
			}
			decodedCertificate.CertificateBody.PublicKey.DomainParameters = make([]int64, len(r.DecodedCertificate.CertificateBody.PublicKey.DomainParameters))
			for i, dp := range r.DecodedCertificate.CertificateBody.PublicKey.DomainParameters {
				decodedCertificate.CertificateBody.PublicKey.DomainParameters[i] = int64(dp)
			}
			if r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.X != nil && r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.Y != nil {
				decodedCertificate.CertificateBody.PublicKey.PublicPoint.X = r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.X.String()
				decodedCertificate.CertificateBody.PublicKey.PublicPoint.Y = r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.Y.String()
			}
			if r.DecodedCertificate.ECCCertificateSignature.R != nil && r.DecodedCertificate.ECCCertificateSignature.S != nil {
				decodedCertificate.EccCertificateSignature = &pb.DecodedCertificateSecondGen_ECCCertificateSignature{
					R: r.DecodedCertificate.ECCCertificateSignature.R.String(),
					S: r.DecodedCertificate.ECCCertificateSignature.S.String(),
				}
			}
			decodedCertificate.Valid = r.DecodedCertificate.Valid
		}
		vuOverview2MemberStateCertificateRecords[i] = &pb.CertificateSecondGen{
			Certificate:        r.Certificate,
			DecodedCertificate: decodedCertificate,
		}
	}
	vuOverview2MemberStateCertificateRecordsV2 := make([]*pb.CertificateSecondGen, len(v.VuOverviewSecondGenV2.MemberStateCertificateRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.MemberStateCertificateRecordArray.Records {
		decodedCertificate := &pb.DecodedCertificateSecondGen{}
		if r.DecodedCertificate != nil {
			decodedCertificate.CertificateBody = &pb.DecodedCertificateSecondGen_CertificateBody{
				CertificateProfileIdentifier:   uint32(r.DecodedCertificate.CertificateBody.CertificateProfileIdentifier),
				CertificateAuthorityReference:  r.DecodedCertificate.CertificateBody.CertificateAuthorityReference,
				CertificateHolderAuthorisation: r.DecodedCertificate.CertificateBody.CertificateHolderAuthorisation[:],
				PublicKey:                      &pb.DecodedCertificateSecondGen_CertificateBody_PublicKey{},
				CertificateHolderReference:     r.DecodedCertificate.CertificateBody.CertificateHolderReference,
				CertificateEffectiveDate:       r.DecodedCertificate.CertificateBody.CertificateEffectiveDate.Unix(),
				CertificateExpirationDate:      r.DecodedCertificate.CertificateBody.CertificateExpirationDate.Unix(),
			}
			decodedCertificate.CertificateBody.PublicKey.DomainParameters = make([]int64, len(r.DecodedCertificate.CertificateBody.PublicKey.DomainParameters))
			for i, dp := range r.DecodedCertificate.CertificateBody.PublicKey.DomainParameters {
				decodedCertificate.CertificateBody.PublicKey.DomainParameters[i] = int64(dp)
			}
			if r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.X != nil && r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.Y != nil {
				decodedCertificate.CertificateBody.PublicKey.PublicPoint.X = r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.X.String()
				decodedCertificate.CertificateBody.PublicKey.PublicPoint.Y = r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.Y.String()
			}
			if r.DecodedCertificate.ECCCertificateSignature.R != nil && r.DecodedCertificate.ECCCertificateSignature.S != nil {
				decodedCertificate.EccCertificateSignature = &pb.DecodedCertificateSecondGen_ECCCertificateSignature{
					R: r.DecodedCertificate.ECCCertificateSignature.R.String(),
					S: r.DecodedCertificate.ECCCertificateSignature.S.String(),
				}
			}
			decodedCertificate.Valid = r.DecodedCertificate.Valid
		}
		vuOverview2MemberStateCertificateRecordsV2[i] = &pb.CertificateSecondGen{
			Certificate:        r.Certificate,
			DecodedCertificate: decodedCertificate,
		}
	}
	vuOverview2VuCertificateRecords := make([]*pb.CertificateSecondGen, len(v.VuOverviewSecondGen.VuCertificateRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.VuCertificateRecordArray.Records {
		decodedCertificate := &pb.DecodedCertificateSecondGen{}
		if r.DecodedCertificate != nil {
			decodedCertificate.CertificateBody = &pb.DecodedCertificateSecondGen_CertificateBody{
				CertificateProfileIdentifier:   uint32(r.DecodedCertificate.CertificateBody.CertificateProfileIdentifier),
				CertificateAuthorityReference:  r.DecodedCertificate.CertificateBody.CertificateAuthorityReference,
				CertificateHolderAuthorisation: r.DecodedCertificate.CertificateBody.CertificateHolderAuthorisation[:],
				PublicKey:                      &pb.DecodedCertificateSecondGen_CertificateBody_PublicKey{},
				CertificateHolderReference:     r.DecodedCertificate.CertificateBody.CertificateHolderReference,
				CertificateEffectiveDate:       r.DecodedCertificate.CertificateBody.CertificateEffectiveDate.Unix(),
				CertificateExpirationDate:      r.DecodedCertificate.CertificateBody.CertificateExpirationDate.Unix(),
			}
			decodedCertificate.CertificateBody.PublicKey.DomainParameters = make([]int64, len(r.DecodedCertificate.CertificateBody.PublicKey.DomainParameters))
			for i, dp := range r.DecodedCertificate.CertificateBody.PublicKey.DomainParameters {
				decodedCertificate.CertificateBody.PublicKey.DomainParameters[i] = int64(dp)
			}
			if r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.X != nil && r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.Y != nil {
				decodedCertificate.CertificateBody.PublicKey.PublicPoint.X = r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.X.String()
				decodedCertificate.CertificateBody.PublicKey.PublicPoint.Y = r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.Y.String()
			}
			if r.DecodedCertificate.ECCCertificateSignature.R != nil && r.DecodedCertificate.ECCCertificateSignature.S != nil {
				decodedCertificate.EccCertificateSignature = &pb.DecodedCertificateSecondGen_ECCCertificateSignature{
					R: r.DecodedCertificate.ECCCertificateSignature.R.String(),
					S: r.DecodedCertificate.ECCCertificateSignature.S.String(),
				}
			}
			decodedCertificate.Valid = r.DecodedCertificate.Valid
		}
		vuOverview2VuCertificateRecords[i] = &pb.CertificateSecondGen{
			Certificate:        r.Certificate,
			DecodedCertificate: decodedCertificate,
		}
	}
	vuOverview2VuCertificateRecordsV2 := make([]*pb.CertificateSecondGen, len(v.VuOverviewSecondGenV2.VuCertificateRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.VuCertificateRecordArray.Records {
		decodedCertificate := &pb.DecodedCertificateSecondGen{}
		if r.DecodedCertificate != nil {
			decodedCertificate.CertificateBody = &pb.DecodedCertificateSecondGen_CertificateBody{
				CertificateProfileIdentifier:   uint32(r.DecodedCertificate.CertificateBody.CertificateProfileIdentifier),
				CertificateAuthorityReference:  r.DecodedCertificate.CertificateBody.CertificateAuthorityReference,
				CertificateHolderAuthorisation: r.DecodedCertificate.CertificateBody.CertificateHolderAuthorisation[:],
				PublicKey:                      &pb.DecodedCertificateSecondGen_CertificateBody_PublicKey{},
				CertificateHolderReference:     r.DecodedCertificate.CertificateBody.CertificateHolderReference,
				CertificateEffectiveDate:       r.DecodedCertificate.CertificateBody.CertificateEffectiveDate.Unix(),
				CertificateExpirationDate:      r.DecodedCertificate.CertificateBody.CertificateExpirationDate.Unix(),
			}
			decodedCertificate.CertificateBody.PublicKey.DomainParameters = make([]int64, len(r.DecodedCertificate.CertificateBody.PublicKey.DomainParameters))
			for i, dp := range r.DecodedCertificate.CertificateBody.PublicKey.DomainParameters {
				decodedCertificate.CertificateBody.PublicKey.DomainParameters[i] = int64(dp)
			}
			if r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.X != nil && r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.Y != nil {
				decodedCertificate.CertificateBody.PublicKey.PublicPoint.X = r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.X.String()
				decodedCertificate.CertificateBody.PublicKey.PublicPoint.Y = r.DecodedCertificate.CertificateBody.PublicKey.PublicPoint.Y.String()
			}
			if r.DecodedCertificate.ECCCertificateSignature.R != nil && r.DecodedCertificate.ECCCertificateSignature.S != nil {
				decodedCertificate.EccCertificateSignature = &pb.DecodedCertificateSecondGen_ECCCertificateSignature{
					R: r.DecodedCertificate.ECCCertificateSignature.R.String(),
					S: r.DecodedCertificate.ECCCertificateSignature.S.String(),
				}
			}
			decodedCertificate.Valid = r.DecodedCertificate.Valid
		}
		vuOverview2VuCertificateRecordsV2[i] = &pb.CertificateSecondGen{
			Certificate:        r.Certificate,
			DecodedCertificate: decodedCertificate,
		}
	}
	vuOverview2VehicleIdentificationNumberRecords := make([]string, len(v.VuOverviewSecondGen.VehicleIdentificationNumberRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.VehicleIdentificationNumberRecordArray.Records {
		vuOverview2VehicleIdentificationNumberRecords[i] = r.String()
	}
	vuOverview2VehicleIdentificationNumberRecordsV2 := make([]string, len(v.VuOverviewSecondGenV2.VehicleIdentificationNumberRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.VehicleIdentificationNumberRecordArray.Records {
		vuOverview2VehicleIdentificationNumberRecordsV2[i] = r.String()
	}
	vuOverview2VehicleRegistrationNumberRecords := make([]string, len(v.VuOverviewSecondGen.VehicleRegistrationNumberRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.VehicleRegistrationNumberRecordArray.Records {
		vuOverview2VehicleRegistrationNumberRecords[i] = r.String()
	}

	vuOverview2VehicleRegistrationIdentificationRecordsV2 := make([]*pb.VehicleRegistrationIdentification, len(v.VuOverviewSecondGenV2.VehicleRegistrationIdentificationRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.VehicleRegistrationIdentificationRecordArray.Records {
		vuOverview2VehicleRegistrationIdentificationRecordsV2[i] = &pb.VehicleRegistrationIdentification{
			VehicleRegistrationNation: uint32(r.VehicleRegistrationNation),
			VehicleRegistrationNumber: r.VehicleRegistrationNumber.String(),
		}
	}
	vuOverview2CurrentDateTimeRecords := make([]int64, len(v.VuOverviewSecondGen.CurrentDateTimeRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.CurrentDateTimeRecordArray.Records {
		vuOverview2CurrentDateTimeRecords[i] = r.Decode().Unix()
	}
	vuOverview2CurrentDateTimeRecordsV2 := make([]int64, len(v.VuOverviewSecondGenV2.CurrentDateTimeRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.CurrentDateTimeRecordArray.Records {
		vuOverview2CurrentDateTimeRecordsV2[i] = r.Decode().Unix()
	}
	vuOverview2VuDownloadablePeriodRecords := make([]*pb.VuDownloadablePeriod, len(v.VuOverviewSecondGen.VuDownloadablePeriodRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.VuDownloadablePeriodRecordArray.Records {
		vuOverview2VuDownloadablePeriodRecords[i] = &pb.VuDownloadablePeriod{
			MinDownloadableTime: r.MinDownloadableTime.Decode().Unix(),
			MaxDownloadableTime: r.MaxDownloadableTime.Decode().Unix(),
		}
	}
	vuOverview2VuDownloadablePeriodRecordsV2 := make([]*pb.VuDownloadablePeriod, len(v.VuOverviewSecondGenV2.VuDownloadablePeriodRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.VuDownloadablePeriodRecordArray.Records {
		vuOverview2VuDownloadablePeriodRecordsV2[i] = &pb.VuDownloadablePeriod{
			MinDownloadableTime: r.MinDownloadableTime.Decode().Unix(),
			MaxDownloadableTime: r.MaxDownloadableTime.Decode().Unix(),
		}
	}
	vuOverview2CardSlotsStatusRecords := make([]uint32, len(v.VuOverviewSecondGen.CardSlotsStatusRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.CardSlotsStatusRecordArray.Records {
		vuOverview2CardSlotsStatusRecords[i] = uint32(r)
	}
	vuOverview2CardSlotsStatusRecordsV2 := make([]uint32, len(v.VuOverviewSecondGenV2.CardSlotsStatusRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.CardSlotsStatusRecordArray.Records {
		vuOverview2CardSlotsStatusRecordsV2[i] = uint32(r)
	}
	vuOverview2VuDownloadActivityDataRecords := make([]*pb.VuDownloadActivityDataSecondGen, len(v.VuOverviewSecondGen.VuDownloadActivityDataRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.VuDownloadActivityDataRecordArray.Records {
		vuOverview2VuDownloadActivityDataRecords[i] = &pb.VuDownloadActivityDataSecondGen{
			DownloadingTime: r.DownloadingTime.Decode().Unix(),
			FullCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
				FullCardNumber: &pb.FullCardNumber{
					CardType:               uint32(r.FullCardNumberAndGeneration.FullCardNumber.CardType),
					CardIssuingMemberState: uint32(r.FullCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
					CardNumber:             r.FullCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
				},
				Generation: uint32(r.FullCardNumberAndGeneration.Generation),
			},
			CompanyOrWorkshopName: r.CompanyOrWorkshopName.String(),
		}
	}
	vuOverview2VuDownloadActivityDataRecordsV2 := make([]*pb.VuDownloadActivityDataSecondGen, len(v.VuOverviewSecondGenV2.VuDownloadActivityDataRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.VuDownloadActivityDataRecordArray.Records {
		vuOverview2VuDownloadActivityDataRecordsV2[i] = &pb.VuDownloadActivityDataSecondGen{
			DownloadingTime: r.DownloadingTime.Decode().Unix(),
			FullCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
				FullCardNumber: &pb.FullCardNumber{
					CardType:               uint32(r.FullCardNumberAndGeneration.FullCardNumber.CardType),
					CardIssuingMemberState: uint32(r.FullCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
					CardNumber:             r.FullCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
				},
				Generation: uint32(r.FullCardNumberAndGeneration.Generation),
			},
			CompanyOrWorkshopName: r.CompanyOrWorkshopName.String(),
		}
	}
	vuOverview2VuCompanyLocksRecords := make([]*pb.VuCompanyLocksRecordSecondGen, len(v.VuOverviewSecondGen.VuCompanyLocksRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.VuCompanyLocksRecordArray.Records {
		vuOverview2VuCompanyLocksRecords[i] = &pb.VuCompanyLocksRecordSecondGen{
			LockInTime:     r.LockInTime.Decode().Unix(),
			LockOutTime:    r.LockOutTime.Decode().Unix(),
			CompanyName:    r.CompanyName.String(),
			CompanyAddress: r.CompanyAddress.String(),
			CompanyCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
				FullCardNumber: &pb.FullCardNumber{
					CardType:               uint32(r.CompanyCardNumberAndGeneration.FullCardNumber.CardType),
					CardIssuingMemberState: uint32(r.CompanyCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
					CardNumber:             r.CompanyCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
				},
				Generation: uint32(r.CompanyCardNumberAndGeneration.Generation),
			},
		}
	}
	vuOverview2VuCompanyLocksRecordsV2 := make([]*pb.VuCompanyLocksRecordSecondGen, len(v.VuOverviewSecondGenV2.VuCompanyLocksRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.VuCompanyLocksRecordArray.Records {
		vuOverview2VuCompanyLocksRecordsV2[i] = &pb.VuCompanyLocksRecordSecondGen{
			LockInTime:     r.LockInTime.Decode().Unix(),
			LockOutTime:    r.LockOutTime.Decode().Unix(),
			CompanyName:    r.CompanyName.String(),
			CompanyAddress: r.CompanyAddress.String(),
			CompanyCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
				FullCardNumber: &pb.FullCardNumber{
					CardType:               uint32(r.CompanyCardNumberAndGeneration.FullCardNumber.CardType),
					CardIssuingMemberState: uint32(r.CompanyCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
					CardNumber:             r.CompanyCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
				},
				Generation: uint32(r.CompanyCardNumberAndGeneration.Generation),
			},
		}
	}
	vuOverview2ControlActivityRecords := make([]*pb.VuControlActivityRecordSecondGen, len(v.VuOverviewSecondGen.VuControlActivityRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.VuControlActivityRecordArray.Records {
		vuOverview2ControlActivityRecords[i] = &pb.VuControlActivityRecordSecondGen{
			ControlType: uint32(r.ControlType),
			ControlTime: r.ControlTime.Decode().Unix(),
			ControlCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
				FullCardNumber: &pb.FullCardNumber{
					CardType:               uint32(r.ControlCardNumberAndGeneration.FullCardNumber.CardType),
					CardIssuingMemberState: uint32(r.ControlCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
					CardNumber:             r.ControlCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
				},
				Generation: uint32(r.ControlCardNumberAndGeneration.Generation),
			},
			DownloadPeriodBeginTime: r.DownloadPeriodBeginTime.Decode().Unix(),
			DownloadPeriodEndTime:   r.DownloadPeriodEndTime.Decode().Unix(),
		}
	}
	vuOverview2ControlActivityRecordsV2 := make([]*pb.VuControlActivityRecordSecondGen, len(v.VuOverviewSecondGenV2.VuControlActivityRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.VuControlActivityRecordArray.Records {
		vuOverview2ControlActivityRecordsV2[i] = &pb.VuControlActivityRecordSecondGen{
			ControlType: uint32(r.ControlType),
			ControlTime: r.ControlTime.Decode().Unix(),
			ControlCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
				FullCardNumber: &pb.FullCardNumber{
					CardType:               uint32(r.ControlCardNumberAndGeneration.FullCardNumber.CardType),
					CardIssuingMemberState: uint32(r.ControlCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
					CardNumber:             r.ControlCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
				},
				Generation: uint32(r.ControlCardNumberAndGeneration.Generation),
			},
			DownloadPeriodBeginTime: r.DownloadPeriodBeginTime.Decode().Unix(),
			DownloadPeriodEndTime:   r.DownloadPeriodEndTime.Decode().Unix(),
		}
	}
	vuOverview2SignatureRecords := make([]*pb.SignatureSecondGen, len(v.VuOverviewSecondGen.SignatureRecordArray.Records))
	for i, r := range v.VuOverviewSecondGen.SignatureRecordArray.Records {
		vuOverview2SignatureRecords[i] = &pb.SignatureSecondGen{
			Signature: r.Signature,
		}
	}
	vuOverview2SignatureRecordsV2 := make([]*pb.SignatureSecondGen, len(v.VuOverviewSecondGenV2.SignatureRecordArray.Records))
	for i, r := range v.VuOverviewSecondGenV2.SignatureRecordArray.Records {
		vuOverview2SignatureRecordsV2[i] = &pb.SignatureSecondGen{
			Signature: r.Signature,
		}
	}
	vuActivities1 := make([]*pb.VuActivitiesFirstGen, len(v.VuActivitiesFirstGen))
	for i, r := range v.VuActivitiesFirstGen {
		vuCardIwRecords := make([]*pb.VuCardIWRecordFirstGen, len(r.VuCardIWData.VuCardIWRecords))
		for j, rec := range r.VuCardIWData.VuCardIWRecords {
			vuCardIwRecords[j] = &pb.VuCardIWRecordFirstGen{
				CardHolderName: &pb.HolderName{
					HolderSurname:    rec.CardHolderName.HolderSurname.String(),
					HolderFirstNames: rec.CardHolderName.HolderFirstNames.String(),
				},
				FullCardNumber: &pb.FullCardNumber{
					CardType:               uint32(rec.FullCardNumber.CardType),
					CardIssuingMemberState: uint32(rec.FullCardNumber.CardIssuingMemberState),
					CardNumber:             rec.FullCardNumber.CardNumber.String(),
				},
				CardExpiryDate:                   rec.CardExpiryDate.Decode().Unix(),
				CardInsertionTime:                rec.CardInsertionTime.Decode().Unix(),
				VehicleOdometerValueAtInsertion:  uint32(rec.VehicleOdometerValueAtInsertion.Decode()),
				CardSlotNumber:                   uint32(rec.CardSlotNumber),
				CardWithdrawalTime:               rec.CardWithdrawalTime.Decode().Unix(),
				VehicleOdometerValueAtWithdrawal: uint32(rec.VehicleOdometerValueAtWithdrawal.Decode()),
				PreviousVehicleInfo: &pb.PreviousVehicleInfoFirstGen{
					VehicleRegistrationIdentification: &pb.VehicleRegistrationIdentification{
						VehicleRegistrationNation: uint32(rec.PreviousVehicleInfo.VehicleRegistrationIdentification.VehicleRegistrationNation),
						VehicleRegistrationNumber: rec.PreviousVehicleInfo.VehicleRegistrationIdentification.VehicleRegistrationNumber.String(),
					},
					CardWithdrawalTime: rec.PreviousVehicleInfo.CardWithdrawalTime.Decode().Unix(),
				},
				ManualInputFlag: uint32(rec.ManualInputFlag),
			}
		}
		vuActivityChangeInfo := make([]*pb.ActivityChangeInfo, len(r.VuActivityDailyData.ActivityChangeInfo))
		for j, rec := range r.VuActivityDailyData.ActivityChangeInfo {
			decodedActivityChangeInfo := rec.Decode()
			vuActivityChangeInfo[j] = &pb.ActivityChangeInfo{
				Driver:      decodedActivityChangeInfo.Driver,
				Team:        decodedActivityChangeInfo.Team,
				CardPresent: decodedActivityChangeInfo.CardPresent,
				WorkType:    uint32(decodedActivityChangeInfo.WorkType),
				Minutes:     uint32(decodedActivityChangeInfo.Minutes),
			}
		}
		vuPlaceDailyWorkPeriodRecords := make([]*pb.VuPlaceDailyWorkPeriodRecordFirstGen, len(r.VuPlaceDailyWorkPeriodData.VuPlaceDailyWorkPeriodRecords))
		for j, rec := range r.VuPlaceDailyWorkPeriodData.VuPlaceDailyWorkPeriodRecords {
			vuPlaceDailyWorkPeriodRecords[j] = &pb.VuPlaceDailyWorkPeriodRecordFirstGen{
				FullCardNumber: &pb.FullCardNumber{
					CardType:               uint32(rec.FullCardNumber.CardType),
					CardIssuingMemberState: uint32(rec.FullCardNumber.CardIssuingMemberState),
					CardNumber:             rec.FullCardNumber.CardNumber.String(),
				},
				PlaceRecord: &pb.PlaceRecordFirstGen{
					EntryTime:                rec.PlaceRecord.EntryTime.Decode().Unix(),
					EntryTypeDailyWorkPeriod: uint32(rec.PlaceRecord.EntryTypeDailyWorkPeriod),
					DailyWorkPeriodCountry:   uint32(rec.PlaceRecord.DailyWorkPeriodCountry),
					DailyWorkPeriodRegion:    uint32(rec.PlaceRecord.DailyWorkPeriodRegion),
					VehicleOdometerValue:     uint32(rec.PlaceRecord.VehicleOdometerValue.Decode()),
				},
			}
		}
		vuSpecificConditionRecords := make([]*pb.SpecificConditionRecord, len(r.VuSpecificConditionData.SpecificConditionRecords))
		for j, rec := range r.VuSpecificConditionData.SpecificConditionRecords {
			vuSpecificConditionRecords[j] = &pb.SpecificConditionRecord{
				EntryTime:             rec.EntryTime.Decode().Unix(),
				SpecificConditionType: uint32(rec.SpecificConditionType),
			}
		}
		vuActivities1[i] = &pb.VuActivitiesFirstGen{
			Verified:              r.Verified,
			TimeReal:              r.TimeReal.Decode().Unix(),
			OdometerValueMidnight: uint32(r.OdometerValueMidnight.Decode()),
			VuCardIwData: &pb.VuCardIWData{
				NoOfIwRecords:   uint32(r.VuCardIWData.NoOfIWRecords),
				VuCardIwRecords: vuCardIwRecords,
			},
			VuActivityDailyData: &pb.VuActivityDailyDataFirstGen{
				NoOfActivityChanges: uint32(r.VuActivityDailyData.NoOfActivityChanges),
				ActivityChangeInfo:  vuActivityChangeInfo,
			},
			VuPlaceDailyWorkPeriodData: &pb.VuPlaceDailyWorkPeriodDataFirstGen{
				NoOfPlaceRecords:              uint32(r.VuPlaceDailyWorkPeriodData.NoOfPlaceRecords),
				VuPlaceDailyWorkPeriodRecords: vuPlaceDailyWorkPeriodRecords,
			},
			VuSpecificConditionData: &pb.VuSpecificConditionDataFirstGen{
				NoOfSpecificConditionRecords: uint32(r.VuSpecificConditionData.NoOfSpecificConditionRecords),
				SpecificConditionRecords:     vuSpecificConditionRecords,
			},
			Signature: &pb.SignatureFirstGen{
				Signature: r.Signature.Signature[:],
			},
		}
	}
	vuActivities2 := make([]*pb.VuActivitiesSecondGen, len(v.VuActivitiesSecondGen))
	for i, r := range v.VuActivitiesSecondGen {
		dateOfDayDownloadedRecords := make([]int64, len(r.DateOfDayDownloadedRecordArray.Records))
		for j, rec := range r.DateOfDayDownloadedRecordArray.Records {
			dateOfDayDownloadedRecords[j] = rec.Decode().Unix()
		}
		odometerValueMidnightRecords := make([]uint32, len(r.OdometerValueMidnightRecordArray.Records))
		for j, rec := range r.OdometerValueMidnightRecordArray.Records {
			odometerValueMidnightRecords[j] = uint32(rec.Decode())
		}
		vuCardIwRecords := make([]*pb.VuCardIWRecordSecondGen, len(r.VuCardIWRecordArray.Records))
		for j, rec := range r.VuCardIWRecordArray.Records {
			vuCardIwRecords[j] = &pb.VuCardIWRecordSecondGen{
				CardHolderName: &pb.HolderName{
					HolderSurname:    rec.CardHolderName.HolderSurname.String(),
					HolderFirstNames: rec.CardHolderName.HolderFirstNames.String(),
				},
				FullCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.FullCardNumberAndGeneration.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.FullCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.FullCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.FullCardNumberAndGeneration.Generation),
				},
				CardExpiryDate:                   rec.CardExpiryDate.Decode().Unix(),
				CardInsertionTime:                rec.CardInsertionTime.Decode().Unix(),
				VehicleOdometerValueAtInsertion:  uint32(rec.VehicleOdometerValueAtInsertion.Decode()),
				CardSlotNumber:                   uint32(rec.CardSlotNumber),
				CardWithdrawalTime:               rec.CardWithdrawalTime.Decode().Unix(),
				VehicleOdometerValueAtWithdrawal: uint32(rec.VehicleOdometerValueAtWithdrawal.Decode()),
				PreviousVehicleInfo: &pb.PreviousVehicleInfoSecondGen{
					VehicleRegistrationIdentification: &pb.VehicleRegistrationIdentification{
						VehicleRegistrationNation: uint32(rec.PreviousVehicleInfo.VehicleRegistrationIdentification.VehicleRegistrationNation),
						VehicleRegistrationNumber: rec.PreviousVehicleInfo.VehicleRegistrationIdentification.VehicleRegistrationNumber.String(),
					},
					CardWithdrawalTime: rec.PreviousVehicleInfo.CardWithdrawalTime.Decode().Unix(),
					VuGeneration:       uint32(rec.PreviousVehicleInfo.VuGeneration),
				},
				ManualInputFlag: uint32(rec.ManualInputFlag),
			}
		}
		vuActivityDailyRecords := make([]*pb.ActivityChangeInfo, len(r.VuActivityDailyRecordArray.Records))
		for j, rec := range r.VuActivityDailyRecordArray.Records {
			decodedChangeInfo := rec.Decode()
			vuActivityDailyRecords[j] = &pb.ActivityChangeInfo{
				Driver:      decodedChangeInfo.Driver,
				Team:        decodedChangeInfo.Team,
				CardPresent: decodedChangeInfo.CardPresent,
				WorkType:    uint32(decodedChangeInfo.WorkType),
				Minutes:     uint32(decodedChangeInfo.Minutes),
			}
		}
		vuPlaceDailyWorkPeriodRecords := make([]*pb.VuPlaceDailyWorkPeriodRecordSecondGen, len(r.VuPlaceDailyWorkPeriodRecordArray.Records))
		for j, rec := range r.VuPlaceDailyWorkPeriodRecordArray.Records {
			lon, lat := rec.PlaceRecord.EntryGNSSPlaceRecord.GeoCoordinates.Decode()
			vuPlaceDailyWorkPeriodRecords[j] = &pb.VuPlaceDailyWorkPeriodRecordSecondGen{
				FullCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.FullCardNumberAndGeneration.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.FullCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.FullCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.FullCardNumberAndGeneration.Generation),
				},
				PlaceRecord: &pb.PlaceRecordSecondGen{
					EntryTime:                rec.PlaceRecord.EntryTime.Decode().Unix(),
					EntryTypeDailyWorkPeriod: uint32(rec.PlaceRecord.EntryTypeDailyWorkPeriod),
					DailyWorkPeriodCountry:   uint32(rec.PlaceRecord.DailyWorkPeriodCountry),
					DailyWorkPeriodRegion:    uint32(rec.PlaceRecord.DailyWorkPeriodRegion),
					VehicleOdometerValue:     uint32(rec.PlaceRecord.VehicleOdometerValue.Decode()),
					EntryGnssPlaceRecord: &pb.GNSSPlaceRecord{
						TimeStamp:    rec.PlaceRecord.EntryGNSSPlaceRecord.TimeStamp.Decode().Unix(),
						GnssAccuracy: uint32(rec.PlaceRecord.EntryGNSSPlaceRecord.GNSSAccuracy),
						GeoCoordinates: &pb.GeoCoordinates{
							Latitude:  lat,
							Longitude: lon,
						},
					},
				},
			}
		}
		vuGnssAdRecords := make([]*pb.VuGNSSADRecord, len(r.VuGNSSADRecordArray.Records))
		for j, rec := range r.VuGNSSADRecordArray.Records {
			lon, lat := rec.GNSSPlaceRecord.GeoCoordinates.Decode()
			vuGnssAdRecords[j] = &pb.VuGNSSADRecord{
				TimeStamp: rec.TimeStamp.Decode().Unix(),
				CardNumberAndGenDriverSlot: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlot.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlot.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlot.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlot.Generation),
				},
				CardNumberAndGenCodriverSlot: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlot.Generation),
				},
				GnssPlaceRecord: &pb.GNSSPlaceRecord{
					TimeStamp:    rec.GNSSPlaceRecord.TimeStamp.Decode().Unix(),
					GnssAccuracy: uint32(rec.GNSSPlaceRecord.GNSSAccuracy),
					GeoCoordinates: &pb.GeoCoordinates{
						Latitude:  lat,
						Longitude: lon,
					},
				},
				VehicleOdometerValue: uint32(rec.VehicleOdometerValue.Decode()),
			}
		}
		vuSpecificConditionRecords := make([]*pb.SpecificConditionRecord, len(r.VuSpecificConditionRecordArray.Records))
		for j, rec := range r.VuSpecificConditionRecordArray.Records {
			vuSpecificConditionRecords[j] = &pb.SpecificConditionRecord{
				EntryTime:             rec.EntryTime.Decode().Unix(),
				SpecificConditionType: uint32(rec.SpecificConditionType),
			}
		}
		signatureRecords := make([]*pb.SignatureSecondGen, len(r.SignatureRecordArray.Records))
		for j, rec := range r.SignatureRecordArray.Records {
			signatureRecords[j] = &pb.SignatureSecondGen{
				Signature: rec.Signature,
			}
		}
		vuActivities2[i] = &pb.VuActivitiesSecondGen{
			Verified: r.Verified,
			DateOfDayDownloadedRecordArray: &pb.DateOfDayDownloadedRecordArray{
				RecordType:  uint32(r.DateOfDayDownloadedRecordArray.RecordType),
				RecordSize:  uint32(r.DateOfDayDownloadedRecordArray.RecordSize),
				NoOfRecords: uint32(r.DateOfDayDownloadedRecordArray.NoOfRecords),
				Records:     dateOfDayDownloadedRecords,
			},
			OdometerValueMidnightRecordArray: &pb.OdometerValueMidnightRecordArray{
				RecordType:  uint32(r.OdometerValueMidnightRecordArray.RecordType),
				RecordSize:  uint32(r.OdometerValueMidnightRecordArray.RecordSize),
				NoOfRecords: uint32(r.OdometerValueMidnightRecordArray.NoOfRecords),
				Records:     odometerValueMidnightRecords,
			},
			VuCardIwRecordArray: &pb.VuCardIWRecordArray{
				RecordType:  uint32(r.VuCardIWRecordArray.RecordType),
				RecordSize:  uint32(r.VuCardIWRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuCardIWRecordArray.NoOfRecords),
				Records:     vuCardIwRecords,
			},
			VuActivityDailyRecordArray: &pb.VuActivityDailyRecordArray{
				RecordType:  uint32(r.VuActivityDailyRecordArray.RecordType),
				RecordSize:  uint32(r.VuActivityDailyRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuActivityDailyRecordArray.NoOfRecords),
				Records:     vuActivityDailyRecords,
			},
			VuPlaceDailyWorkPeriodRecordArray: &pb.VuPlaceDailyWorkPeriodRecordArray{
				RecordType:  uint32(r.VuPlaceDailyWorkPeriodRecordArray.RecordType),
				RecordSize:  uint32(r.VuPlaceDailyWorkPeriodRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuPlaceDailyWorkPeriodRecordArray.NoOfRecords),
				Records:     vuPlaceDailyWorkPeriodRecords,
			},
			VuGnssAdRecordArray: &pb.VuGNSSADRecordArray{
				RecordType:  uint32(r.VuGNSSADRecordArray.RecordType),
				RecordSize:  uint32(r.VuGNSSADRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuGNSSADRecordArray.NoOfRecords),
				Records:     vuGnssAdRecords,
			},
			VuSpecificConditionRecordArray: &pb.VuSpecificConditionRecordArray{
				RecordType:  uint32(r.VuSpecificConditionRecordArray.RecordType),
				RecordSize:  uint32(r.VuSpecificConditionRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuSpecificConditionRecordArray.NoOfRecords),
				Records:     vuSpecificConditionRecords,
			},
			SignatureRecordArray: &pb.SignatureRecordArray{
				RecordType:  uint32(r.SignatureRecordArray.RecordType),
				RecordSize:  uint32(r.SignatureRecordArray.RecordSize),
				NoOfRecords: uint32(r.SignatureRecordArray.NoOfRecords),
				Records:     signatureRecords,
			},
		}
	}

	vuActivities2V2 := make([]*pb.VuActivitiesSecondGenV2, len(v.VuActivitiesSecondGenV2))
	for i, r := range v.VuActivitiesSecondGenV2 {
		dateOfDayDownloadedRecords := make([]int64, len(r.DateOfDayDownloadedRecordArray.Records))
		for j, rec := range r.DateOfDayDownloadedRecordArray.Records {
			dateOfDayDownloadedRecords[j] = rec.Decode().Unix()
		}
		odometerValueMidnightRecords := make([]uint32, len(r.OdometerValueMidnightRecordArray.Records))
		for j, rec := range r.OdometerValueMidnightRecordArray.Records {
			odometerValueMidnightRecords[j] = uint32(rec.Decode())
		}
		vuCardIwRecords := make([]*pb.VuCardIWRecordSecondGen, len(r.VuCardIWRecordArray.Records))
		for j, rec := range r.VuCardIWRecordArray.Records {
			vuCardIwRecords[j] = &pb.VuCardIWRecordSecondGen{
				CardHolderName: &pb.HolderName{
					HolderSurname:    rec.CardHolderName.HolderSurname.String(),
					HolderFirstNames: rec.CardHolderName.HolderFirstNames.String(),
				},
				FullCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.FullCardNumberAndGeneration.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.FullCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.FullCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.FullCardNumberAndGeneration.Generation),
				},
				CardExpiryDate:                   rec.CardExpiryDate.Decode().Unix(),
				CardInsertionTime:                rec.CardInsertionTime.Decode().Unix(),
				VehicleOdometerValueAtInsertion:  uint32(rec.VehicleOdometerValueAtInsertion.Decode()),
				CardSlotNumber:                   uint32(rec.CardSlotNumber),
				CardWithdrawalTime:               rec.CardWithdrawalTime.Decode().Unix(),
				VehicleOdometerValueAtWithdrawal: uint32(rec.VehicleOdometerValueAtWithdrawal.Decode()),
				PreviousVehicleInfo: &pb.PreviousVehicleInfoSecondGen{
					VehicleRegistrationIdentification: &pb.VehicleRegistrationIdentification{
						VehicleRegistrationNation: uint32(rec.PreviousVehicleInfo.VehicleRegistrationIdentification.VehicleRegistrationNation),
						VehicleRegistrationNumber: rec.PreviousVehicleInfo.VehicleRegistrationIdentification.VehicleRegistrationNumber.String(),
					},
					CardWithdrawalTime: rec.PreviousVehicleInfo.CardWithdrawalTime.Decode().Unix(),
					VuGeneration:       uint32(rec.PreviousVehicleInfo.VuGeneration),
				},
				ManualInputFlag: uint32(rec.ManualInputFlag),
			}
		}
		vuActivityDailyRecords := make([]*pb.ActivityChangeInfo, len(r.VuActivityDailyRecordArray.Records))
		for j, rec := range r.VuActivityDailyRecordArray.Records {
			decodedChangeInfo := rec.Decode()
			vuActivityDailyRecords[j] = &pb.ActivityChangeInfo{
				Driver:      decodedChangeInfo.Driver,
				Team:        decodedChangeInfo.Team,
				CardPresent: decodedChangeInfo.CardPresent,
				WorkType:    uint32(decodedChangeInfo.WorkType),
				Minutes:     uint32(decodedChangeInfo.Minutes),
			}
		}
		vuPlaceDailyWorkPeriodRecordsV2 := make([]*pb.VuPlaceDailyWorkPeriodRecordSecondGenV2, len(r.VuPlaceDailyWorkPeriodRecordArray.Records))
		for j, rec := range r.VuPlaceDailyWorkPeriodRecordArray.Records {
			lon, lat := rec.PlaceAuthRecord.EntryGNSSPlaceAuthRecord.GeoCoordinates.Decode()
			vuPlaceDailyWorkPeriodRecordsV2[j] = &pb.VuPlaceDailyWorkPeriodRecordSecondGenV2{
				FullCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.FullCardNumberAndGeneration.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.FullCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.FullCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.FullCardNumberAndGeneration.Generation),
				},
				PlaceAuthRecord: &pb.PlaceAuthRecord{
					EntryTime:                rec.PlaceAuthRecord.EntryTime.Decode().Unix(),
					EntryTypeDailyWorkPeriod: uint32(rec.PlaceAuthRecord.EntryTypeDailyWorkPeriod),
					DailyWorkPeriodCountry:   uint32(rec.PlaceAuthRecord.DailyWorkPeriodCountry),
					DailyWorkPeriodRegion:    uint32(rec.PlaceAuthRecord.DailyWorkPeriodRegion),
					VehicleOdometerValue:     uint32(rec.PlaceAuthRecord.VehicleOdometerValue.Decode()),
					EntryGnssPlaceRecord: &pb.GNSSPlaceAuthRecord{
						TimeStamp:    rec.PlaceAuthRecord.EntryGNSSPlaceAuthRecord.TimeStamp.Decode().Unix(),
						GnssAccuracy: uint32(rec.PlaceAuthRecord.EntryGNSSPlaceAuthRecord.GNSSAccuracy),
						GeoCoordinates: &pb.GeoCoordinates{
							Latitude:  lat,
							Longitude: lon,
						},
						AuthenticationStatus: uint32(rec.PlaceAuthRecord.EntryGNSSPlaceAuthRecord.AuthenticationStatus),
					},
				},
			}
		}
		vuGnssAdRecordsV2 := make([]*pb.VuGNSSADRecordV2, len(r.VuGNSSADRecordArray.Records))
		for j, rec := range r.VuGNSSADRecordArray.Records {
			lon, lat := rec.GNSSPlaceAuthRecord.GeoCoordinates.Decode()
			vuGnssAdRecordsV2[j] = &pb.VuGNSSADRecordV2{
				TimeStamp: rec.TimeStamp.Decode().Unix(),
				CardNumberAndGenDriverSlot: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlot.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlot.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlot.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlot.Generation),
				},
				CardNumberAndGenCodriverSlot: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlot.Generation),
				},
				GnssPlaceAuthRecord: &pb.GNSSPlaceAuthRecord{
					TimeStamp:    rec.GNSSPlaceAuthRecord.TimeStamp.Decode().Unix(),
					GnssAccuracy: uint32(rec.GNSSPlaceAuthRecord.GNSSAccuracy),
					GeoCoordinates: &pb.GeoCoordinates{
						Latitude:  lat,
						Longitude: lon,
					},
					AuthenticationStatus: uint32(rec.GNSSPlaceAuthRecord.AuthenticationStatus),
				},
				VehicleOdometerValue: uint32(rec.VehicleOdometerValue.Decode()),
			}
		}
		vuSpecificConditionRecords := make([]*pb.SpecificConditionRecord, len(r.VuSpecificConditionRecordArray.Records))
		for j, rec := range r.VuSpecificConditionRecordArray.Records {
			vuSpecificConditionRecords[j] = &pb.SpecificConditionRecord{
				EntryTime:             rec.EntryTime.Decode().Unix(),
				SpecificConditionType: uint32(rec.SpecificConditionType),
			}
		}
		vuBorderCrossingRecordArray := make([]*pb.VuBorderCrossingRecord, len(r.VuBorderCrossingRecordArray.Records))
		for j, rec := range r.VuBorderCrossingRecordArray.Records {
			lon, lat := rec.GNSSPlaceAuthRecord.GeoCoordinates.Decode()
			vuBorderCrossingRecordArray[j] = &pb.VuBorderCrossingRecord{
				CardNumberAndGenDriverSlot: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlot.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlot.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlot.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlot.Generation),
				},
				CardNumberAndGenCodriverSlot: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlot.Generation),
				},
				CountryLeft:    uint32(rec.CountryLeft),
				CountryEntered: uint32(rec.CountryEntered),
				GnssPlaceAuthRecord: &pb.GNSSPlaceAuthRecord{
					TimeStamp:    rec.GNSSPlaceAuthRecord.TimeStamp.Decode().Unix(),
					GnssAccuracy: uint32(rec.GNSSPlaceAuthRecord.GNSSAccuracy),
					GeoCoordinates: &pb.GeoCoordinates{
						Latitude:  lat,
						Longitude: lon,
					},
					AuthenticationStatus: uint32(rec.GNSSPlaceAuthRecord.AuthenticationStatus),
				},
				VehicleOdometerValue: uint32(rec.VehicleOdometerValue.Decode()),
			}
		}
		vuLoadUnloadRecordArray := make([]*pb.VuLoadUnloadRecord, len(r.VuLoadUnloadRecordArray.Records))
		for j, rec := range r.VuLoadUnloadRecordArray.Records {
			lon, lat := rec.GNSSPlaceAuthRecord.GeoCoordinates.Decode()
			vuLoadUnloadRecordArray[j] = &pb.VuLoadUnloadRecord{
				TimeStamp:     rec.TimeStamp.Decode().Unix(),
				OperationType: uint32(rec.OperationType),
				CardNumberAndGenDriverSlot: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlot.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlot.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlot.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlot.Generation),
				},
				CardNumberAndGenCodriverSlot: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlot.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlot.Generation),
				},
				GnssPlaceAuthRecord: &pb.GNSSPlaceAuthRecord{
					TimeStamp:    rec.GNSSPlaceAuthRecord.TimeStamp.Decode().Unix(),
					GnssAccuracy: uint32(rec.GNSSPlaceAuthRecord.GNSSAccuracy),
					GeoCoordinates: &pb.GeoCoordinates{
						Latitude:  lat,
						Longitude: lon,
					},
					AuthenticationStatus: uint32(rec.GNSSPlaceAuthRecord.AuthenticationStatus),
				},
				VehicleOdometerValue: uint32(rec.VehicleOdometerValue.Decode()),
			}
		}
		signatureRecords := make([]*pb.SignatureSecondGen, len(r.SignatureRecordArray.Records))
		for j, rec := range r.SignatureRecordArray.Records {
			signatureRecords[j] = &pb.SignatureSecondGen{
				Signature: rec.Signature,
			}
		}
		vuActivities2V2[i] = &pb.VuActivitiesSecondGenV2{
			Verified: r.Verified,
			DateOfDayDownloadedRecordArray: &pb.DateOfDayDownloadedRecordArray{
				RecordType:  uint32(r.DateOfDayDownloadedRecordArray.RecordType),
				RecordSize:  uint32(r.DateOfDayDownloadedRecordArray.RecordSize),
				NoOfRecords: uint32(r.DateOfDayDownloadedRecordArray.NoOfRecords),
				Records:     dateOfDayDownloadedRecords,
			},
			OdometerValueMidnightRecordArray: &pb.OdometerValueMidnightRecordArray{
				RecordType:  uint32(r.OdometerValueMidnightRecordArray.RecordType),
				RecordSize:  uint32(r.OdometerValueMidnightRecordArray.RecordSize),
				NoOfRecords: uint32(r.OdometerValueMidnightRecordArray.NoOfRecords),
				Records:     odometerValueMidnightRecords,
			},
			VuCardIwRecordArray: &pb.VuCardIWRecordArray{
				RecordType:  uint32(r.VuCardIWRecordArray.RecordType),
				RecordSize:  uint32(r.VuCardIWRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuCardIWRecordArray.NoOfRecords),
				Records:     vuCardIwRecords,
			},
			VuActivityDailyRecordArray: &pb.VuActivityDailyRecordArray{
				RecordType:  uint32(r.VuActivityDailyRecordArray.RecordType),
				RecordSize:  uint32(r.VuActivityDailyRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuActivityDailyRecordArray.NoOfRecords),
				Records:     vuActivityDailyRecords,
			},
			VuPlaceDailyWorkPeriodRecordArray: &pb.VuPlaceDailyWorkPeriodRecordArrayV2{
				RecordType:  uint32(r.VuPlaceDailyWorkPeriodRecordArray.RecordType),
				RecordSize:  uint32(r.VuPlaceDailyWorkPeriodRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuPlaceDailyWorkPeriodRecordArray.NoOfRecords),
				Records:     vuPlaceDailyWorkPeriodRecordsV2,
			},
			VuGnssAdRecordArray: &pb.VuGNSSADRecordArrayV2{
				RecordType:  uint32(r.VuGNSSADRecordArray.RecordType),
				RecordSize:  uint32(r.VuGNSSADRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuGNSSADRecordArray.NoOfRecords),
				Records:     vuGnssAdRecordsV2,
			},
			VuSpecificConditionRecordArray: &pb.VuSpecificConditionRecordArray{
				RecordType:  uint32(r.VuSpecificConditionRecordArray.RecordType),
				RecordSize:  uint32(r.VuSpecificConditionRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuSpecificConditionRecordArray.NoOfRecords),
				Records:     vuSpecificConditionRecords,
			},
			VuBorderCrossingRecordArray: &pb.VuBorderCrossingRecordArray{
				RecordType:  uint32(r.VuBorderCrossingRecordArray.RecordType),
				RecordSize:  uint32(r.VuBorderCrossingRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuBorderCrossingRecordArray.NoOfRecords),
				Records:     vuBorderCrossingRecordArray,
			},
			VuLoadUnloadRecordArray: &pb.VuLoadUnloadRecordArray{
				RecordType:  uint32(r.VuLoadUnloadRecordArray.RecordType),
				RecordSize:  uint32(r.VuLoadUnloadRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuLoadUnloadRecordArray.NoOfRecords),
				Records:     vuLoadUnloadRecordArray,
			},
			SignatureRecordArray: &pb.SignatureRecordArray{
				RecordType:  uint32(r.SignatureRecordArray.RecordType),
				RecordSize:  uint32(r.SignatureRecordArray.RecordSize),
				NoOfRecords: uint32(r.SignatureRecordArray.NoOfRecords),
				Records:     signatureRecords,
			},
		}
	}

	vuEventsAndFaults1 := make([]*pb.VuEventsAndFaultsFirstGen, len(v.VuEventsAndFaultsFirstGen))
	for i, r := range v.VuEventsAndFaultsFirstGen {
		vuVaultRecords := make([]*pb.VuFaultRecordFirstGen, len(r.VuFaultData.VuFaultRecords))
		for j, rec := range r.VuFaultData.VuFaultRecords {
			vuVaultRecords[j] = &pb.VuFaultRecordFirstGen{
				FaultType:          uint32(rec.FaultType),
				FaultRecordPurpose: uint32(rec.FaultRecordPurpose),
				FaultBeginTime:     rec.FaultBeginTime.Decode().Unix(),
				FaultEndTime:       rec.FaultEndTime.Decode().Unix(),
				CardNumberDriverSlotBegin: &pb.FullCardNumber{
					CardType:               uint32(rec.CardNumberDriverSlotBegin.CardType),
					CardIssuingMemberState: uint32(rec.CardNumberDriverSlotBegin.CardIssuingMemberState),
					CardNumber:             rec.CardNumberDriverSlotBegin.CardNumber.String(),
				},
				CardNumberCodriverSlotBegin: &pb.FullCardNumber{
					CardType:               uint32(rec.CardNumberCodriverSlotBegin.CardType),
					CardIssuingMemberState: uint32(rec.CardNumberCodriverSlotBegin.CardIssuingMemberState),
					CardNumber:             rec.CardNumberCodriverSlotBegin.CardNumber.String(),
				},
				CardNumberDriverSlotEnd: &pb.FullCardNumber{
					CardType:               uint32(rec.CardNumberDriverSlotEnd.CardType),
					CardIssuingMemberState: uint32(rec.CardNumberDriverSlotEnd.CardIssuingMemberState),
					CardNumber:             rec.CardNumberDriverSlotEnd.CardNumber.String(),
				},
				CardNumberCodriverSlotEnd: &pb.FullCardNumber{
					CardType:               uint32(rec.CardNumberCodriverSlotEnd.CardType),
					CardIssuingMemberState: uint32(rec.CardNumberCodriverSlotEnd.CardIssuingMemberState),
					CardNumber:             rec.CardNumberCodriverSlotEnd.CardNumber.String(),
				},
			}
		}
		vuEventRecords := make([]*pb.VuEventRecordFirstGen, len(r.VuEventData.VuEventRecords))
		for j, rec := range r.VuEventData.VuEventRecords {
			vuEventRecords[j] = &pb.VuEventRecordFirstGen{
				EventType:          uint32(rec.EventType),
				EventRecordPurpose: uint32(rec.EventRecordPurpose),
				EventBeginTime:     rec.EventBeginTime.Decode().Unix(),
				EventEndTime:       rec.EventEndTime.Decode().Unix(),
				CardNumberDriverSlotBegin: &pb.FullCardNumber{
					CardType:               uint32(rec.CardNumberDriverSlotBegin.CardType),
					CardIssuingMemberState: uint32(rec.CardNumberDriverSlotBegin.CardIssuingMemberState),
					CardNumber:             rec.CardNumberDriverSlotBegin.CardNumber.String(),
				},
				CardNumberCodriverSlotBegin: &pb.FullCardNumber{
					CardType:               uint32(rec.CardNumberCodriverSlotBegin.CardType),
					CardIssuingMemberState: uint32(rec.CardNumberCodriverSlotBegin.CardIssuingMemberState),
					CardNumber:             rec.CardNumberCodriverSlotBegin.CardNumber.String(),
				},
				CardNumberDriverSlotEnd: &pb.FullCardNumber{
					CardType:               uint32(rec.CardNumberDriverSlotEnd.CardType),
					CardIssuingMemberState: uint32(rec.CardNumberDriverSlotEnd.CardIssuingMemberState),
					CardNumber:             rec.CardNumberDriverSlotEnd.CardNumber.String(),
				},
				CardNumberCodriverSlotEnd: &pb.FullCardNumber{
					CardType:               uint32(rec.CardNumberCodriverSlotEnd.CardType),
					CardIssuingMemberState: uint32(rec.CardNumberCodriverSlotEnd.CardIssuingMemberState),
					CardNumber:             rec.CardNumberCodriverSlotEnd.CardNumber.String(),
				},
				SimilarEventsNumber: uint32(rec.SimilarEventsNumber),
			}
		}
		vuOverSpeedingEventRecords := make([]*pb.VuOverSpeedingEventRecordFirstGen, len(r.VuOverSpeedingEventData.VuOverSpeedingEventRecords))
		for j, rec := range r.VuOverSpeedingEventData.VuOverSpeedingEventRecords {
			vuOverSpeedingEventRecords[j] = &pb.VuOverSpeedingEventRecordFirstGen{
				EventType:          uint32(rec.EventType),
				EventRecordPurpose: uint32(rec.EventRecordPurpose),
				EventBeginTime:     rec.EventBeginTime.Decode().Unix(),
				EventEndTime:       rec.EventEndTime.Decode().Unix(),
				MaxSpeedValue:      uint32(rec.MaxSpeedValue),
				AverageSpeedValue:  uint32(rec.AverageSpeedValue),
				CardNumberDriverSlotBegin: &pb.FullCardNumber{
					CardType:               uint32(rec.CardNumberDriverSlotBegin.CardType),
					CardIssuingMemberState: uint32(rec.CardNumberDriverSlotBegin.CardIssuingMemberState),
					CardNumber:             rec.CardNumberDriverSlotBegin.CardNumber.String(),
				},
				SimilarEventsNumber: uint32(rec.SimilarEventsNumber),
			}
		}
		vuTimeAdjustmentRecords := make([]*pb.VuTimeAdjustmentRecordFirstGen, len(r.VuTimeAdjustmentData.VuTimeAdjustmentRecords))
		for j, rec := range r.VuTimeAdjustmentData.VuTimeAdjustmentRecords {
			vuTimeAdjustmentRecords[j] = &pb.VuTimeAdjustmentRecordFirstGen{
				OldTimeValue:    rec.OldTimeValue.Decode().Unix(),
				NewTimeValue:    rec.NewTimeValue.Decode().Unix(),
				WorkshopName:    rec.WorkshopName.String(),
				WorkshopAddress: rec.WorkshopAddress.String(),
				WorkshopCardNumber: &pb.FullCardNumber{
					CardType:               uint32(rec.WorkshopCardNumber.CardType),
					CardIssuingMemberState: uint32(rec.WorkshopCardNumber.CardIssuingMemberState),
					CardNumber:             rec.WorkshopCardNumber.CardNumber.String(),
				},
			}
		}
		vuEventsAndFaults1[i] = &pb.VuEventsAndFaultsFirstGen{
			Verified: r.Verified,
			VuFaultData: &pb.VuFaultData{
				NoOfVuFaults:   uint32(r.VuFaultData.NoOfVuFaults),
				VuFaultRecords: vuVaultRecords,
			},
			VuEventData: &pb.VuEventData{
				NoOfVuEvents:   uint32(r.VuEventData.NoOfVuEvents),
				VuEventRecords: vuEventRecords,
			},
			VuOverSpeedingControlData: &pb.VuOverSpeedingControlData{
				LastOverspeedControlTime: r.VuOverSpeedingControlData.LastOverspeedControlTime.Decode().Unix(),
				FirstOverspeedSince:      r.VuOverSpeedingControlData.FirstOverspeedSince.Decode().Unix(),
				NumberOfOverspeedSince:   uint32(r.VuOverSpeedingControlData.NumberOfOverspeedSince),
			},
			VuOverSpeedingEventData: &pb.VuOverSpeedingEventData{
				NoOfVuOverSpeedingEvents:   uint32(r.VuOverSpeedingEventData.NoOfOvVuOverSpeedingEvents),
				VuOverSpeedingEventRecords: vuOverSpeedingEventRecords,
			},
			VuTimeAdjustmentData: &pb.VuTimeAdjustmentData{
				NoOfVuTimeAdjRecords:    uint32(r.VuTimeAdjustmentData.NoOfVuTimeAdjRecords),
				VuTimeAdjustmentRecords: vuTimeAdjustmentRecords,
			},
			Signature: &pb.SignatureFirstGen{
				Signature: r.Signature.Signature[:],
			},
		}
	}
	vuEventsAndFaults2 := make([]*pb.VuEventsAndFaultsSecondGen, len(v.VuEventsAndFaultsSecondGen))
	for i, r := range v.VuEventsAndFaultsSecondGen {
		vuFaultRecords := make([]*pb.VuFaultRecordSecondGen, len(r.VuFaultRecordArray.Records))
		for j, rec := range r.VuFaultRecordArray.Records {
			vuFaultRecords[j] = &pb.VuFaultRecordSecondGen{
				FaultType:          uint32(rec.FaultType),
				FaultRecordPurpose: uint32(rec.FaultRecordPurpose),
				FaultBeginTime:     rec.FaultBeginTime.Decode().Unix(),
				FaultEndTime:       rec.FaultEndTime.Decode().Unix(),
				CardNumberAndGenDriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotBegin.Generation),
				},
				CardNumberAndGenCodriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotBegin.Generation),
				},
				CardNumberAndGenDriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotEnd.Generation),
				},
				CardNumberAndGenCodriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotEnd.Generation),
				},
				ManufacturerSpecificEventFaultData: &pb.ManufacturerSpecificEventFaultData{
					ManufacturerCode:              uint32(rec.ManufacturerSpecificEventFaultData.ManufacturerCode),
					ManufacturerSpecificErrorCode: rec.ManufacturerSpecificEventFaultData.ManufacturerSpecificErrorCode[:],
				},
			}
		}
		vuEventRecords := make([]*pb.VuEventRecordSecondGen, len(r.VuEventRecordArray.Records))
		for j, rec := range r.VuEventRecordArray.Records {
			vuEventRecords[j] = &pb.VuEventRecordSecondGen{
				EventType:          uint32(rec.EventType),
				EventRecordPurpose: uint32(rec.EventRecordPurpose),
				EventBeginTime:     rec.EventBeginTime.Decode().Unix(),
				EventEndTime:       rec.EventEndTime.Decode().Unix(),
				CardNumberAndGenDriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotBegin.Generation),
				},
				CardNumberAndGenCodriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotBegin.Generation),
				},
				CardNumberAndGenDriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotEnd.Generation),
				},
				CardNumberAndGenCodriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotEnd.Generation),
				},
				SimilarEventsNumber: uint32(rec.SimilarEventsNumber),
				ManufacturerSpecificEventFaultData: &pb.ManufacturerSpecificEventFaultData{
					ManufacturerCode:              uint32(rec.ManufacturerSpecificEventFaultData.ManufacturerCode),
					ManufacturerSpecificErrorCode: rec.ManufacturerSpecificEventFaultData.ManufacturerSpecificErrorCode[:],
				},
			}
		}
		vuOverSpeedingControlDataRecords := make([]*pb.VuOverSpeedingControlData, len(r.VuOverSpeedingControlDataRecordArray.Records))
		for j, rec := range r.VuOverSpeedingControlDataRecordArray.Records {
			vuOverSpeedingControlDataRecords[j] = &pb.VuOverSpeedingControlData{
				LastOverspeedControlTime: rec.LastOverspeedControlTime.Decode().Unix(),
				FirstOverspeedSince:      rec.FirstOverspeedSince.Decode().Unix(),
				NumberOfOverspeedSince:   uint32(rec.NumberOfOverspeedSince),
			}
		}
		vuOverSpeedingEventRecords := make([]*pb.VuOverSpeedingEventRecordSecondGen, len(r.VuOverSpeedingEventRecordArray.Records))
		for j, rec := range r.VuOverSpeedingEventRecordArray.Records {
			vuOverSpeedingEventRecords[j] = &pb.VuOverSpeedingEventRecordSecondGen{
				EventType:          uint32(rec.EventType),
				EventRecordPurpose: uint32(rec.EventRecordPurpose),
				EventBeginTime:     rec.EventBeginTime.Decode().Unix(),
				EventEndTime:       rec.EventEndTime.Decode().Unix(),
				MaxSpeedValue:      uint32(rec.MaxSpeedValue),
				AverageSpeedValue:  uint32(rec.AverageSpeedValue),
				CardNumberAndGenDriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotBegin.Generation),
				},
				SimilarEventsNumber: uint32(rec.SimilarEventsNumber),
			}
		}
		vuTimeAdjustmentRecords := make([]*pb.VuTimeAdjustmentRecordSecondGen, len(r.VuTimeAdjustmentRecordArray.Records))
		for j, rec := range r.VuTimeAdjustmentRecordArray.Records {
			vuTimeAdjustmentRecords[j] = &pb.VuTimeAdjustmentRecordSecondGen{
				OldTimeValue:    rec.OldTimeValue.Decode().Unix(),
				NewTimeValue:    rec.NewTimeValue.Decode().Unix(),
				WorkshopName:    rec.WorkshopName.String(),
				WorkshopAddress: rec.WorkshopAddress.String(),
				WorkshopCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.WorkshopCardNumberAndGeneration.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.WorkshopCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.WorkshopCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.WorkshopCardNumberAndGeneration.Generation),
				},
			}
		}
		signatureRecords := make([]*pb.SignatureSecondGen, len(r.SignatureRecordArray.Records))
		for j, rec := range r.SignatureRecordArray.Records {
			signatureRecords[j] = &pb.SignatureSecondGen{
				Signature: rec.Signature,
			}
		}
		vuEventsAndFaults2[i] = &pb.VuEventsAndFaultsSecondGen{
			Verified: r.Verified,
			VuFaultRecordArray: &pb.VuFaultRecordArray{
				RecordType:  uint32(r.VuFaultRecordArray.RecordType),
				RecordSize:  uint32(r.VuFaultRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuFaultRecordArray.NoOfRecords),
				Records:     vuFaultRecords,
			},
			VuEventRecordArray: &pb.VuEventRecordArray{
				RecordType:  uint32(r.VuEventRecordArray.RecordType),
				RecordSize:  uint32(r.VuEventRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuEventRecordArray.NoOfRecords),
				Records:     vuEventRecords,
			},
			VuOverSpeedingControlDataRecordArray: &pb.VuOverSpeedingControlDataRecordArray{
				RecordType:  uint32(r.VuOverSpeedingControlDataRecordArray.RecordType),
				RecordSize:  uint32(r.VuOverSpeedingControlDataRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuOverSpeedingControlDataRecordArray.NoOfRecords),
				Records:     vuOverSpeedingControlDataRecords,
			},
			VuOverSpeedingEventRecordArray: &pb.VuOverSpeedingEventRecordArray{
				RecordType:  uint32(r.VuOverSpeedingEventRecordArray.RecordType),
				RecordSize:  uint32(r.VuOverSpeedingEventRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuOverSpeedingEventRecordArray.NoOfRecords),
				Records:     vuOverSpeedingEventRecords,
			},
			VuTimeAdjustmentRecordArray: &pb.VuTimeAdjustmentRecordArray{
				RecordType:  uint32(r.VuTimeAdjustmentRecordArray.RecordType),
				RecordSize:  uint32(r.VuTimeAdjustmentRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuTimeAdjustmentRecordArray.NoOfRecords),
				Records:     vuTimeAdjustmentRecords,
			},
			SignatureRecordArray: &pb.SignatureRecordArray{
				RecordType:  uint32(r.SignatureRecordArray.RecordType),
				RecordSize:  uint32(r.SignatureRecordArray.RecordSize),
				NoOfRecords: uint32(r.SignatureRecordArray.NoOfRecords),
				Records:     signatureRecords,
			},
		}
	}

	vuEventsAndFaults2V2 := make([]*pb.VuEventsAndFaultsSecondGenV2, len(v.VuEventsAndFaultsSecondGenV2))
	for i, r := range v.VuEventsAndFaultsSecondGenV2 {
		vuFaultRecords := make([]*pb.VuFaultRecordSecondGen, len(r.VuFaultRecordArray.Records))
		for j, rec := range r.VuFaultRecordArray.Records {
			vuFaultRecords[j] = &pb.VuFaultRecordSecondGen{
				FaultType:          uint32(rec.FaultType),
				FaultRecordPurpose: uint32(rec.FaultRecordPurpose),
				FaultBeginTime:     rec.FaultBeginTime.Decode().Unix(),
				FaultEndTime:       rec.FaultEndTime.Decode().Unix(),
				CardNumberAndGenDriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotBegin.Generation),
				},
				CardNumberAndGenCodriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotBegin.Generation),
				},
				CardNumberAndGenDriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotEnd.Generation),
				},
				CardNumberAndGenCodriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotEnd.Generation),
				},
				ManufacturerSpecificEventFaultData: &pb.ManufacturerSpecificEventFaultData{
					ManufacturerCode:              uint32(rec.ManufacturerSpecificEventFaultData.ManufacturerCode),
					ManufacturerSpecificErrorCode: rec.ManufacturerSpecificEventFaultData.ManufacturerSpecificErrorCode[:],
				},
			}
		}
		vuEventRecords := make([]*pb.VuEventRecordSecondGen, len(r.VuEventRecordArray.Records))
		for j, rec := range r.VuEventRecordArray.Records {
			vuEventRecords[j] = &pb.VuEventRecordSecondGen{
				EventType:          uint32(rec.EventType),
				EventRecordPurpose: uint32(rec.EventRecordPurpose),
				EventBeginTime:     rec.EventBeginTime.Decode().Unix(),
				EventEndTime:       rec.EventEndTime.Decode().Unix(),
				CardNumberAndGenDriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotBegin.Generation),
				},
				CardNumberAndGenCodriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotBegin.Generation),
				},
				CardNumberAndGenDriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotEnd.Generation),
				},
				CardNumberAndGenCodriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotEnd.Generation),
				},
				SimilarEventsNumber: uint32(rec.SimilarEventsNumber),
				ManufacturerSpecificEventFaultData: &pb.ManufacturerSpecificEventFaultData{
					ManufacturerCode:              uint32(rec.ManufacturerSpecificEventFaultData.ManufacturerCode),
					ManufacturerSpecificErrorCode: rec.ManufacturerSpecificEventFaultData.ManufacturerSpecificErrorCode[:],
				},
			}
		}
		vuOverSpeedingControlDataRecords := make([]*pb.VuOverSpeedingControlData, len(r.VuOverSpeedingControlDataRecordArray.Records))
		for j, rec := range r.VuOverSpeedingControlDataRecordArray.Records {
			vuOverSpeedingControlDataRecords[j] = &pb.VuOverSpeedingControlData{
				LastOverspeedControlTime: rec.LastOverspeedControlTime.Decode().Unix(),
				FirstOverspeedSince:      rec.FirstOverspeedSince.Decode().Unix(),
				NumberOfOverspeedSince:   uint32(rec.NumberOfOverspeedSince),
			}
		}
		vuOverSpeedingEventRecords := make([]*pb.VuOverSpeedingEventRecordSecondGen, len(r.VuOverSpeedingEventRecordArray.Records))
		for j, rec := range r.VuOverSpeedingEventRecordArray.Records {
			vuOverSpeedingEventRecords[j] = &pb.VuOverSpeedingEventRecordSecondGen{
				EventType:          uint32(rec.EventType),
				EventRecordPurpose: uint32(rec.EventRecordPurpose),
				EventBeginTime:     rec.EventBeginTime.Decode().Unix(),
				EventEndTime:       rec.EventEndTime.Decode().Unix(),
				MaxSpeedValue:      uint32(rec.MaxSpeedValue),
				AverageSpeedValue:  uint32(rec.AverageSpeedValue),
				CardNumberAndGenDriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotBegin.Generation),
				},
				SimilarEventsNumber: uint32(rec.SimilarEventsNumber),
			}
		}
		vuTimeAdjustmentRecords := make([]*pb.VuTimeAdjustmentRecordSecondGen, len(r.VuTimeAdjustmentRecordArray.Records))
		for j, rec := range r.VuTimeAdjustmentRecordArray.Records {
			vuTimeAdjustmentRecords[j] = &pb.VuTimeAdjustmentRecordSecondGen{
				OldTimeValue:    rec.OldTimeValue.Decode().Unix(),
				NewTimeValue:    rec.NewTimeValue.Decode().Unix(),
				WorkshopName:    rec.WorkshopName.String(),
				WorkshopAddress: rec.WorkshopAddress.String(),
				WorkshopCardNumberAndGeneration: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.WorkshopCardNumberAndGeneration.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.WorkshopCardNumberAndGeneration.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.WorkshopCardNumberAndGeneration.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.WorkshopCardNumberAndGeneration.Generation),
				},
			}
		}
		signatureRecords := make([]*pb.SignatureSecondGen, len(r.SignatureRecordArray.Records))
		for j, rec := range r.SignatureRecordArray.Records {
			signatureRecords[j] = &pb.SignatureSecondGen{
				Signature: rec.Signature,
			}
		}
		vuEventsAndFaults2[i] = &pb.VuEventsAndFaultsSecondGen{
			Verified: r.Verified,
			VuFaultRecordArray: &pb.VuFaultRecordArray{
				RecordType:  uint32(r.VuFaultRecordArray.RecordType),
				RecordSize:  uint32(r.VuFaultRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuFaultRecordArray.NoOfRecords),
				Records:     vuFaultRecords,
			},
			VuEventRecordArray: &pb.VuEventRecordArray{
				RecordType:  uint32(r.VuEventRecordArray.RecordType),
				RecordSize:  uint32(r.VuEventRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuEventRecordArray.NoOfRecords),
				Records:     vuEventRecords,
			},
			VuOverSpeedingControlDataRecordArray: &pb.VuOverSpeedingControlDataRecordArray{
				RecordType:  uint32(r.VuOverSpeedingControlDataRecordArray.RecordType),
				RecordSize:  uint32(r.VuOverSpeedingControlDataRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuOverSpeedingControlDataRecordArray.NoOfRecords),
				Records:     vuOverSpeedingControlDataRecords,
			},
			VuOverSpeedingEventRecordArray: &pb.VuOverSpeedingEventRecordArray{
				RecordType:  uint32(r.VuOverSpeedingEventRecordArray.RecordType),
				RecordSize:  uint32(r.VuOverSpeedingEventRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuOverSpeedingEventRecordArray.NoOfRecords),
				Records:     vuOverSpeedingEventRecords,
			},
			VuTimeAdjustmentRecordArray: &pb.VuTimeAdjustmentRecordArray{
				RecordType:  uint32(r.VuTimeAdjustmentRecordArray.RecordType),
				RecordSize:  uint32(r.VuTimeAdjustmentRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuTimeAdjustmentRecordArray.NoOfRecords),
				Records:     vuTimeAdjustmentRecords,
			},
			SignatureRecordArray: &pb.SignatureRecordArray{
				RecordType:  uint32(r.SignatureRecordArray.RecordType),
				RecordSize:  uint32(r.SignatureRecordArray.RecordSize),
				NoOfRecords: uint32(r.SignatureRecordArray.NoOfRecords),
				Records:     signatureRecords,
			},
		}
	}

	vuDetailedSpeed1 := make([]*pb.VuDetailedSpeedFirstGen, len(v.VuDetailedSpeedFirstGen))
	for i, r := range v.VuDetailedSpeedFirstGen {
		vuDetailedSpeedBlocks := make([]*pb.VuDetailedSpeedBlock, len(r.VuDetailedSpeedData.VuDetailedSpeedBlocks))
		for j, rec := range r.VuDetailedSpeedData.VuDetailedSpeedBlocks {
			speedsPerSecond := make([]byte, len(rec.SpeedsPerSecond))
			for k, r2 := range rec.SpeedsPerSecond {
				speedsPerSecond[k] = byte(r2)
			}
			vuDetailedSpeedBlocks[j] = &pb.VuDetailedSpeedBlock{
				SpeedBlockBeginDate: rec.SpeedBlockBeginDate.Decode().Unix(),
				SpeedsPerSecond:     speedsPerSecond,
			}
		}
		vuDetailedSpeed1[i] = &pb.VuDetailedSpeedFirstGen{
			Verified: r.Verified,
			VuDetailedSpeedData: &pb.VuDetailedSpeedData{
				NoOfSpeedBlocks:       uint32(r.VuDetailedSpeedData.NoOfSpeedBlocks),
				VuDetailedSpeedBlocks: vuDetailedSpeedBlocks,
			},
			Signature: &pb.SignatureFirstGen{
				Signature: r.Signature.Signature[:],
			},
		}
	}
	vuDetailedSpeed2 := make([]*pb.VuDetailedSpeedSecondGen, len(v.VuDetailedSpeedSecondGen))
	for i, r := range v.VuDetailedSpeedSecondGen {
		vuDetailedSpeedBlockRecords := make([]*pb.VuDetailedSpeedBlock, len(r.VuDetailedSpeedBlockRecordArray.Records))
		for j, rec := range r.VuDetailedSpeedBlockRecordArray.Records {
			speedsPerSecond := make([]byte, len(rec.SpeedsPerSecond))
			for k, r2 := range rec.SpeedsPerSecond {
				speedsPerSecond[k] = byte(r2)
			}
			vuDetailedSpeedBlockRecords[j] = &pb.VuDetailedSpeedBlock{
				SpeedBlockBeginDate: rec.SpeedBlockBeginDate.Decode().Unix(),
				SpeedsPerSecond:     speedsPerSecond,
			}
		}
		signatureRecords := make([]*pb.SignatureSecondGen, len(r.SignatureRecordArray.Records))
		for j, rec := range r.SignatureRecordArray.Records {
			signatureRecords[j] = &pb.SignatureSecondGen{
				Signature: rec.Signature,
			}
		}
		vuDetailedSpeed2[i] = &pb.VuDetailedSpeedSecondGen{
			Verified: r.Verified,
			VuDetailedSpeedBlockRecordArray: &pb.VuDetailedSpeedBlockRecordArray{
				RecordType:  uint32(r.VuDetailedSpeedBlockRecordArray.RecordType),
				RecordSize:  uint32(r.VuDetailedSpeedBlockRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuDetailedSpeedBlockRecordArray.NoOfRecords),
				Records:     vuDetailedSpeedBlockRecords,
			},
			SignatureRecordArray: &pb.SignatureRecordArray{
				RecordType:  uint32(r.SignatureRecordArray.RecordType),
				RecordSize:  uint32(r.SignatureRecordArray.RecordSize),
				NoOfRecords: uint32(r.SignatureRecordArray.NoOfRecords),
				Records:     signatureRecords,
			},
		}
	}

	vuTechnicalData1 := make([]*pb.VuTechnicalDataFirstGen, len(v.VuTechnicalDataFirstGen))
	for i, r := range v.VuTechnicalDataFirstGen {
		month, year := r.VuIdentification.VuSerialNumber.MonthYear.Decode()
		vuCalibrationRecords := make([]*pb.VuCalibrationRecordFirstGen, len(r.VuCalibrationData.VuCalibrationRecords))
		for j, rec := range r.VuCalibrationData.VuCalibrationRecords {
			vuCalibrationRecords[j] = &pb.VuCalibrationRecordFirstGen{
				CalibrationPurpose:                uint32(rec.CalibrationPurpose),
				WorkshopName:                      rec.WorkshopName.String(),
				WorkshopAddress:                   rec.WorkshopAddress.String(),
				WorkshopCardNumber:                &pb.FullCardNumber{},
				WorkshopCardExpiryDate:            rec.WorkshopCardExpiryDate.Decode().Unix(),
				VehicleIdentificationNumber:       rec.VehicleIdentificationNumber.String(),
				VehicleRegistrationIdentification: &pb.VehicleRegistrationIdentification{},
				WVehicleCharacteristicConstant:    uint32(rec.WVehicleCharacteristicConstant),
				KConstantOfRecordingEquipment:     uint32(rec.KConstantOfRecordingEquipment),
				LTyreCircumference:                uint32(rec.LTyreCircumference),
				TyreSize:                          rec.TyreSize.String(),
				AuthorisedSpeed:                   uint32(rec.AuthorisedSpeed),
				OldOdometerValue:                  uint32(rec.OldOdometerValue.Decode()),
				NewOdometerValue:                  uint32(rec.NewOdometerValue.Decode()),
				OldTimeValue:                      rec.OldTimeValue.Decode().Unix(),
				NewTimeValue:                      rec.NewTimeValue.Decode().Unix(),
				NextCalibrationDate:               rec.NextCalibrationDate.Decode().Unix(),
			}
		}
		vuTechnicalData1[i] = &pb.VuTechnicalDataFirstGen{
			Verified: r.Verified,
			VuIdentification: &pb.VuIdentificationFirstGen{
				VuManufacturerName:    r.VuIdentification.VuManufacturerName.String(),
				VuManufacturerAddress: r.VuIdentification.VuManufacturerAddress.String(),
				VuPartNumber:          r.VuIdentification.VuPartNumber.String(),
				VuSerialNumber: &pb.ExtendedSerialNumberFirstGen{
					SerialNumber: r.VuIdentification.VuSerialNumber.SerialNumber,
					MonthYear: &pb.MonthYear{
						Year:  uint32(year),
						Month: uint32(month),
					},
					Type:             uint32(r.VuIdentification.VuSerialNumber.Type),
					ManufacturerCode: uint32(r.VuIdentification.VuSerialNumber.ManufacturerCode),
				},
				VuSoftwareIdentification: &pb.VuSoftwareIdentification{
					VuSoftwareVersion:      r.VuIdentification.VuSoftwareIdentification.VuSoftwareVersion[:],
					VuSoftInstallationDate: r.VuIdentification.VuSoftwareIdentification.VuSoftInstallationDate.Decode().Unix(),
				},
				VuManufacturingDate: r.VuIdentification.VuManufacturingDate.Decode().Unix(),
				VuApprovalNumber:    r.VuIdentification.VuApprovalNumber.String(),
			},
			SensorPaired: &pb.SensorPaired{
				SensorSerialNumber:     &pb.ExtendedSerialNumberFirstGen{},
				SensorApprovalNumber:   r.SensorPaired.SensorApprovalNumber[:],
				SensorPairingDateFirst: r.SensorPaired.SensorPairingDateFirst.Decode().Unix(),
			},
			VuCalibrationData: &pb.VuCalibrationData{
				NoOfVuCalibrationRecords: uint32(r.VuCalibrationData.NoOfVuCalibrationRecords),
				VuCalibrationRecords:     vuCalibrationRecords,
			},
			Signature: &pb.SignatureFirstGen{
				Signature: r.Signature.Signature[:],
			},
		}
	}
	vuTechnicalData2 := make([]*pb.VuTechnicalDataSecondGen, len(v.VuTechnicalDataSecondGen))
	for i, r := range v.VuTechnicalDataSecondGen {
		vuIdentificationRecords := make([]*pb.VuIdentificationSecondGen, len(r.VuIdentificationRecordArray.Records))
		for j, rec := range r.VuIdentificationRecordArray.Records {
			month, year := rec.VuSerialNumber.MonthYear.Decode()
			vuIdentificationRecords[j] = &pb.VuIdentificationSecondGen{
				VuManufacturerName:    rec.VuManufacturerName.String(),
				VuManufacturerAddress: rec.VuManufacturerAddress.String(),
				VuPartNumber:          rec.VuPartNumber.String(),
				VuSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber: rec.VuSerialNumber.SerialNumber,
					MonthYear: &pb.MonthYear{
						Year:  uint32(year),
						Month: uint32(month),
					},
					Type:             uint32(rec.VuSerialNumber.Type),
					ManufacturerCode: uint32(rec.VuSerialNumber.ManufacturerCode),
				},
				VuSoftwareIdentification: &pb.VuSoftwareIdentification{
					VuSoftwareVersion:      rec.VuSoftwareIdentification.VuSoftwareVersion[:],
					VuSoftInstallationDate: rec.VuSoftwareIdentification.VuSoftInstallationDate.Decode().Unix(),
				},
				VuManufacturingDate: rec.VuManufacturingDate.Decode().Unix(),
				VuApprovalNumber:    rec.VuApprovalNumber.String(),
				VuGeneration:        uint32(rec.VuGeneration),
				VuAbility:           uint32(rec.VuAbility),
			}
		}
		vuSensorPairedRecords := make([]*pb.SensorPairedRecord, len(r.VuSensorPairedRecordArray.Records))
		for j, rec := range r.VuSensorPairedRecordArray.Records {
			month, year := rec.SensorSerialNumber.MonthYear.Decode()
			vuSensorPairedRecords[j] = &pb.SensorPairedRecord{
				SensorSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber: rec.SensorSerialNumber.SerialNumber,
					MonthYear: &pb.MonthYear{
						Year:  uint32(year),
						Month: uint32(month),
					},
					Type:             uint32(rec.SensorSerialNumber.Type),
					ManufacturerCode: uint32(rec.SensorSerialNumber.ManufacturerCode),
				},
				SensorApprovalNumber: rec.SensorApprovalNumber[:],
				SensorPairingDate:    rec.SensorPairingDate.Decode().Unix(),
			}
		}
		vuSensorExternalGnssCoupledRecords := make([]*pb.SensorExternalGNSSCoupledRecord, len(r.VuSensorExternalGNSSCoupledRecordArray.Records))
		for j, rec := range r.VuSensorExternalGNSSCoupledRecordArray.Records {
			month, year := rec.SensorSerialNumber.MonthYear.Decode()
			vuSensorExternalGnssCoupledRecords[j] = &pb.SensorExternalGNSSCoupledRecord{
				SensorSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber: rec.SensorSerialNumber.SerialNumber,
					MonthYear: &pb.MonthYear{
						Year:  uint32(year),
						Month: uint32(month),
					},
					Type:             uint32(rec.SensorSerialNumber.Type),
					ManufacturerCode: uint32(rec.SensorSerialNumber.ManufacturerCode),
				},
				SensorApprovalNumber: rec.SensorApprovalNumber.String(),
				SensorCouplingDate:   rec.SensorCouplingDate.Decode().Unix(),
			}
		}
		vuCalibrationRecords := make([]*pb.VuCalibrationRecordSecondGen, len(r.VuCalibrationRecordArray.Records))
		for j, rec := range r.VuCalibrationRecordArray.Records {
			sealData := make([]*pb.SealRecord, len(rec.SealDataVu))
			for k, r2 := range rec.SealDataVu {
				sealData[k] = &pb.SealRecord{
					EquipmentType: uint32(r2.SealRecord.EquipmentType),
					ExtendedSealIdentifier: &pb.ExtendedSealIdentifier{
						ManufacturerCode: r2.SealRecord.ExtendedSealIdentifier.ManufacturerCode[:],
						SealIdentifier:   r2.SealRecord.ExtendedSealIdentifier.SealIdentifier[:],
					},
				}
			}
			vuCalibrationRecords[j] = &pb.VuCalibrationRecordSecondGen{
				CalibrationPurpose: uint32(rec.CalibrationPurpose),
				WorkshopName:       rec.WorkshopName.String(),
				WorkshopAddress:    rec.WorkshopAddress.String(),
				WorkshopCardNumber: &pb.FullCardNumber{
					CardType:               uint32(rec.WorkshopCardNumber.CardType),
					CardIssuingMemberState: uint32(rec.WorkshopCardNumber.CardIssuingMemberState),
					CardNumber:             rec.WorkshopCardNumber.CardNumber.String(),
				},
				WorkshopCardExpiryDate:      rec.WorkshopCardExpiryDate.Decode().Unix(),
				VehicleIdentificationNumber: rec.VehicleIdentificationNumber.String(),
				VehicleRegistrationIdentification: &pb.VehicleRegistrationIdentification{
					VehicleRegistrationNation: uint32(rec.VehicleRegistrationIdentification.VehicleRegistrationNation),
					VehicleRegistrationNumber: rec.VehicleRegistrationIdentification.VehicleRegistrationNumber.String(),
				},
				WVehicleCharacteristicConstant: uint32(rec.WVehicleCharacteristicConstant),
				KConstantOfRecordingEquipment:  uint32(rec.KConstantOfRecordingEquipment),
				LTyreCircumference:             uint32(rec.LTyreCircumference),
				TyreSize:                       rec.TyreSize.String(),
				AuthorisedSpeed:                uint32(rec.AuthorisedSpeed),
				OldOdometerValue:               uint32(rec.OldOdometerValue.Decode()),
				NewOdometerValue:               uint32(rec.NewOdometerValue.Decode()),
				OldTimeValue:                   rec.OldTimeValue.Decode().Unix(),
				NewTimeValue:                   rec.NewTimeValue.Decode().Unix(),
				NextCalibrationDate:            rec.NextCalibrationDate.Decode().Unix(),
				SealDataVu:                     sealData,
			}
		}
		vuCardRecords := make([]*pb.VuCardRecord, len(r.VuCardRecordArray.Records))
		for j, rec := range r.VuCardRecordArray.Records {
			month, year := rec.CardExtendedSerialNumber.MonthYear.Decode()
			vuCardRecords[j] = &pb.VuCardRecord{
				CardNumberAndGenerationInformation: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenerationInformation.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenerationInformation.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenerationInformation.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenerationInformation.Generation),
				},
				CardExtendedSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber: rec.CardExtendedSerialNumber.SerialNumber,
					MonthYear: &pb.MonthYear{
						Year:  uint32(year),
						Month: uint32(month),
					},
					Type:             uint32(rec.CardExtendedSerialNumber.Type),
					ManufacturerCode: uint32(rec.CardExtendedSerialNumber.ManufacturerCode),
				},
				CardStuctureVersion: rec.CardStructureVersion[:],
				CardNumber:          rec.CardNumber.String(),
			}
		}
		vuItsConsentRecords := make([]*pb.VuITSConsentRecord, len(r.VuITSConsentRecordArray.Records))
		for j, rec := range r.VuITSConsentRecordArray.Records {
			vuItsConsentRecords[j] = &pb.VuITSConsentRecord{
				CardNumberAndGen: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGen.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGen.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGen.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGen.Generation),
				},
				Consent: uint32(rec.Consent),
			}
		}
		vuPowerSupplyInterruptionRecords := make([]*pb.VuPowerSupplyInterruptionRecord, len(r.VuPowerSupplyInterruptionRecordArray.Records))
		for j, rec := range r.VuPowerSupplyInterruptionRecordArray.Records {
			vuPowerSupplyInterruptionRecords[j] = &pb.VuPowerSupplyInterruptionRecord{
				EventType:          uint32(rec.EventType),
				EventRecordPurpose: uint32(rec.EventRecordPurpose),
				EventBeginTime:     rec.EventBeginTime.Decode().Unix(),
				EventEndTime:       rec.EventEndTime.Decode().Unix(),
				CardNumberAndGenDriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotBegin.Generation),
				},
				CardNumberAndGenDriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotEnd.Generation),
				},
				CardNumberAndGenCodriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotBegin.Generation),
				},
				CardNumberAndGenCodriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotEnd.Generation),
				},
				SimilarEventsNumber: uint32(rec.SimilarEventsNumber),
			}
		}
		signatureRecords := make([]*pb.SignatureSecondGen, len(r.SignatureRecordArray.Records))
		for j, rec := range r.SignatureRecordArray.Records {
			signatureRecords[j] = &pb.SignatureSecondGen{
				Signature: rec.Signature[:],
			}
		}
		vuTechnicalData2[i] = &pb.VuTechnicalDataSecondGen{
			Verified: r.Verified,
			VuIdentificationRecordArray: &pb.VuIdentificationRecordArray{
				RecordType:  uint32(r.VuIdentificationRecordArray.RecordType),
				RecordSize:  uint32(r.VuIdentificationRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuIdentificationRecordArray.NoOfRecords),
				Records:     vuIdentificationRecords,
			},
			VuSensorPairedRecordArray: &pb.VuSensorPairedRecordArray{
				RecordType:  uint32(r.VuSensorPairedRecordArray.RecordType),
				RecordSize:  uint32(r.VuSensorPairedRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuSensorPairedRecordArray.NoOfRecords),
				Records:     vuSensorPairedRecords,
			},
			VuSensorExternalGnssCoupledRecordArray: &pb.VuSensorExternalGNSSCoupledRecordArray{
				RecordType:  uint32(r.VuSensorExternalGNSSCoupledRecordArray.RecordType),
				RecordSize:  uint32(r.VuSensorExternalGNSSCoupledRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuSensorExternalGNSSCoupledRecordArray.NoOfRecords),
				Records:     vuSensorExternalGnssCoupledRecords,
			},
			VuCalibrationRecordArray: &pb.VuCalibrationRecordArray{
				RecordType:  uint32(r.VuCalibrationRecordArray.RecordType),
				RecordSize:  uint32(r.VuCalibrationRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuCalibrationRecordArray.NoOfRecords),
				Records:     vuCalibrationRecords,
			},
			VuCardRecordArray: &pb.VuCardRecordArray{
				RecordType:  uint32(r.VuCardRecordArray.RecordType),
				RecordSize:  uint32(r.VuCardRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuCardRecordArray.NoOfRecords),
				Records:     vuCardRecords,
			},
			VuItsConsentRecordArray: &pb.VuITSConsentRecordArray{
				RecordType:  uint32(r.VuITSConsentRecordArray.RecordType),
				RecordSize:  uint32(r.VuITSConsentRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuITSConsentRecordArray.NoOfRecords),
				Records:     vuItsConsentRecords,
			},
			VuPowerSupplyInterruptionRecordArray: &pb.VuPowerSupplyInterruptionRecordArray{
				RecordType:  uint32(r.VuPowerSupplyInterruptionRecordArray.RecordType),
				RecordSize:  uint32(r.VuPowerSupplyInterruptionRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuPowerSupplyInterruptionRecordArray.NoOfRecords),
				Records:     vuPowerSupplyInterruptionRecords,
			},
			SignatureRecordArray: &pb.SignatureRecordArray{
				RecordType:  uint32(r.SignatureRecordArray.RecordType),
				RecordSize:  uint32(r.SignatureRecordArray.RecordSize),
				NoOfRecords: uint32(r.SignatureRecordArray.NoOfRecords),
				Records:     signatureRecords,
			},
		}
	}

	vuTechnicalData2V2 := make([]*pb.VuTechnicalDataSecondGenV2, len(v.VuTechnicalDataSecondGenV2))
	for i, r := range v.VuTechnicalDataSecondGenV2 {
		vuIdentificationRecords := make([]*pb.VuIdentificationSecondGenV2, len(r.VuIdentificationRecordArray.Records))
		for j, rec := range r.VuIdentificationRecordArray.Records {
			month, year := rec.VuSerialNumber.MonthYear.Decode()
			vuIdentificationRecords[j] = &pb.VuIdentificationSecondGenV2{
				VuManufacturerName:    rec.VuManufacturerName.String(),
				VuManufacturerAddress: rec.VuManufacturerAddress.String(),
				VuPartNumber:          rec.VuPartNumber.String(),
				VuSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber: rec.VuSerialNumber.SerialNumber,
					MonthYear: &pb.MonthYear{
						Year:  uint32(year),
						Month: uint32(month),
					},
					Type:             uint32(rec.VuSerialNumber.Type),
					ManufacturerCode: uint32(rec.VuSerialNumber.ManufacturerCode),
				},
				VuSoftwareIdentification: &pb.VuSoftwareIdentification{
					VuSoftwareVersion:      rec.VuSoftwareIdentification.VuSoftwareVersion[:],
					VuSoftInstallationDate: rec.VuSoftwareIdentification.VuSoftInstallationDate.Decode().Unix(),
				},
				VuManufacturingDate: rec.VuManufacturingDate.Decode().Unix(),
				VuApprovalNumber:    rec.VuApprovalNumber.String(),
				VuGeneration:        uint32(rec.VuGeneration),
				VuAbility:           uint32(rec.VuAbility),
				VuDigitalMapVersion: rec.VuDigitalMapVersion.String(),
			}
		}
		vuSensorPairedRecords := make([]*pb.SensorPairedRecord, len(r.VuSensorPairedRecordArray.Records))
		for j, rec := range r.VuSensorPairedRecordArray.Records {
			month, year := rec.SensorSerialNumber.MonthYear.Decode()
			vuSensorPairedRecords[j] = &pb.SensorPairedRecord{
				SensorSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber: rec.SensorSerialNumber.SerialNumber,
					MonthYear: &pb.MonthYear{
						Year:  uint32(year),
						Month: uint32(month),
					},
					Type:             uint32(rec.SensorSerialNumber.Type),
					ManufacturerCode: uint32(rec.SensorSerialNumber.ManufacturerCode),
				},
				SensorApprovalNumber: rec.SensorApprovalNumber[:],
				SensorPairingDate:    rec.SensorPairingDate.Decode().Unix(),
			}
		}
		vuSensorExternalGnssCoupledRecords := make([]*pb.SensorExternalGNSSCoupledRecord, len(r.VuSensorExternalGNSSCoupledRecordArray.Records))
		for j, rec := range r.VuSensorExternalGNSSCoupledRecordArray.Records {
			month, year := rec.SensorSerialNumber.MonthYear.Decode()
			vuSensorExternalGnssCoupledRecords[j] = &pb.SensorExternalGNSSCoupledRecord{
				SensorSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber: rec.SensorSerialNumber.SerialNumber,
					MonthYear: &pb.MonthYear{
						Year:  uint32(year),
						Month: uint32(month),
					},
					Type:             uint32(rec.SensorSerialNumber.Type),
					ManufacturerCode: uint32(rec.SensorSerialNumber.ManufacturerCode),
				},
				SensorApprovalNumber: rec.SensorApprovalNumber.String(),
				SensorCouplingDate:   rec.SensorCouplingDate.Decode().Unix(),
			}
		}
		vuCalibrationRecords := make([]*pb.VuCalibrationRecordSecondGenV2, len(r.VuCalibrationRecordArray.Records))
		for j, rec := range r.VuCalibrationRecordArray.Records {
			sealData := make([]*pb.SealRecord, len(rec.SealDataVu))
			for k, r2 := range rec.SealDataVu {
				sealData[k] = &pb.SealRecord{
					EquipmentType: uint32(r2.SealRecord.EquipmentType),
					ExtendedSealIdentifier: &pb.ExtendedSealIdentifier{
						ManufacturerCode: r2.SealRecord.ExtendedSealIdentifier.ManufacturerCode[:],
						SealIdentifier:   r2.SealRecord.ExtendedSealIdentifier.SealIdentifier[:],
					},
				}
			}
			month, year := rec.SensorSerialNumber.MonthYear.Decode()
			gnssMonth, gnssYear := rec.SensorGNSSSerialNumber.MonthYear.Decode()
			rcmMonth, rcmYear := rec.RCMSerialNumber.MonthYear.Decode()
			vuCalibrationRecords[j] = &pb.VuCalibrationRecordSecondGenV2{
				CalibrationPurpose: uint32(rec.CalibrationPurpose),
				WorkshopName:       rec.WorkshopName.String(),
				WorkshopAddress:    rec.WorkshopAddress.String(),
				WorkshopCardNumber: &pb.FullCardNumber{
					CardType:               uint32(rec.WorkshopCardNumber.CardType),
					CardIssuingMemberState: uint32(rec.WorkshopCardNumber.CardIssuingMemberState),
					CardNumber:             rec.WorkshopCardNumber.CardNumber.String(),
				},
				WorkshopCardExpiryDate:      rec.WorkshopCardExpiryDate.Decode().Unix(),
				VehicleIdentificationNumber: rec.VehicleIdentificationNumber.String(),
				VehicleRegistrationIdentification: &pb.VehicleRegistrationIdentification{
					VehicleRegistrationNation: uint32(rec.VehicleRegistrationIdentification.VehicleRegistrationNation),
					VehicleRegistrationNumber: rec.VehicleRegistrationIdentification.VehicleRegistrationNumber.String(),
				},
				WVehicleCharacteristicConstant: uint32(rec.WVehicleCharacteristicConstant),
				KConstantOfRecordingEquipment:  uint32(rec.KConstantOfRecordingEquipment),
				LTyreCircumference:             uint32(rec.LTyreCircumference),
				TyreSize:                       rec.TyreSize.String(),
				AuthorisedSpeed:                uint32(rec.AuthorisedSpeed),
				OldOdometerValue:               uint32(rec.OldOdometerValue.Decode()),
				NewOdometerValue:               uint32(rec.NewOdometerValue.Decode()),
				OldTimeValue:                   rec.OldTimeValue.Decode().Unix(),
				NewTimeValue:                   rec.NewTimeValue.Decode().Unix(),
				NextCalibrationDate:            rec.NextCalibrationDate.Decode().Unix(),
				SensorSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber:     rec.SensorSerialNumber.SerialNumber,
					MonthYear:        &pb.MonthYear{Year: uint32(year), Month: uint32(month)},
					Type:             uint32(rec.SensorSerialNumber.Type),
					ManufacturerCode: uint32(rec.SensorSerialNumber.ManufacturerCode),
				},
				SensorGnssSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber:     rec.SensorGNSSSerialNumber.SerialNumber,
					MonthYear:        &pb.MonthYear{Year: uint32(gnssYear), Month: uint32(gnssMonth)},
					Type:             uint32(rec.SensorGNSSSerialNumber.Type),
					ManufacturerCode: uint32(rec.SensorGNSSSerialNumber.ManufacturerCode),
				},
				RcmSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber:     rec.RCMSerialNumber.SerialNumber,
					MonthYear:        &pb.MonthYear{Year: uint32(rcmYear), Month: uint32(rcmMonth)},
					Type:             uint32(rec.RCMSerialNumber.Type),
					ManufacturerCode: uint32(rec.RCMSerialNumber.ManufacturerCode),
				},
				SealDataVu:                  sealData,
				ByDefaultLoadType:           uint32(rec.ByDefaultLoadType),
				CalibrationCountry:          uint32(rec.CalibrationCountry),
				CalibrationCountryTimestamp: rec.CalibrationCountryTimestamp.Decode().Unix(),
			}
		}
		vuCardRecords := make([]*pb.VuCardRecord, len(r.VuCardRecordArray.Records))
		for j, rec := range r.VuCardRecordArray.Records {
			month, year := rec.CardExtendedSerialNumber.MonthYear.Decode()
			vuCardRecords[j] = &pb.VuCardRecord{
				CardNumberAndGenerationInformation: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenerationInformation.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenerationInformation.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenerationInformation.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenerationInformation.Generation),
				},
				CardExtendedSerialNumber: &pb.ExtendedSerialNumberSecondGen{
					SerialNumber: rec.CardExtendedSerialNumber.SerialNumber,
					MonthYear: &pb.MonthYear{
						Year:  uint32(year),
						Month: uint32(month),
					},
					Type:             uint32(rec.CardExtendedSerialNumber.Type),
					ManufacturerCode: uint32(rec.CardExtendedSerialNumber.ManufacturerCode),
				},
				CardStuctureVersion: rec.CardStructureVersion[:],
				CardNumber:          rec.CardNumber.String(),
			}
		}
		vuItsConsentRecords := make([]*pb.VuITSConsentRecord, len(r.VuITSConsentRecordArray.Records))
		for j, rec := range r.VuITSConsentRecordArray.Records {
			vuItsConsentRecords[j] = &pb.VuITSConsentRecord{
				CardNumberAndGen: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGen.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGen.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGen.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGen.Generation),
				},
				Consent: uint32(rec.Consent),
			}
		}
		vuPowerSupplyInterruptionRecords := make([]*pb.VuPowerSupplyInterruptionRecord, len(r.VuPowerSupplyInterruptionRecordArray.Records))
		for j, rec := range r.VuPowerSupplyInterruptionRecordArray.Records {
			vuPowerSupplyInterruptionRecords[j] = &pb.VuPowerSupplyInterruptionRecord{
				EventType:          uint32(rec.EventType),
				EventRecordPurpose: uint32(rec.EventRecordPurpose),
				EventBeginTime:     rec.EventBeginTime.Decode().Unix(),
				EventEndTime:       rec.EventEndTime.Decode().Unix(),
				CardNumberAndGenDriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotBegin.Generation),
				},
				CardNumberAndGenDriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenDriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenDriverSlotEnd.Generation),
				},
				CardNumberAndGenCodriverSlotBegin: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotBegin.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotBegin.Generation),
				},
				CardNumberAndGenCodriverSlotEnd: &pb.FullCardNumberAndGeneration{
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardIssuingMemberState),
						CardNumber:             rec.CardNumberAndGenCodriverSlotEnd.FullCardNumber.CardNumber.String(),
					},
					Generation: uint32(rec.CardNumberAndGenCodriverSlotEnd.Generation),
				},
				SimilarEventsNumber: uint32(rec.SimilarEventsNumber),
			}
		}
		signatureRecords := make([]*pb.SignatureSecondGen, len(r.SignatureRecordArray.Records))
		for j, rec := range r.SignatureRecordArray.Records {
			signatureRecords[j] = &pb.SignatureSecondGen{
				Signature: rec.Signature[:],
			}
		}
		vuTechnicalData2V2[i] = &pb.VuTechnicalDataSecondGenV2{
			Verified: r.Verified,
			VuIdentificationRecordArray: &pb.VuIdentificationRecordArrayV2{
				RecordType:  uint32(r.VuIdentificationRecordArray.RecordType),
				RecordSize:  uint32(r.VuIdentificationRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuIdentificationRecordArray.NoOfRecords),
				Records:     vuIdentificationRecords,
			},
			VuSensorPairedRecordArray: &pb.VuSensorPairedRecordArray{
				RecordType:  uint32(r.VuSensorPairedRecordArray.RecordType),
				RecordSize:  uint32(r.VuSensorPairedRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuSensorPairedRecordArray.NoOfRecords),
				Records:     vuSensorPairedRecords,
			},
			VuSensorExternalGnssCoupledRecordArray: &pb.VuSensorExternalGNSSCoupledRecordArray{
				RecordType:  uint32(r.VuSensorExternalGNSSCoupledRecordArray.RecordType),
				RecordSize:  uint32(r.VuSensorExternalGNSSCoupledRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuSensorExternalGNSSCoupledRecordArray.NoOfRecords),
				Records:     vuSensorExternalGnssCoupledRecords,
			},
			VuCalibrationRecordArray: &pb.VuCalibrationRecordArrayV2{
				RecordType:  uint32(r.VuCalibrationRecordArray.RecordType),
				RecordSize:  uint32(r.VuCalibrationRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuCalibrationRecordArray.NoOfRecords),
				Records:     vuCalibrationRecords,
			},
			VuCardRecordArray: &pb.VuCardRecordArray{
				RecordType:  uint32(r.VuCardRecordArray.RecordType),
				RecordSize:  uint32(r.VuCardRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuCardRecordArray.NoOfRecords),
				Records:     vuCardRecords,
			},
			VuItsConsentRecordArray: &pb.VuITSConsentRecordArray{
				RecordType:  uint32(r.VuITSConsentRecordArray.RecordType),
				RecordSize:  uint32(r.VuITSConsentRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuITSConsentRecordArray.NoOfRecords),
				Records:     vuItsConsentRecords,
			},
			VuPowerSupplyInterruptionRecordArray: &pb.VuPowerSupplyInterruptionRecordArray{
				RecordType:  uint32(r.VuPowerSupplyInterruptionRecordArray.RecordType),
				RecordSize:  uint32(r.VuPowerSupplyInterruptionRecordArray.RecordSize),
				NoOfRecords: uint32(r.VuPowerSupplyInterruptionRecordArray.NoOfRecords),
				Records:     vuPowerSupplyInterruptionRecords,
			},
			SignatureRecordArray: &pb.SignatureRecordArray{
				RecordType:  uint32(r.SignatureRecordArray.RecordType),
				RecordSize:  uint32(r.SignatureRecordArray.RecordSize),
				NoOfRecords: uint32(r.SignatureRecordArray.NoOfRecords),
				Records:     signatureRecords,
			},
		}
	}

	resp := &pb.ParseVuResponse{
		Vu: &pb.Vu{
			VuDownloadInterfaceVersion: &pb.VuDownloadInterfaceVersion{
				Verified:                 v.VuDownloadInterfaceVersion.Verified,
				DownloadInterfaceVersion: v.VuDownloadInterfaceVersion.DownloadInterfaceVersion[:],
			},
			VuOverview_1: &pb.VuOverviewFirstGen{
				Verified:                    v.VuOverviewFirstGen.Verified,
				MemberStateCertificate:      vuOverview1MemberStateCertificate,
				VuCertificate:               vuOverview1VuCertificate,
				VehicleIdentificationNumber: v.VuOverviewFirstGen.VehicleIdentificationNumber.String(),
				VehicleRegistrationIdentification: &pb.VehicleRegistrationIdentification{
					VehicleRegistrationNation: uint32(v.VuOverviewFirstGen.VehicleRegistrationIdentification.VehicleRegistrationNation),
					VehicleRegistrationNumber: v.VuOverviewFirstGen.VehicleRegistrationIdentification.VehicleRegistrationNumber.String(),
				},
				CurrentDateTime: v.VuOverviewFirstGen.CurrentDateTime.Decode().Unix(),
				VuDownloadablePeriod: &pb.VuDownloadablePeriod{
					MinDownloadableTime: v.VuOverviewFirstGen.VuDownloadablePeriod.MinDownloadableTime.Decode().Unix(),
					MaxDownloadableTime: v.VuOverviewFirstGen.VuDownloadablePeriod.MaxDownloadableTime.Decode().Unix(),
				},
				CardSlotsStatus: uint32(v.VuOverviewFirstGen.CardSlotsStatus),
				VuDownloadActivityData: &pb.VuDownloadActivityDataFirstGen{
					DownloadingTime: v.VuOverviewFirstGen.VuDownloadActivityData.DownloadingTime.Decode().Unix(),
					FullCardNumber: &pb.FullCardNumber{
						CardType:               uint32(v.VuOverviewFirstGen.VuDownloadActivityData.FullCardNumber.CardType),
						CardIssuingMemberState: uint32(v.VuOverviewFirstGen.VuDownloadActivityData.FullCardNumber.CardIssuingMemberState),
						CardNumber:             v.VuOverviewFirstGen.VuDownloadActivityData.FullCardNumber.CardNumber.String(),
					},
					CompanyOrWorkshopName: v.VuOverviewFirstGen.VuDownloadActivityData.CompanyOrWorkshopName.String(),
				},
				VuCompanyLocksData: &pb.VuCompanyLocksDataFirstGen{
					NoOfLocks:             uint32(v.VuOverviewFirstGen.VuCompanyLocksData.NoOfLocks),
					VuCompanyLocksRecords: vuOverviewFirstGenVuCompanyLocksRecords,
				},
				VuControlActivityData: &pb.VuControlActivityDataFirstGen{
					NoOfControls:             uint32(v.VuOverviewFirstGen.VuControlActivityData.NoOfControls),
					VuControlActivityRecords: vuOverviewFirstGenVuControlActivityRecords,
				},
				Signature: &pb.SignatureFirstGen{
					Signature: v.VuOverviewFirstGen.Signature.Signature[:],
				},
			},
			VuOverview_2: &pb.VuOverviewSecondGen{
				Verified: v.VuOverviewSecondGen.Verified,
				MemberStateCertificateRecordArray: &pb.MemberStateCertificateRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.MemberStateCertificateRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.MemberStateCertificateRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.MemberStateCertificateRecordArray.NoOfRecords),
					Records:     vuOverview2MemberStateCertificateRecords,
				},
				VuCertificateRecordArray: &pb.VuCertificateRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.VuCertificateRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.VuCertificateRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.VuCertificateRecordArray.NoOfRecords),
					Records:     vuOverview2VuCertificateRecords,
				},
				VehicleIdentificationNumberRecordArray: &pb.VehicleIdentificationNumberRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.VehicleIdentificationNumberRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.VehicleIdentificationNumberRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.VehicleIdentificationNumberRecordArray.NoOfRecords),
					Records:     vuOverview2VehicleIdentificationNumberRecords,
				},
				VehicleRegistrationNumberRecordArray: &pb.VehicleRegistrationNumberRecordArray{
					RecordType:  uint32(decoder.RecordTypeVehicleRegistrationNumber),
					RecordSize:  uint32(v.VuOverviewSecondGen.VehicleRegistrationNumberRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.VehicleRegistrationNumberRecordArray.NoOfRecords),
					Records:     vuOverview2VehicleRegistrationNumberRecords,
				},
				CurrentDateTimeRecordArray: &pb.CurrentDateTimeRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.CurrentDateTimeRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.CurrentDateTimeRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.CurrentDateTimeRecordArray.NoOfRecords),
					Records:     vuOverview2CurrentDateTimeRecords,
				},
				VuDownloadablePeriodRecordArray: &pb.VuDownloadablePeriodRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.VuDownloadablePeriodRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.VuDownloadablePeriodRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.VuDownloadablePeriodRecordArray.NoOfRecords),
					Records:     vuOverview2VuDownloadablePeriodRecords,
				},
				CardSlotsStatusRecordArray: &pb.CardSlotsStatusRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.CardSlotsStatusRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.CardSlotsStatusRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.CardSlotsStatusRecordArray.NoOfRecords),
					Records:     vuOverview2CardSlotsStatusRecords,
				},
				VuDownloadActivityDataRecordArray: &pb.VuDownloadActivityDataRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.VuDownloadActivityDataRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.VuDownloadActivityDataRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.VuDownloadActivityDataRecordArray.NoOfRecords),
					Records:     vuOverview2VuDownloadActivityDataRecords,
				},
				VuCompanyLocksRecordArray: &pb.VuCompanyLocksRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.VuCompanyLocksRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.VuCompanyLocksRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.VuCompanyLocksRecordArray.NoOfRecords),
					Records:     vuOverview2VuCompanyLocksRecords,
				},
				VuControlActivityRecordArray: &pb.VuControlActivityRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.VuControlActivityRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.VuControlActivityRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.VuControlActivityRecordArray.NoOfRecords),
					Records:     vuOverview2ControlActivityRecords,
				},
				SignatureRecordArray: &pb.SignatureRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGen.SignatureRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGen.SignatureRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGen.SignatureRecordArray.NoOfRecords),
					Records:     vuOverview2SignatureRecords,
				},
			},
			VuOverview_2_2: &pb.VuOverviewSecondGenV2{
				Verified: v.VuOverviewSecondGenV2.Verified,
				MemberStateCertificateRecordArray: &pb.MemberStateCertificateRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.MemberStateCertificateRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.MemberStateCertificateRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.MemberStateCertificateRecordArray.NoOfRecords),
					Records:     vuOverview2MemberStateCertificateRecordsV2,
				},
				VuCertificateRecordArray: &pb.VuCertificateRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.VuCertificateRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.VuCertificateRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.VuCertificateRecordArray.NoOfRecords),
					Records:     vuOverview2VuCertificateRecordsV2,
				},
				VehicleRegistrationIdentificationRecordArray: &pb.VehicleRegistrationIdentificationRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.VehicleRegistrationIdentificationRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.VehicleRegistrationIdentificationRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.VehicleRegistrationIdentificationRecordArray.NoOfRecords),
					Records:     vuOverview2VehicleRegistrationIdentificationRecordsV2,
				},
				CurrentDateTimeRecordArray: &pb.CurrentDateTimeRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.CurrentDateTimeRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.CurrentDateTimeRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.CurrentDateTimeRecordArray.NoOfRecords),
					Records:     vuOverview2CurrentDateTimeRecordsV2,
				},
				VuDownloadablePeriodRecordArray: &pb.VuDownloadablePeriodRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.VuDownloadablePeriodRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.VuDownloadablePeriodRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.VuDownloadablePeriodRecordArray.NoOfRecords),
					Records:     vuOverview2VuDownloadablePeriodRecordsV2,
				},
				CardSlotsStatusRecordArray: &pb.CardSlotsStatusRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.CardSlotsStatusRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.CardSlotsStatusRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.CardSlotsStatusRecordArray.NoOfRecords),
					Records:     vuOverview2CardSlotsStatusRecordsV2,
				},
				VuDownloadActivityDataRecordArray: &pb.VuDownloadActivityDataRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.VuDownloadActivityDataRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.VuDownloadActivityDataRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.VuDownloadActivityDataRecordArray.NoOfRecords),
					Records:     vuOverview2VuDownloadActivityDataRecordsV2,
				},
				VuCompanyLocksRecordArray: &pb.VuCompanyLocksRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.VuCompanyLocksRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.VuCompanyLocksRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.VuCompanyLocksRecordArray.NoOfRecords),
					Records:     vuOverview2VuCompanyLocksRecordsV2,
				},
				VuControlActivityRecordArray: &pb.VuControlActivityRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.VuControlActivityRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.VuControlActivityRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.VuControlActivityRecordArray.NoOfRecords),
					Records:     vuOverview2ControlActivityRecordsV2,
				},
				SignatureRecordArray: &pb.SignatureRecordArray{
					RecordType:  uint32(v.VuOverviewSecondGenV2.SignatureRecordArray.RecordType),
					RecordSize:  uint32(v.VuOverviewSecondGenV2.SignatureRecordArray.RecordSize),
					NoOfRecords: uint32(v.VuOverviewSecondGenV2.SignatureRecordArray.NoOfRecords),
					Records:     vuOverview2SignatureRecordsV2,
				},
			},
			VuActivities_1:        vuActivities1,
			VuActivities_2:        vuActivities2,
			VuActivities_2_2:      vuActivities2V2,
			VuEventsAndFaults_1:   vuEventsAndFaults1,
			VuEventsAndFaults_2:   vuEventsAndFaults2,
			VuEventsAndFaults_2_2: vuEventsAndFaults2V2,
			VuDetailedSpeed_1:     vuDetailedSpeed1,
			VuDetailedSpeed_2:     vuDetailedSpeed2,
			VuTechnicalData_1:     vuTechnicalData1,
			VuTechnicalData_2:     vuTechnicalData2,
			VuTechnicalData_2_2:   vuTechnicalData2V2,
		},
	}
	return resp, nil
}

func (s *server) ParseCard(ctx context.Context, req *pb.ParseCardRequest) (*pb.ParseCardResponse, error) {
	mutex.Lock()
	defer mutex.Unlock()
	var c decoder.Card
	_, err := decoder.UnmarshalTLV(req.Data, &c)
	if err != nil {
		log.Printf("error: could not parse card: %v", err)
		return nil, err
	}
	cardIccIdentification1Month, cardIccIdentification1Year := c.CardIccIdentificationFirstGen.CardExtendedSerialNumber.MonthYear.Decode()
	cardIccIdentification1ModuleEmbedder, _ := c.CardIccIdentificationFirstGen.EmbedderIcAssemblerId.ModuleEmbedder.Decode()
	cardIccIdentification1 := &pb.CardIccIdentificationFirstGen{
		Verified:  c.CardIccIdentificationFirstGen.Verified,
		ClockStop: uint32(c.CardIccIdentificationFirstGen.ClockStop),
		CardExtendedSerialNumber: &pb.ExtendedSerialNumberFirstGen{
			SerialNumber: c.CardIccIdentificationFirstGen.CardExtendedSerialNumber.SerialNumber,
			MonthYear: &pb.MonthYear{
				Year:  uint32(cardIccIdentification1Year),
				Month: uint32(cardIccIdentification1Month),
			},
			Type:             uint32(c.CardIccIdentificationFirstGen.CardExtendedSerialNumber.Type),
			ManufacturerCode: uint32(c.CardIccIdentificationFirstGen.CardExtendedSerialNumber.ManufacturerCode),
		},
		CardApprovalNumber: c.CardIccIdentificationFirstGen.CardApprovalNumber.String(),
		CardPersonaliserId: uint32(c.CardIccIdentificationFirstGen.CardPersonaliserID),
		EmbedderIcAssemblerId: &pb.EmbedderIcAssemblerId{
			CountryCode:             c.CardIccIdentificationFirstGen.EmbedderIcAssemblerId.CountryCode.String(),
			ModuleEmbedder:          uint32(cardIccIdentification1ModuleEmbedder),
			ManufacturerInformation: uint32(c.CardIccIdentificationFirstGen.EmbedderIcAssemblerId.ManufacturerInformation),
		},
		IcIdentifier: c.CardIccIdentificationFirstGen.IcIdentifier[:],
	}
	cardIccIdentification2Month, cardIccIdentification2Year := c.CardIccIdentificationSecondGen.CardExtendedSerialNumber.MonthYear.Decode()
	cardIccIdentification2ModuleEmbedder, _ := c.CardIccIdentificationSecondGen.EmbedderIcAssemblerId.ModuleEmbedder.Decode()
	cardIccIdentification2 := &pb.CardIccIdentificationSecondGen{
		Verified:  c.CardIccIdentificationSecondGen.Verified,
		ClockStop: uint32(c.CardIccIdentificationSecondGen.ClockStop),
		CardExtendedSerialNumber: &pb.ExtendedSerialNumberSecondGen{
			SerialNumber: c.CardIccIdentificationSecondGen.CardExtendedSerialNumber.SerialNumber,
			MonthYear: &pb.MonthYear{
				Year:  uint32(cardIccIdentification2Year),
				Month: uint32(cardIccIdentification2Month),
			},
			Type:             uint32(c.CardIccIdentificationSecondGen.CardExtendedSerialNumber.Type),
			ManufacturerCode: uint32(c.CardIccIdentificationSecondGen.CardExtendedSerialNumber.ManufacturerCode),
		},
		CardApprovalNumber: c.CardIccIdentificationSecondGen.CardApprovalNumber.String(),
		CardPersonaliserId: uint32(c.CardIccIdentificationSecondGen.CardPersonaliserID),
		EmbedderIcAssemblerId: &pb.EmbedderIcAssemblerId{
			CountryCode:             c.CardIccIdentificationSecondGen.EmbedderIcAssemblerId.CountryCode.String(),
			ModuleEmbedder:          uint32(cardIccIdentification2ModuleEmbedder),
			ManufacturerInformation: uint32(c.CardIccIdentificationSecondGen.EmbedderIcAssemblerId.ManufacturerInformation),
		},
		IcIdentifier: c.CardIccIdentificationSecondGen.IcIdentifier[:],
	}
	cardChipCardIdentification1 := &pb.CardChipIdentification{
		Verified:                 c.CardChipIdentificationFirstGen.Verified,
		IcSerialNumber:           c.CardChipIdentificationFirstGen.IcSerialNumber[:],
		IcManufacturingReference: c.CardChipIdentificationFirstGen.IcManufacturingReference[:],
	}
	cardChipCardIdentification2 := &pb.CardChipIdentification{
		Verified:                 c.CardChipIdentificationSecondGen.Verified,
		IcSerialNumber:           c.CardChipIdentificationSecondGen.IcSerialNumber[:],
		IcManufacturingReference: c.CardChipIdentificationSecondGen.IcManufacturingReference[:],
	}
	driverCardApplicationIdentification1 := &pb.DriverCardApplicationIdentificationFirstGen{
		Verified:                c.DriverCardApplicationIdentificationFirstGen.Verified,
		TypeOfTachographCardId:  uint32(c.DriverCardApplicationIdentificationFirstGen.TypeOfTachographCardId),
		CardStructureVersion:    c.DriverCardApplicationIdentificationFirstGen.CardStructureVersion[:],
		NoOfEventsPerType:       uint32(c.DriverCardApplicationIdentificationFirstGen.NoOfEventsPerTypeFirstGen),
		NoOfFaultsPerType:       uint32(c.DriverCardApplicationIdentificationFirstGen.NoOfFaultsPerTypeFirstGen),
		ActivityStructureLength: uint32(c.DriverCardApplicationIdentificationFirstGen.ActivityStructureLengthFirstGen),
		NoOfCardVehicleRecords:  uint32(c.DriverCardApplicationIdentificationFirstGen.NoOfCardVehicleRecordsFirstGen),
		NoOfCardPlaceRecords:    uint32(c.DriverCardApplicationIdentificationFirstGen.NoOfCardPlaceRecordsFirstGen),
	}
	driverCardApplicationIdentification2 := &pb.DriverCardApplicationIdentificationSecondGen{
		Verified:                     c.DriverCardApplicationIdentificationSecondGen.Verified,
		TypeOfTachographCardId:       uint32(c.DriverCardApplicationIdentificationSecondGen.TypeOfTachographCardId),
		CardStructureVersion:         c.DriverCardApplicationIdentificationSecondGen.CardStructureVersion[:],
		NoOfEventsPerType:            uint32(c.DriverCardApplicationIdentificationSecondGen.NoOfEventsPerTypeSecondGen),
		NoOfFaultsPerType:            uint32(c.DriverCardApplicationIdentificationSecondGen.NoOfFaultsPerTypeSecondGen),
		ActivityStructureLength:      uint32(c.DriverCardApplicationIdentificationSecondGen.ActivityStructureLengthSecondGen),
		NoOfCardVehicleRecords:       uint32(c.DriverCardApplicationIdentificationSecondGen.NoOfCardVehicleRecordsSecondGen),
		NoOfCardPlaceRecords:         uint32(c.DriverCardApplicationIdentificationSecondGen.NoOfCardPlaceRecordsSecondGen),
		NoOfGnssAdRecords:            uint32(c.DriverCardApplicationIdentificationSecondGen.NoOfGNSSADRecords),
		NoOfSpecificConditionRecords: uint32(c.DriverCardApplicationIdentificationSecondGen.NoOfSpecificConditionRecords),
		NoOfCardVehicleUnitRecords:   uint32(c.DriverCardApplicationIdentificationSecondGen.NoOfCardVehicleUnitRecords),
	}
	cardEventRecords1 := make([]*pb.CardEventDataFirstGen_CardEventRecordsArrayElement, len(c.CardEventDataFirstGen.CardEventRecordsArray))
	for i, r := range c.CardEventDataFirstGen.CardEventRecordsArray {
		records := make([]*pb.CardEventRecord, len(r.CardEventRecords))
		for j, rec := range r.CardEventRecords {
			records[j] = &pb.CardEventRecord{
				EventType:      uint32(rec.EventType),
				EventBeginTime: rec.EventBeginTime.Decode().Unix(),
				EventEndTime:   rec.EventEndTime.Decode().Unix(),
				EventVehicleRegistration: &pb.VehicleRegistrationIdentification{
					VehicleRegistrationNation: uint32(rec.EventVehicleRegistration.VehicleRegistrationNation),
					VehicleRegistrationNumber: rec.EventVehicleRegistration.VehicleRegistrationNumber.String(),
				},
			}
		}
		cardEventRecords1[i] = &pb.CardEventDataFirstGen_CardEventRecordsArrayElement{
			CardEventRecords: records,
		}
	}
	cardEventData1 := &pb.CardEventDataFirstGen{
		Verified:              c.CardEventDataFirstGen.Verified,
		CardEventRecordsArray: cardEventRecords1,
	}
	cardEventRecords2 := make([]*pb.CardEventDataSecondGen_CardEventRecordsArrayElement, len(c.CardEventDataSecondGen.CardEventRecordsArray))
	for i, r := range c.CardEventDataSecondGen.CardEventRecordsArray {
		records := make([]*pb.CardEventRecord, len(r.CardEventRecords))
		for j, rec := range r.CardEventRecords {
			records[j] = &pb.CardEventRecord{
				EventType:      uint32(rec.EventType),
				EventBeginTime: rec.EventBeginTime.Decode().Unix(),
				EventEndTime:   rec.EventEndTime.Decode().Unix(),
				EventVehicleRegistration: &pb.VehicleRegistrationIdentification{
					VehicleRegistrationNation: uint32(rec.EventVehicleRegistration.VehicleRegistrationNation),
					VehicleRegistrationNumber: rec.EventVehicleRegistration.VehicleRegistrationNumber.String(),
				},
			}
		}
		cardEventRecords2[i] = &pb.CardEventDataSecondGen_CardEventRecordsArrayElement{
			CardEventRecords: records,
		}
	}
	cardEventData2 := &pb.CardEventDataSecondGen{
		Verified:              c.CardEventDataSecondGen.Verified,
		CardEventRecordsArray: cardEventRecords2,
	}
	cardFaultRecordsArray1 := make([]*pb.CardFaultDataFirstGen_CardFaultRecordsArrayElement, len(c.CardFaultDataFirstGen.CardFaultRecordsArray))
	for i, r := range c.CardFaultDataFirstGen.CardFaultRecordsArray {
		records := make([]*pb.CardFaultRecord, len(r.CardFaultRecords))
		for j, rec := range r.CardFaultRecords {
			records[j] = &pb.CardFaultRecord{
				FaultType:      uint32(rec.FaultType),
				FaultBeginTime: rec.FaultBeginTime.Decode().Unix(),
				FaultEndTime:   rec.FaultEndTime.Decode().Unix(),
				FaultVehicleRegistration: &pb.VehicleRegistrationIdentification{
					VehicleRegistrationNation: uint32(rec.FaultVehicleRegistration.VehicleRegistrationNation),
					VehicleRegistrationNumber: rec.FaultVehicleRegistration.VehicleRegistrationNumber.String(),
				},
			}
		}
		cardFaultRecordsArray1[i] = &pb.CardFaultDataFirstGen_CardFaultRecordsArrayElement{
			CardFaultRecords: records,
		}
	}
	cardFaultData1 := &pb.CardFaultDataFirstGen{
		Verified:              c.CardFaultDataFirstGen.Verified,
		CardFaultRecordsArray: cardFaultRecordsArray1,
	}
	cardFaultRecordsArray2 := make([]*pb.CardFaultDataSecondGen_CardFaultRecordsArrayElement, len(c.CardFaultDataSecondGen.CardFaultRecordsArray))
	for i, r := range c.CardFaultDataSecondGen.CardFaultRecordsArray {
		records := make([]*pb.CardFaultRecord, len(r.CardFaultRecords))
		for j, rec := range r.CardFaultRecords {
			records[j] = &pb.CardFaultRecord{
				FaultType:      uint32(rec.FaultType),
				FaultBeginTime: rec.FaultBeginTime.Decode().Unix(),
				FaultEndTime:   rec.FaultEndTime.Decode().Unix(),
				FaultVehicleRegistration: &pb.VehicleRegistrationIdentification{
					VehicleRegistrationNation: uint32(rec.FaultVehicleRegistration.VehicleRegistrationNation),
					VehicleRegistrationNumber: rec.FaultVehicleRegistration.VehicleRegistrationNumber.String(),
				},
			}
		}
		cardFaultRecordsArray1[i] = &pb.CardFaultDataFirstGen_CardFaultRecordsArrayElement{
			CardFaultRecords: records,
		}
	}
	cardFaultData2 := &pb.CardFaultDataSecondGen{
		Verified:              c.CardFaultDataSecondGen.Verified,
		CardFaultRecordsArray: cardFaultRecordsArray2,
	}
	decodedCardDriverActivity1 := c.CardDriverActivityFirstGen.Decode()
	activityDailyRecords1 := make([]*pb.CardActivityDailyRecord, len(decodedCardDriverActivity1))
	for i, r := range decodedCardDriverActivity1 {
		activityChangeInfo := make([]*pb.ActivityChangeInfo, len(r.ActivityChangeInfo))
		for j, rec := range r.ActivityChangeInfo {
			decodedChangeInfo := rec.Decode()
			activityChangeInfo[j] = &pb.ActivityChangeInfo{
				Driver:      decodedChangeInfo.Driver,
				Team:        decodedChangeInfo.Team,
				CardPresent: decodedChangeInfo.CardPresent,
				WorkType:    uint32(decodedChangeInfo.WorkType),
				Minutes:     uint32(decodedChangeInfo.Minutes),
			}
		}
		presence, _ := r.ActivityDailyPresenceCounter.Decode()
		activityDailyRecords1[i] = &pb.CardActivityDailyRecord{
			ActivityPreviousRecordLength: uint32(r.ActivityPreviousRecordLength),
			ActivityRecordLength:         uint32(r.ActivityRecordLength),
			ActivityRecordDate:           r.ActivityRecordDate.Decode().Unix(),
			ActivityDailyPresenceCounter: uint32(presence),
			ActivityDayDistance:          uint32(r.ActivityDayDistance),
			ActivityChangeInfo:           activityChangeInfo,
		}
	}
	cardDriverActivity1 := &pb.CardDriverActivityFirstGen{
		Verified:                       c.CardDriverActivityFirstGen.Verified,
		ActivityPointerOldestDayRecord: uint32(c.CardDriverActivityFirstGen.ActivityPointerOldestDayRecord),
		ActivityPointerNewestRecord:    uint32(c.CardDriverActivityFirstGen.ActivityPointerNewestRecord),
		DecodedActivityDailyRecords:    activityDailyRecords1,
	}
	decodedCardDriverActivity2 := c.CardDriverActivitySecondGen.Decode()
	activityDailyRecords2 := make([]*pb.CardActivityDailyRecord, len(decodedCardDriverActivity2))
	for i, r := range decodedCardDriverActivity2 {
		activityChangeInfo := make([]*pb.ActivityChangeInfo, len(r.ActivityChangeInfo))
		for j, rec := range r.ActivityChangeInfo {
			decodedChangeInfo := rec.Decode()
			activityChangeInfo[j] = &pb.ActivityChangeInfo{
				Driver:      decodedChangeInfo.Driver,
				Team:        decodedChangeInfo.Team,
				CardPresent: decodedChangeInfo.CardPresent,
				WorkType:    uint32(decodedChangeInfo.WorkType),
				Minutes:     uint32(decodedChangeInfo.Minutes),
			}
		}
		presence, _ := r.ActivityDailyPresenceCounter.Decode()
		activityDailyRecords2[i] = &pb.CardActivityDailyRecord{
			ActivityPreviousRecordLength: uint32(r.ActivityPreviousRecordLength),
			ActivityRecordLength:         uint32(r.ActivityRecordLength),
			ActivityRecordDate:           r.ActivityRecordDate.Decode().Unix(),
			ActivityDailyPresenceCounter: uint32(presence),
			ActivityDayDistance:          uint32(r.ActivityDayDistance),
			ActivityChangeInfo:           activityChangeInfo,
		}
	}
	cardDriverActivity2 := &pb.CardDriverActivitySecondGen{
		Verified:                       c.CardDriverActivitySecondGen.Verified,
		ActivityPointerOldestDayRecord: uint32(c.CardDriverActivitySecondGen.ActivityPointerOldestDayRecord),
		ActivityPointerNewestRecord:    uint32(c.CardDriverActivitySecondGen.ActivityPointerNewestRecord),
		DecodedActivityDailyRecords:    activityDailyRecords2,
	}
	cardVehicleRecords1 := make([]*pb.CardVehicleRecordFirstGen, len(c.CardVehiclesUsedFirstGen.CardVehicleRecords))
	for i, r := range c.CardVehiclesUsedFirstGen.CardVehicleRecords {
		blockCounter, _ := r.VuDataBlockCounter.Decode()
		cardVehicleRecords1[i] = &pb.CardVehicleRecordFirstGen{
			VehicleOdometerBegin: uint32(r.VehicleOdometerBegin.Decode()),
			VehicleOdometerEnd:   uint32(r.VehicleOdometerEnd.Decode()),
			VehicleFirstUse:      r.VehicleFirstUse.Decode().Unix(),
			VehicleLastUse:       r.VehicleLastUse.Decode().Unix(),
			VehicleRegistration: &pb.VehicleRegistrationIdentification{
				VehicleRegistrationNation: uint32(r.VehicleRegistration.VehicleRegistrationNation),
				VehicleRegistrationNumber: r.VehicleRegistration.VehicleRegistrationNumber.String(),
			},
			VuDataBlockCounter: uint32(blockCounter),
		}
	}
	cardVehiclesUsed1 := &pb.CardVehiclesUsedFirstGen{
		Verified:                   c.CardVehiclesUsedFirstGen.Verified,
		VehiclePointerNewestRecord: uint32(c.CardVehiclesUsedFirstGen.VehiclePointerNewestRecord),
		CardVehicleRecords:         cardVehicleRecords1,
	}
	cardVehicleRecords2 := make([]*pb.CardVehicleRecordSecondGen, len(c.CardVehiclesUsedSecondGen.CardVehicleRecords))
	for i, r := range c.CardVehiclesUsedSecondGen.CardVehicleRecords {
		blockCounter, _ := r.VuDataBlockCounter.Decode()
		cardVehicleRecords2[i] = &pb.CardVehicleRecordSecondGen{
			VehicleOdometerBegin: uint32(r.VehicleOdometerBegin.Decode()),
			VehicleOdometerEnd:   uint32(r.VehicleOdometerEnd.Decode()),
			VehicleFirstUse:      r.VehicleFirstUse.Decode().Unix(),
			VehicleLastUse:       r.VehicleLastUse.Decode().Unix(),
			VehicleRegistration: &pb.VehicleRegistrationIdentification{
				VehicleRegistrationNation: uint32(r.VehicleRegistration.VehicleRegistrationNation),
				VehicleRegistrationNumber: r.VehicleRegistration.VehicleRegistrationNumber.String(),
			},
			VuDataBlockCounter:          uint32(blockCounter),
			VehicleIdentificationNumber: r.VehicleIdentificationNumber.String(),
		}
	}
	cardVehiclesUsed2 := &pb.CardVehiclesUsedSecondGen{
		Verified:                   c.CardVehiclesUsedSecondGen.Verified,
		VehiclePointerNewestRecord: uint32(c.CardVehiclesUsedSecondGen.VehiclePointerNewestRecord),
		CardVehicleRecords:         cardVehicleRecords2,
	}
	placeRecords1 := make([]*pb.PlaceRecordFirstGen, len(c.CardPlaceDailyWorkPeriodFirstGen.PlaceRecords))
	for i, r := range c.CardPlaceDailyWorkPeriodFirstGen.PlaceRecords {
		placeRecords1[i] = &pb.PlaceRecordFirstGen{
			EntryTime:                r.EntryTime.Decode().Unix(),
			EntryTypeDailyWorkPeriod: uint32(r.EntryTypeDailyWorkPeriod),
			DailyWorkPeriodCountry:   uint32(r.DailyWorkPeriodCountry),
			DailyWorkPeriodRegion:    uint32(r.DailyWorkPeriodRegion),
			VehicleOdometerValue:     uint32(r.VehicleOdometerValue.Decode()),
		}
	}
	cardPlaceDailyWorkPeriod1 := &pb.CardPlaceDailyWorkPeriodFirstGen{
		Verified:                 c.CardPlaceDailyWorkPeriodFirstGen.Verified,
		PlacePointerNewestRecord: uint32(c.CardPlaceDailyWorkPeriodFirstGen.PlacePointerNewestRecord),
		PlaceRecords:             placeRecords1,
	}
	placeRecords2 := make([]*pb.PlaceRecordSecondGen, len(c.CardPlaceDailyWorkPeriodSecondGen.PlaceRecords))
	for i, r := range c.CardPlaceDailyWorkPeriodSecondGen.PlaceRecords {
		lon, lat := r.EntryGNSSPlaceRecord.GeoCoordinates.Decode()
		placeRecords2[i] = &pb.PlaceRecordSecondGen{
			EntryTime:                r.EntryTime.Decode().Unix(),
			EntryTypeDailyWorkPeriod: uint32(r.EntryTypeDailyWorkPeriod),
			DailyWorkPeriodCountry:   uint32(r.DailyWorkPeriodCountry),
			DailyWorkPeriodRegion:    uint32(r.DailyWorkPeriodRegion),
			VehicleOdometerValue:     uint32(r.VehicleOdometerValue.Decode()),
			EntryGnssPlaceRecord: &pb.GNSSPlaceRecord{
				TimeStamp:    r.EntryGNSSPlaceRecord.TimeStamp.Decode().Unix(),
				GnssAccuracy: uint32(r.EntryGNSSPlaceRecord.GNSSAccuracy),
				GeoCoordinates: &pb.GeoCoordinates{
					Latitude:  lat,
					Longitude: lon,
				},
			},
		}
	}
	cardPlaceDailyWorkPeriod2 := &pb.CardPlaceDailyWorkPeriodSecondGen{
		Verified:                 c.CardPlaceDailyWorkPeriodSecondGen.Verified,
		PlacePointerNewestRecord: uint32(c.CardPlaceDailyWorkPeriodSecondGen.PlacePointerNewestRecord),
		PlaceRecords:             placeRecords2,
	}
	cardCurrentUse1 := &pb.CardCurrentUse{
		Verified:        c.CardCurrentUseFirstGen.Verified,
		SessionOpenTime: c.CardCurrentUseFirstGen.SessionOpenTime.Decode().Unix(),
		SessionOpenVehicle: &pb.VehicleRegistrationIdentification{
			VehicleRegistrationNation: uint32(c.CardCurrentUseFirstGen.SessionOpenVehicle.VehicleRegistrationNation),
			VehicleRegistrationNumber: c.CardCurrentUseFirstGen.SessionOpenVehicle.VehicleRegistrationNumber.String(),
		},
	}
	cardCurrentUse2 := &pb.CardCurrentUse{
		Verified:        c.CardCurrentUseSecondGen.Verified,
		SessionOpenTime: c.CardCurrentUseSecondGen.SessionOpenTime.Decode().Unix(),
		SessionOpenVehicle: &pb.VehicleRegistrationIdentification{
			VehicleRegistrationNation: uint32(c.CardCurrentUseSecondGen.SessionOpenVehicle.VehicleRegistrationNation),
			VehicleRegistrationNumber: c.CardCurrentUseSecondGen.SessionOpenVehicle.VehicleRegistrationNumber.String(),
		},
	}
	cardControlActivityDataRecord1 := &pb.CardControlActivityDataRecord{
		Verified:    c.CardControlActivityDataRecordFirstGen.Verified,
		ControlType: uint32(c.CardControlActivityDataRecordFirstGen.ControlType),
		ControlTime: c.CardControlActivityDataRecordFirstGen.ControlTime.Decode().Unix(),
		ControlCardNumber: &pb.FullCardNumber{
			CardType:               uint32(c.CardControlActivityDataRecordFirstGen.ControlCardNumber.CardType),
			CardIssuingMemberState: uint32(c.CardControlActivityDataRecordFirstGen.ControlCardNumber.CardIssuingMemberState),
			CardNumber:             c.CardControlActivityDataRecordFirstGen.ControlCardNumber.CardNumber.String(),
		},
		ControlVehicleRegistration: &pb.VehicleRegistrationIdentification{
			VehicleRegistrationNation: uint32(c.CardControlActivityDataRecordFirstGen.ControlVehicleRegistration.VehicleRegistrationNation),
			VehicleRegistrationNumber: c.CardControlActivityDataRecordFirstGen.ControlVehicleRegistration.VehicleRegistrationNumber.String(),
		},
		ControlDownloadPeriodBegin: c.CardControlActivityDataRecordFirstGen.ControlDownloadPeriodBegin.Decode().Unix(),
		ControlDownloadPeriodEnd:   c.CardControlActivityDataRecordFirstGen.ControlDownloadPeriodEnd.Decode().Unix(),
	}
	cardControlActivityDataRecord2 := &pb.CardControlActivityDataRecord{
		Verified:    c.CardControlActivityDataRecordSecondGen.Verified,
		ControlType: uint32(c.CardControlActivityDataRecordSecondGen.ControlType),
		ControlTime: c.CardControlActivityDataRecordSecondGen.ControlTime.Decode().Unix(),
		ControlCardNumber: &pb.FullCardNumber{
			CardType:               uint32(c.CardControlActivityDataRecordSecondGen.ControlCardNumber.CardType),
			CardIssuingMemberState: uint32(c.CardControlActivityDataRecordSecondGen.ControlCardNumber.CardIssuingMemberState),
			CardNumber:             c.CardControlActivityDataRecordSecondGen.ControlCardNumber.CardNumber.String(),
		},
		ControlVehicleRegistration: &pb.VehicleRegistrationIdentification{},
		ControlDownloadPeriodBegin: c.CardControlActivityDataRecordSecondGen.ControlDownloadPeriodBegin.Decode().Unix(),
		ControlDownloadPeriodEnd:   c.CardControlActivityDataRecordSecondGen.ControlDownloadPeriodEnd.Decode().Unix(),
	}
	lastCardDownload1 := &pb.LastCardDownload{
		Verified:         c.LastCardDownloadFirstGen.Verified,
		LastCardDownload: c.LastCardDownloadFirstGen.LastCardDownLoad.Decode().Unix(),
	}
	lastCardDownload2 := &pb.LastCardDownload{
		Verified:         c.LastCardDownloadSecondGen.Verified,
		LastCardDownload: c.LastCardDownloadSecondGen.LastCardDownLoad.Decode().Unix(),
	}
	driverCardHolderBirthDateYear1, _ := c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.DriverCardHolderIdentification.CardHolderBirthDate.Year.Decode()
	driverCardHolderBirthDateMonth1, _ := c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.DriverCardHolderIdentification.CardHolderBirthDate.Month.Decode()
	driverCardHolderBirthDateDay1, _ := c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.DriverCardHolderIdentification.CardHolderBirthDate.Day.Decode()
	cardIdentificationAndDriverCardHolderIdentification1 := &pb.CardIdentificationAndDriverCardHolderIdentification{
		Verified: c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.Verified,
		CardIdentification: &pb.CardIdentification{
			CardIssuingMemberState:   uint32(c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.CardIdentification.CardIssuingMemberState),
			CardNumber:               c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.CardIdentification.CardNumber.String(),
			CardIssuingAuthorityName: c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.CardIdentification.CardIssuingAuthorityName.String(),
			CardIssueDate:            c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.CardIdentification.CardIssueDate.Decode().Unix(),
			CardValidityBegin:        c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.CardIdentification.CardValidityBegin.Decode().Unix(),
			CardExpiryDate:           c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.CardIdentification.CardExpiryDate.Decode().Unix(),
		},
		DriverCardHolderIdentification: &pb.DriverCardHolderIdentification{
			CardHolderName: &pb.HolderName{
				HolderSurname:    c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.DriverCardHolderIdentification.CardHolderName.HolderSurname.String(),
				HolderFirstNames: c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.DriverCardHolderIdentification.CardHolderName.HolderFirstNames.String(),
			},
			CardHolderBirthDate: &pb.Datef{
				Year:  uint32(driverCardHolderBirthDateYear1),
				Month: uint32(driverCardHolderBirthDateMonth1),
				Day:   uint32(driverCardHolderBirthDateDay1),
			},
			CardHolderPreferredLanguage: c.CardIdentificationAndDriverCardHolderIdentificationFirstGen.DriverCardHolderIdentification.CardHolderPreferredLanguage.String(),
		},
	}
	driverCardHolderBirthDateYear2, _ := c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.DriverCardHolderIdentification.CardHolderBirthDate.Year.Decode()
	driverCardHolderBirthDateMonth2, _ := c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.DriverCardHolderIdentification.CardHolderBirthDate.Month.Decode()
	driverCardHolderBirthDateDay2, _ := c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.DriverCardHolderIdentification.CardHolderBirthDate.Day.Decode()
	cardIdentificationAndDriverCardHolderIdentification2 := &pb.CardIdentificationAndDriverCardHolderIdentification{
		Verified: c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.Verified,
		CardIdentification: &pb.CardIdentification{
			CardIssuingMemberState:   uint32(c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.CardIdentification.CardIssuingMemberState),
			CardNumber:               c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.CardIdentification.CardNumber.String(),
			CardIssuingAuthorityName: c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.CardIdentification.CardIssuingAuthorityName.String(),
			CardIssueDate:            c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.CardIdentification.CardIssueDate.Decode().Unix(),
			CardValidityBegin:        c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.CardIdentification.CardValidityBegin.Decode().Unix(),
			CardExpiryDate:           c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.CardIdentification.CardExpiryDate.Decode().Unix(),
		},
		DriverCardHolderIdentification: &pb.DriverCardHolderIdentification{
			CardHolderName: &pb.HolderName{
				HolderSurname:    c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.DriverCardHolderIdentification.CardHolderName.HolderSurname.String(),
				HolderFirstNames: c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.DriverCardHolderIdentification.CardHolderName.HolderFirstNames.String(),
			},
			CardHolderBirthDate: &pb.Datef{
				Year:  uint32(driverCardHolderBirthDateYear2),
				Month: uint32(driverCardHolderBirthDateMonth2),
				Day:   uint32(driverCardHolderBirthDateDay2),
			},
			CardHolderPreferredLanguage: c.CardIdentificationAndDriverCardHolderIdentificationSecondGen.DriverCardHolderIdentification.CardHolderPreferredLanguage.String(),
		},
	}
	cardDrivingLicenceInformation1 := &pb.CardDrivingLicenceInformation{
		Verified:                       c.CardDrivingLicenceInformationFirstGen.Verified,
		DrivingLicenceIssuingAuthority: c.CardDrivingLicenceInformationFirstGen.DrivingLicenceIssuingAuthority.String(),
		DrivingLicenceIssuingNation:    uint32(c.CardDrivingLicenceInformationFirstGen.DrivingLicenceIssuingNation),
		DrivingLicenceNumber:           c.CardDrivingLicenceInformationFirstGen.DrivingLicenceNumber.String(),
	}
	cardDrivingLicenceInformation2 := &pb.CardDrivingLicenceInformation{
		Verified:                       c.CardDrivingLicenceInformationSecondGen.Verified,
		DrivingLicenceIssuingAuthority: c.CardDrivingLicenceInformationSecondGen.DrivingLicenceIssuingAuthority.String(),
		DrivingLicenceIssuingNation:    uint32(c.CardDrivingLicenceInformationSecondGen.DrivingLicenceIssuingNation),
		DrivingLicenceNumber:           c.CardDrivingLicenceInformationSecondGen.DrivingLicenceNumber.String(),
	}
	specificConditionRecords1 := make([]*pb.SpecificConditionRecord, len(c.SpecificConditionsFirstGen.SpecificConditionRecords))
	for i, r := range c.SpecificConditionsFirstGen.SpecificConditionRecords {
		specificConditionRecords1[i] = &pb.SpecificConditionRecord{
			EntryTime:             r.EntryTime.Decode().Unix(),
			SpecificConditionType: uint32(r.SpecificConditionType),
		}
	}
	specificConditions1 := &pb.SpecificConditionsFirstGen{
		Verified:                 c.SpecificConditionsFirstGen.Verified,
		SpecificConditionRecords: specificConditionRecords1,
	}
	specificConditionRecords2 := make([]*pb.SpecificConditionRecord, len(c.SpecificConditionsSecondGen.SpecificConditionRecords))
	for i, r := range c.SpecificConditionsSecondGen.SpecificConditionRecords {
		specificConditionRecords2[i] = &pb.SpecificConditionRecord{
			EntryTime:             r.EntryTime.Decode().Unix(),
			SpecificConditionType: uint32(r.SpecificConditionType),
		}
	}
	specificConditions2 := &pb.SpecificConditionsSecondGen{
		Verified:                     c.SpecificConditionsSecondGen.Verified,
		ConditionPointerNewestRecord: uint32(c.SpecificConditionsSecondGen.ConditionPointerNewestRecord),
		SpecificConditionRecords:     specificConditionRecords2,
	}
	cardVehicleUnitRecords := make([]*pb.CardVehicleUnitRecord, len(c.CardVehicleUnitsUsed.CardVehicleUnitRecords))
	for i, r := range c.CardVehicleUnitsUsed.CardVehicleUnitRecords {
		cardVehicleUnitRecords[i] = &pb.CardVehicleUnitRecord{
			TimeStamp:         r.TimeStamp.Decode().Unix(),
			ManufacturerCode:  uint32(r.ManufacturerCode),
			DeviceId:          uint32(r.DeviceID),
			VuSoftwareVersion: r.VuSoftwareVersion[:],
		}
	}
	cardVehicleUnitsUsed := &pb.CardVehicleUnitsUsed{
		Verified:                       c.CardVehicleUnitsUsed.Verified,
		VehicleUnitPointerNewestRecord: uint32(c.CardVehicleUnitsUsed.VehicleUnitPointerNewestRecord),
		CardVehicleUnitRecords:         cardVehicleUnitRecords,
	}
	gnssAccumulatedDrivingRecords := make([]*pb.GNSSAccumulatedDrivingRecord, len(c.GNSSAccumulatedDriving.GNSSAccumulatedDrivingRecords))
	for i, r := range c.GNSSAccumulatedDriving.GNSSAccumulatedDrivingRecords {
		lon, lat := r.GNSSPlaceRecord.GeoCoordinates.Decode()
		gnssAccumulatedDrivingRecords[i] = &pb.GNSSAccumulatedDrivingRecord{
			TimeStamp: r.TimeStamp.Decode().Unix(),
			GnssPlaceRecord: &pb.GNSSPlaceRecord{
				TimeStamp:    r.GNSSPlaceRecord.TimeStamp.Decode().Unix(),
				GnssAccuracy: uint32(r.GNSSPlaceRecord.GNSSAccuracy),
				GeoCoordinates: &pb.GeoCoordinates{
					Latitude:  lat,
					Longitude: lon,
				},
			},
			VehicleOdometerValue: uint32(r.VehicleOdometerValue.Decode()),
		}
	}
	gnssAccumulatedDriving := &pb.GNSSAccumulatedDriving{
		Verified:                      c.GNSSAccumulatedDriving.Verified,
		GnssAdPointerNewestRecord:     uint32(c.GNSSAccumulatedDriving.GNSSADPointerNewestRecord),
		GnssAccumulatedDrivingRecords: gnssAccumulatedDrivingRecords,
	}
	driverCardApplicationIdentification2V2 := &pb.DriverCardApplicationIdentificationSecondGenV2{
		Verified:                   c.DriverCardApplicationIdentificationSecondGenV2.Verified,
		LengthOfFollowingData:      uint32(c.DriverCardApplicationIdentificationSecondGenV2.LengthOfFollowingData),
		NoOfBorderCrossingRecords:  uint32(c.DriverCardApplicationIdentificationSecondGenV2.NoOfBorderCrossingRecords),
		NoOfLoadUnloadRecords:      uint32(c.DriverCardApplicationIdentificationSecondGenV2.NoOfLoadUnloadRecords),
		NoOfLoadTypeEntryRecords:   uint32(c.DriverCardApplicationIdentificationSecondGenV2.NoOfLoadTypeEntryRecords),
		VuConfigurationLengthRange: uint32(c.DriverCardApplicationIdentificationSecondGenV2.VuConfigurationLengthRange),
	}
	placeAuthStatusRecords := make([]*pb.PlaceAuthStatusRecord, len(c.CardPlaceAuthDailyWorkPeriod.PlaceAuthStatusRecords))
	for i, r := range c.CardPlaceAuthDailyWorkPeriod.PlaceAuthStatusRecords {
		placeAuthStatusRecords[i] = &pb.PlaceAuthStatusRecord{
			EntryTime:            r.EntryTime.Decode().Unix(),
			AuthenticationStatus: uint32(r.AuthenticationStatus),
		}
	}
	cardPlaceAuthDailyWorkPeriod := &pb.CardPlaceAuthDailyWorkPeriod{
		Verified:                     c.CardPlaceAuthDailyWorkPeriod.Verified,
		PlaceAuthPointerNewestRecord: uint32(c.CardPlaceAuthDailyWorkPeriod.PlaceAuthPointerNewestRecord),
		PlaceAuthStatusRecords:       placeAuthStatusRecords,
	}
	gnssAuthStatusAdRecords := make([]*pb.GNSSAuthStatusADRecord, len(c.GNSSAuthAccumulatedDriving.GNSSAuthStatusADRecords))
	for i, r := range c.GNSSAuthAccumulatedDriving.GNSSAuthStatusADRecords {
		gnssAuthStatusAdRecords[i] = &pb.GNSSAuthStatusADRecord{
			TimeStamp:            r.TimeStamp.Decode().Unix(),
			AuthenticationStatus: uint32(r.AuthenticationStatus),
		}
	}
	gnssAuthAccumulatedDriving := &pb.GNSSAuthAccumulatedDriving{
		Verified:                      c.GNSSAuthAccumulatedDriving.Verified,
		GnssAuthAdPointerNewestRecord: uint32(c.GNSSAuthAccumulatedDriving.GNSSAuthADPointerNewestRecord),
		GnssAuthStatusAdRecords:       gnssAuthStatusAdRecords,
	}
	cardBorderCrossingRecords := make([]*pb.CardBorderCrossingRecord, len(c.CardBorderCrossings.CardBorderCrossingRecords))
	for i, r := range c.CardBorderCrossings.CardBorderCrossingRecords {
		lon, lat := r.GNNSPlaceAuthRecord.GeoCoordinates.Decode()
		cardBorderCrossingRecords[i] = &pb.CardBorderCrossingRecord{
			Verified:       r.Verified,
			CountryLeft:    uint32(r.CountryLeft),
			CountryEntered: uint32(r.CountryEntered),
			GnssPlaceAuthRecord: &pb.GNSSPlaceAuthRecord{
				TimeStamp:    r.GNNSPlaceAuthRecord.TimeStamp.Decode().Unix(),
				GnssAccuracy: uint32(r.GNNSPlaceAuthRecord.GNSSAccuracy),
				GeoCoordinates: &pb.GeoCoordinates{
					Latitude:  lat,
					Longitude: lon,
				},
				AuthenticationStatus: uint32(r.GNNSPlaceAuthRecord.AuthenticationStatus),
			},
			VehicleOdometerValue: uint32(r.VehicleOdometerValue.Decode()),
		}
	}
	cardBorderCrossings := &pb.CardBorderCrossings{
		Verified:                          c.CardBorderCrossings.Verified,
		BorderCrossingPointerNewestRecord: uint32(c.CardBorderCrossings.BorderCrossingPointerNewestRecord),
		CardBorderCrossingRecords:         cardBorderCrossingRecords,
	}
	cardLoadUnloadRecords := make([]*pb.CardLoadUnloadRecord, len(c.CardLoadUnloadOperations.CardLoadUnloadRecords))
	for i, r := range c.CardLoadUnloadOperations.CardLoadUnloadRecords {
		lon, lat := r.GNSSPlaceAuthRecord.GeoCoordinates.Decode()
		cardLoadUnloadRecords[i] = &pb.CardLoadUnloadRecord{
			TimeStamp:     r.Timestamp.Decode().Unix(),
			OperationType: uint32(r.OperationType),
			GnssPlaceAuthRecord: &pb.GNSSPlaceAuthRecord{
				TimeStamp:    r.GNSSPlaceAuthRecord.TimeStamp.Decode().Unix(),
				GnssAccuracy: uint32(r.GNSSPlaceAuthRecord.GNSSAccuracy),
				GeoCoordinates: &pb.GeoCoordinates{
					Latitude:  lat,
					Longitude: lon,
				},
				AuthenticationStatus: uint32(r.GNSSPlaceAuthRecord.AuthenticationStatus),
			},
			VehicleOdometerValue: uint32(r.VehicleOdometerValue.Decode()),
		}
	}
	cardLoadUnloadOperations := &pb.CardLoadUnloadOperations{
		Verified:                      c.CardLoadUnloadOperations.Verified,
		LoadUnloadPointerNewestRecord: uint32(c.CardLoadUnloadOperations.LoadUnloadPointerNewestRecord),
		CardLoadUnloadRecords:         cardLoadUnloadRecords,
	}
	cardLoadTypeEntryRecords := make([]*pb.CardLoadTypeEntryRecord, len(c.CardLoadTypeEntries.CardLoadTypeEntryRecords))
	for i, r := range c.CardLoadTypeEntries.CardLoadTypeEntryRecords {
		cardLoadTypeEntryRecords[i] = &pb.CardLoadTypeEntryRecord{
			TimeStamp:       r.Timestamp.Decode().Unix(),
			LoadTypeEntered: uint32(r.LoadTypeEntered),
		}
	}
	cardLoadTypeEntries := &pb.CardLoadTypeEntries{
		Verified:                         c.CardLoadTypeEntries.Verified,
		LoadTypeEntryPointerNewestRecord: uint32(c.CardLoadTypeEntries.LoadTypeEntryPointerNewestRecord),
		CardLoadTypeEntryRecords:         cardLoadTypeEntryRecords,
	}
	vuConfiguration := &pb.VuConfiguration{
		Verified:      c.VuConfiguration.Verified,
		Configuration: c.VuConfiguration.Configuration,
	}

	resp := &pb.Card{
		CardIccIdentification_1: cardIccIdentification1,
		CardIccIdentification_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardIccIdentificationFirstGenSignature.Signature[:],
		},
		CardIccIdentification_2: cardIccIdentification2,
		CardIccIdentification_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardIccIdentificationSecondGenSignature.Signature,
		},
		CardChipIdentification_1: cardChipCardIdentification1,
		CardChipIdentification_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardChipIdentificationFirstGenSignature.Signature[:],
		},
		CardChipIdentification_2: cardChipCardIdentification2,
		CardChipIdentification_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardChipIdentificationSecondGenSignature.Signature,
		},
		DriverCardApplicationIdentification_1: driverCardApplicationIdentification1,
		DriverCardApplicationIdentification_1Sig: &pb.SignatureFirstGen{
			Signature: c.DriverCardApplicationIdentificationFirstGenSignature.Signature[:],
		},
		DriverCardApplicationIdentification_2: driverCardApplicationIdentification2,
		DriverCardApplicationIdentification_2Sig: &pb.SignatureSecondGen{
			Signature: c.DriverCardApplicationIdentificationSecondGenSignature.Signature,
		},
		CardEventData_1: cardEventData1,
		CardEventData_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardEventDataFirstGenSignature.Signature[:],
		},
		CardEventData_2: cardEventData2,
		CardEventData_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardEventDataSecondGenSignature.Signature,
		},
		CardFaultData_1: cardFaultData1,
		CardFaultData_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardFaultDataFirstGenSignature.Signature[:],
		},
		CardFaultData_2: cardFaultData2,
		CardFaultData_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardFaultDataSecondGenSignature.Signature,
		},
		CardDriverActivity_1: cardDriverActivity1,
		CardDriverActivity_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardDriverActivityFirstGenSignature.Signature[:],
		},
		CardDriverActivity_2: cardDriverActivity2,
		CardDriverActivity_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardDriverActivitySecondGenSignature.Signature,
		},
		CardVehiclesUsed_1: cardVehiclesUsed1,
		CardVehiclesUsed_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardVehiclesUsedFirstGenSignature.Signature[:],
		},
		CardVehiclesUsed_2: cardVehiclesUsed2,
		CardVehiclesUsed_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardVehiclesUsedSecondGenSignature.Signature,
		},
		CardPlaceDailyWorkPeriod_1: cardPlaceDailyWorkPeriod1,
		CardPlaceDailyWorkPeriod_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardPlaceDailyWorkPeriodFirstGenSignature.Signature[:],
		},
		CardPlaceDailyWorkPeriod_2: cardPlaceDailyWorkPeriod2,
		CardPlaceDailyWorkPeriod_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardPlaceDailyWorkPeriodSecondGenSignature.Signature,
		},
		CardCurrentUse_1: cardCurrentUse1,
		CardCurrentUse_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardCurrentUseFirstGenSignature.Signature[:],
		},
		CardCurrentUse_2: cardCurrentUse2,
		CardCurrentUse_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardCurrentUseSecondGenSignature.Signature,
		},
		CardControlActivityDataRecord_1: cardControlActivityDataRecord1,
		CardControlActivityDataRecord_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardControlActivityDataRecordFirstGenSignature.Signature[:],
		},
		CardControlActivityDataRecord_2: cardControlActivityDataRecord2,
		CardControlActivityDataRecord_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardControlActivityDataRecordSecondGenSignature.Signature,
		},
		LastCardDownload_1: lastCardDownload1,
		LastCardDownload_1Sig: &pb.SignatureFirstGen{
			Signature: c.LastCardDownloadFirstGenSignature.Signature[:],
		},
		LastCardDownload_2: lastCardDownload2,
		LastCardDownload_2Sig: &pb.SignatureSecondGen{
			Signature: c.LastCardDownloadSecondGenSignature.Signature,
		},
		CardIdentificationAndDriverCardHolderIdentification_1: cardIdentificationAndDriverCardHolderIdentification1,
		CardIdentificationAndDriverCardHolderIdentification_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardIdentificationAndDriverCardHolderIdentificationFirstGenSignature.Signature[:],
		},
		CardIdentificationAndDriverCardHolderIdentification_2: cardIdentificationAndDriverCardHolderIdentification2,
		CardIdentificationAndDriverCardHolderIdentification_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardIdentificationAndDriverCardHolderIdentificationSecondGenSignature.Signature,
		},
		CardDrivingLicenceInformation_1: cardDrivingLicenceInformation1,
		CardDrivingLicenceInformation_1Sig: &pb.SignatureFirstGen{
			Signature: c.CardDriverActivityFirstGenSignature.Signature[:],
		},
		CardDrivingLicenceInformation_2: cardDrivingLicenceInformation2,
		CardDrivingLicenceInformation_2Sig: &pb.SignatureSecondGen{
			Signature: c.CardDriverActivitySecondGenSignature.Signature,
		},
		SpecificConditions_1: specificConditions1,
		SpecificConditions_1Sig: &pb.SignatureFirstGen{
			Signature: c.SpecificConditionsFirstGenSignature.Signature[:],
		},
		SpecificConditions_2: specificConditions2,
		SpecificConditions_2Sig: &pb.SignatureSecondGen{
			Signature: c.SpecificConditionsSecondGenSignature.Signature,
		},
		CardVehicleUnitsUsed: cardVehicleUnitsUsed,
		CardVehicleUnitsUsedSig: &pb.SignatureSecondGen{
			Signature: c.CardVehicleUnitsUsedSignature.Signature,
		},
		GnssAccumulatedDriving: gnssAccumulatedDriving,
		GnssAccumulatedDrivingSig: &pb.SignatureSecondGen{
			Signature: c.GNSSAccumulatedDrivingSignature.Signature,
		},
		DriverCardApplicationIdentification_2_2: driverCardApplicationIdentification2V2,
		DriverCardApplicationIdentification_2_2Sig: &pb.SignatureSecondGen{
			Signature: c.DriverCardApplicationIdentificationSecondGenV2Signature.Signature,
		},
		CardPlaceAuthDailyWorkPeriod: cardPlaceAuthDailyWorkPeriod,
		CardPlaceAuthDailyWorkPeriodSig: &pb.SignatureSecondGen{
			Signature: c.CardPlaceAuthDailyWorkPeriodSignature.Signature,
		},
		GnssAuthAccumulatedDriving: gnssAuthAccumulatedDriving,
		GnssAuthAccumulatedDrivingSig: &pb.SignatureSecondGen{
			Signature: c.GNSSAuthAccumulatedDrivingSignature.Signature,
		},
		CardBorderCrossings: cardBorderCrossings,
		CardBorderCrossingsSig: &pb.SignatureSecondGen{
			Signature: c.CardBorderCrossingsSignature.Signature,
		},
		CardLoadUnloadOperations: cardLoadUnloadOperations,
		CardLoadUnloadOperationsSig: &pb.SignatureSecondGen{
			Signature: c.CardLoadUnloadOperationsSignature.Signature,
		},
		CardLoadTypeEntries: cardLoadTypeEntries,
		CardLoadTypeEntriesSig: &pb.SignatureSecondGen{
			Signature: c.CardLoadTypeEntriesSignature.Signature,
		},
		VuConfiguration: vuConfiguration,
		VuConfigurationSig: &pb.SignatureSecondGen{
			Signature: c.VuConfigurationSignature.Signature,
		},
		CardCertificate: &pb.CertificateFirstGen{
			Certificate: c.CardCertificateFirstGen.Certificate[:],
		},
		CardMaCertificate: &pb.CertificateSecondGen{
			Certificate: c.CardMACertificate.Certificate,
		},
		CardSignCertificate: &pb.CertificateSecondGen{
			Certificate: c.CardSignCertificate.Certificate,
		},
		MemberStateCertificate: &pb.CertificateFirstGen{
			Certificate: c.MemberStateCertificateFirstGen.Certificate[:],
		},
		CaCertificate: &pb.CertificateSecondGen{
			Certificate: c.CACertificate.Certificate,
		},
		LinkCertificate: &pb.CertificateSecondGen{
			Certificate: c.LinkCertificateSecondGen.Certificate,
		},
	}
	return &pb.ParseCardResponse{Card: resp}, nil
}

func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func main() {
	log.Printf("loaded certificates: %v %v", len(decoder.PKsFirstGen), len(decoder.PKsSecondGen))

	flag.Parse()
	listenAddr := *listen

	if consulAddr := os.Getenv("CONSUL_ADDR"); consulAddr != "" {
		serviceName := "tachoparser"
		if sn := os.Getenv("CONSUL_SERVICE_NAME"); sn != "" {
			serviceName = sn
		}
		consulScheme := "http"
		if cs := os.Getenv("CONSUL_SCHEME"); cs != "" {
			consulScheme = cs
		}
		_, portStr, _ := net.SplitHostPort(listenAddr)
		port, _ := strconv.Atoi(portStr)

		privateIp, err := template.Parse(`{{ GetPrivateIP }}`)
		if err != nil {
			log.Printf("warn: unable to find a private ip address: %v", err)
		}
		rnd, _ := RandomHex(4)
		serviceId := fmt.Sprintf("%s-%s", serviceName, rnd)
		serviceDef := &consul.AgentServiceRegistration{
			ID:      serviceId,
			Name:    serviceName,
			Port:    port,
			Address: privateIp,
			Check: &consul.AgentServiceCheck{
				TCP:      net.JoinHostPort(privateIp, portStr),
				Interval: "60s",
			},
		}
		consulConfig := consul.DefaultConfig()
		consulConfig.Address = consulAddr
		consulConfig.Scheme = consulScheme
		if consulDc := os.Getenv("CONSUL_DATACENTER"); consulDc != "" {
			consulConfig.Datacenter = consulDc
		}
		cc, err := consul.NewClient(consulConfig)
		if err != nil {
			log.Fatalf("error: could not create consul client: %v", err)
		} else {
			consulAgent := cc.Agent()
			if err := consulAgent.ServiceRegister(serviceDef); err != nil {
				log.Printf("error: could not register consul: %v (ignored)", err)
			} else {
				c := make(chan os.Signal, 1)
				signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)
				go func() {
					<-c
					consulAgent.ServiceDeregister(serviceId)
					log.Fatal("interrupted/killed!")
				}()
			}
		}
	}

	var statsdClient *statsd.Client
	if *statsdAddr != "" {
		var err error
		statsdClient, err = statsd.New(statsd.Address(*statsdAddr))
		if err != nil {
			log.Printf("error: creating statsd client (ignored)")
		}
	}

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterDDDParserServer(s, &server{
		statsdClient: statsdClient,
	})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("error: failed to serve: %v", err)
	}
}
