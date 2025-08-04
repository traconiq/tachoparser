package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	pb "github.com/traconiq/tachoparser/pkg/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

/**
 * author: tr <thorsten.riess@traconiq.ch>
 */

var (
	addr = flag.String("addr", "", "dddserver grpc address")
	card = flag.Bool("card", false, "parse card data")
	vu   = flag.Bool("vu", false, "parse vu data")
)

func main() {
	flag.Parse()

	if *addr == "" {
		log.Fatal("error: addr is required")
	}
	if !(*card || *vu) || (*card && *vu) {
		log.Fatal("error: either vu or card must be set")
	}

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("error: could not dial: %s", err)
	}

	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("error: could not read stdin: %s", err)
	}

	client := pb.NewDDDParserClient(conn)
	if *card {
		req := &pb.ParseCardRequest{Data: data}
		resp, err := client.ParseCard(context.Background(), req)
		if err != nil {
			log.Fatalf("error: could not execute grpc call: %s", err)
		}
		opts := protojson.MarshalOptions{AllowPartial: true, UseProtoNames: true}
		card, err := opts.Marshal(resp.Card)
		if err != nil {
			log.Fatalf("error: could not marshal card data: %s", err)
		}
		fmt.Printf(string(card))
	}
	if *vu {
		req := &pb.ParseVuRequest{Data: data}
		resp, err := client.ParseVu(context.Background(), req)
		if err != nil {
			log.Fatalf("error: could not execute grpc call: %s", err)
		}
		opts := protojson.MarshalOptions{AllowPartial: true, UseProtoNames: true}
		vu, err := opts.Marshal(resp.Vu)
		if err != nil {
			log.Fatalf("error: could not marshal vu data: %s", err)
		}
		fmt.Printf(string(vu))
	}
}
