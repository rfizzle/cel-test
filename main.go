package main

import (
	"bytes"
	"encoding/json"
	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"log"
	"time"
)

type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Severity string `json:"severity"`
	Title string `json:"title"`
	Description string `json:"description"`
	File map[string]string `json:"file"`
	Ips []string `json:"ips"`
}

func main() {
	e1 := `timestamp(event.timestamp).getFullYear() < 2020`
	e2 := `event.severity == "high"`
	outputResults(e1)
	outputResults(e2)
}

func outputResults(rule string) {
	results := run(rule, &Event{
		Timestamp:   time.Now(),
		Severity:    "high",
		Title:       "XSS",
		Description: "Cross Site Scripting",
		File: map[string]string{
			"path": "/etc/hosts",
		},
		Ips: []string{"127.0.0.1", "192.168.1.1"},
	})

	log.Printf("Output: %v", results)
}

func run(rule string, event *Event) ref.Val {
	// First build the CEL program.
	ds := cel.Declarations(
		decls.NewConst("event", decls.NewMapType(decls.String, decls.Dyn), nil),
	)

	env, err := cel.NewEnv(ds)
	if err != nil {
		log.Println(1)
		log.Fatal(err)
	}

	prs, iss := env.Parse(rule)
	if iss != nil && iss.Err() != nil {
		log.Println(2)
		log.Fatal(iss.Err())
	}

	chk, iss := env.Check(prs)
	if iss != nil && iss.Err() != nil {
		log.Println(3)
		log.Fatal(iss.Err())
	}

	prg, err := env.Program(chk)
	if err != nil {
		log.Println(4)
		log.Fatal(err)
	}

	// Now, get the input in the correct format (conversion: Go struct -> JSON -> structpb).
	j, err := json.Marshal(event)
	if err != nil {
		log.Println(5)
		log.Fatal(err)
	}

	var spb structpb.Struct
	if err := jsonpb.Unmarshal(bytes.NewBuffer(j), &spb); err != nil {
		log.Println(6)
		log.Fatal(err)
	}

	// Now, evaluate the program and check the output.
	val, _, err := prg.Eval(map[string]interface{}{"event": &spb})
	if err != nil {
		log.Println(7)
		log.Fatal(err)
	}

	return val
}
