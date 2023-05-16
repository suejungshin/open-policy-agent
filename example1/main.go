package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/open-policy-agent/opa/rego"
)

func main() {
	ctx := context.Background()

	// Construct a Rego object that can be prepared or evaluated.
	r := rego.New(
		rego.Query(os.Args[2]),
		rego.Load([]string{os.Args[1]}, nil))

	// Create a prepared query that can be evaluated.
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Load the input document from stdin.
	var input any
	dec := json.NewDecoder(os.Stdin)
	dec.UseNumber()
	err = dec.Decode(&input)
	if err != nil {
		log.Fatal(err)
	}

	// Execute the prepared query.
	result, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
	}

	// Do something with the result.
	fmt.Println(result)
}

// TO RUN
// go run main.go example.rego 'data.example.violation' < input.json
