package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/masscan-go/runner"
)

func main() {

	options := runner.ParseOptions()

	run, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	err = run.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}

	//println(options)
}
