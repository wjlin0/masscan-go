package types

import (
	"github.com/projectdiscovery/goflags"
	"time"
)

type Options struct {
	Target             goflags.StringSlice
	Ports              string
	List               goflags.StringSlice
	InterfaceName      string
	Rate               int
	Timeout            time.Duration
	WaitTime           time.Duration
	MaxOpenPorts       int
	SourceIp           string
	ArpTimeout         int
	TopPort            int
	Verbose            bool
	Output             string
	DisableUpdateCheck bool
	SourcePort         int
}
