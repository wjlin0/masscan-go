package runner

import (
	"errors"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/wjlin0/masscan-go/network"
	"github.com/wjlin0/masscan-go/scanner"
	"github.com/wjlin0/masscan-go/types"
	"github.com/wjlin0/masscan-go/util"
	updateutils "github.com/wjlin0/utils/update"
	"net"
	"time"
)

type Runner struct {
	options *types.Options
	scanner *scanner.Scanner
}

func NewRunner(options *types.Options) (runner *Runner, err error) {
	runner = &Runner{options: options}

	if err := runner.validateOptions(); err != nil {
		return runner, err
	}
	runner.scanner, err = scanner.NewScanner(options)
	if err != nil {
		return runner, err
	}
	return runner, nil
}

func (r *Runner) validateOptions() error {
	opts := r.options
	if opts.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	r.showBanner()
	r.showVersion()

	if opts.SourceIp != "" {
		if net.ParseIP(opts.SourceIp) == nil {
			return fmt.Errorf("invalid source ip %s", opts.SourceIp)
		}
	}
	if opts.InterfaceName != "" {
		iface, err := network.GetInterfaceByName(opts.InterfaceName)
		if err != nil {
			return err
		}
		opts.InterfaceName = iface.Name
	}
	ips := append(opts.Target, opts.List...)
	if len(ips) == 0 {
		return errors.New("no target specified")
	}

	if privileges.IsPrivileged == false {
		return errors.New("you need to be root to run masscan e.g.:\n  $ sudo masscan -t 192.168.3.1/24")
	}

	return nil
}

// showBanner is used to show the banner to the user
func (r *Runner) showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\t\twjlin0.com\n\n")
	gologger.Print().Msgf("加入知识星球【爱坤】，获取高质量POC\n")
	gologger.Print().Msgf("慎用。你要为自己的行为负责\n")
	gologger.Print().Msgf("开发者不承担任何责任，也不对任何误用或损坏负责.\n")

}
func (r *Runner) showVersion() {
	opts := r.options
	latestVersion := Version

	var (
		err error
	)
	if !opts.DisableUpdateCheck {
		latestVersion, err = updateutils.GetToolVersionCallback(project, project)()
		if err != nil {
			if opts.Verbose {
				gologger.Verbose().Msgf("%s version check failed: %v", project, err.Error())
			}
			latestVersion = Version
		}
	}
	//println(latestVersion)
	gologger.Info().Msgf("Current %s version v%v %v", project, Version, updateutils.GetVersionDescription(Version, latestVersion))
}

func (r *Runner) RunEnumeration() error {
	start := time.Now()
	_openPorts := r.scanner.Scan()
	var openPorts []scanner.ScanResult
	for _, port := range _openPorts {
		openPorts = append(openPorts, port)
	}
	endtime := time.Now()
	gologger.Info().Msgf("Finished in %v", endtime.Sub(start))
	// 排序输出结果
	util.SortResults(openPorts)
	util.PrintResults(openPorts)

	if r.options.Output != "" {
		gologger.Info().Msgf("Output written to: %s\n", r.options.Output)
		if err := util.OutputResults(openPorts, r.options.Output); err != nil {
			return err
		}
	}

	return nil
}

func (r *Runner) Close() {
	r.scanner.Close()
}
