package runner

import (
	"github.com/projectdiscovery/goflags"
	"github.com/wjlin0/masscan-go/types"
	updateutils "github.com/wjlin0/utils/update"
	"time"
)

func ParseOptions() *types.Options {
	set := goflags.NewFlagSet()
	options := &types.Options{}
	set.SetDescription(`masscan-go is a fast and simple port scanner written in Go.`)
	set.CreateGroup("Input", "Input",
		set.StringSliceVarP(&options.Target, "target", "t", nil, "Target to scan", goflags.CommaSeparatedStringSliceOptions),
		set.StringVarP(&options.Ports, "ports", "p", "", "Ports to scan"),
		set.IntVarP(&options.TopPort, "top-port", "tp", 100, "Top port to scan"),
		set.StringSliceVarP(&options.List, "list", "l", nil, "List of targets to scan", goflags.FileCommaSeparatedStringSliceOptions),
	)
	set.CreateGroup("Config", "Config",
		set.IntVarP(&options.Rate, "rate", "r", 2000, "Rate of packets per second"),
		set.DurationVar(&options.Timeout, "timeout", 5*time.Second, "Timeout for each port scan"),
		// 发包完成后的等待时间
		set.DurationVarP(&options.WaitTime, "wait-time", "wt", 10*time.Second, "Wait time after sending packets"),
		set.BoolVarP(&options.Verbose, "verbose", "v", false, "Verbose output"),
		set.StringVarP(&options.InterfaceName, "interface", "i", "", "Interface to use for scanning"),
		set.StringVarP(&options.SourceIp, "source-ip", "si", "", "Source IP address to use for scanning"),
		set.IntVarP(&options.SourcePort, "source-port", "sp", 0, "Source port to use for scanning"),
		set.IntVarP(&options.MaxOpenPorts, "max-open-ports", "m", 100, "Maximum number of open ports to scan"),
	)

	set.CreateGroup("Output", "Output",
		set.StringVarP(&options.Output, "output", "o", "", "Output file to write found ports"),
	)

	set.CreateGroup("Update", "Update",
		set.CallbackVar(updateutils.GetUpdateToolCallback(project, Version), "update", "更新版本"),
		set.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "跳过自动检查更新"),
	)
	set.SetCustomHelpText(`EXAMPLES:

运行 masscan-go 指定IP/CIDR:
    $ sudo masscan-go -t 192.168.1.1 -t 192.168.1.1/24

运行 masscan-go 从文件中读取:
    $ sudo masscan-go -list file.txt

运行 masscan-go 联动 nmap：
    $ # 目前暂不支持，未来会联动

运行 masscan-go 收集端口 并配合 nuclei 进行自动化漏洞扫描:
    $ sudo masscan-go -t 192.168.1.1/24 -o output.txt && nuclei -list output.txt

其他文档可在以下网址获得: https://github.com/wjlin0/masscan-go/
`)

	_ = set.Parse()

	return options
}
