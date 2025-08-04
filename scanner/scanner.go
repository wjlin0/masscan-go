package scanner

import (
	"context"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/utils/routing"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/masscan-go/cache"
	"github.com/wjlin0/masscan-go/target"
	"github.com/wjlin0/masscan-go/types"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	tcpsequencer = NewTCPSequencer()
)
var preferredSrcPort = getRandomPort()

type ScanResult struct {
	IP    string
	Port  int
	State string // "open", "closed", "filtered"
}

type Scanner struct {
	options           *types.Options
	ResultCache       *cache.ResultCache
	ipList            []net.IP
	dialer            *net.Dialer
	portList          []int
	router            routing.Router
	targets           map[string]*target.Target
	handles           map[string]*pcap.Handle
	tcpConn4          *net.IPConn
	tcpSendPcapCount  int
	tcpTotalPcapCount int
	sendPcapCount     int
	// 读写锁
	sync.RWMutex
}

func (s *Scanner) CleanupHandlersUnix() {
	allActive := s.handles
	for _, handler := range allActive {
		handler.Close()
	}
}

func NewScanner(options *types.Options) (*Scanner, error) {

	ipList, err := target.ParseIps(append(options.Target, options.List...))
	if err != nil {
		return nil, err
	}
	portList, err := target.ParsePorts(options.Ports, options.TopPort)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: options.Timeout}
	scan := &Scanner{
		options:     options,
		ipList:      ipList,
		portList:    portList,
		ResultCache: cache.NewResultCache(),
		dialer:      &dialer,
	}
	scan.router, err = routing.New()

	if scan.options.SourcePort != 0 {
		preferredSrcPort = scan.options.SourcePort
	}
	scan.targets, err = scan.parseTarget()
	if err != nil {
		return nil, err
	}
	handles := make(map[string]*pcap.Handle)
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		isInterfaceDown := iface.Flags&net.FlagUp == 0
		if isInterfaceDown {
			continue
		}

		portStr := strconv.Itoa(preferredSrcPort)
		portFilters := []string{portStr}
		bpfFilter := fmt.Sprintf("(%s) and (tcp or udp)", strings.Join(portFilters, " or "))
		inactiveHandle, err := pcap.NewInactiveHandle(iface.Name)
		if err != nil {
			return nil, err
		}
		err = inactiveHandle.SetImmediateMode(true)
		if err != nil {
			return nil, err
		}
		err = inactiveHandle.SetSnapLen(65536)
		if err != nil {
			return nil, err
		}
		//err = inactiveHandle.SetPromisc(true)
		//if err != nil {
		//	return nil, err
		//}
		err = inactiveHandle.SetTimeout(1500 * time.Millisecond)
		if err != nil {
			scan.CleanupHandlersUnix()
			return nil, err
		}
		handle, err := inactiveHandle.Activate()
		if err != nil {
			scan.CleanupHandlersUnix()
			return nil, err
		}
		err = handle.SetBPFFilter(bpfFilter)
		//handle, err := pcap.OpenLive(iface.Name, 65535, true, pcap.BlockForever)
		//if err != nil {
		//	continue
		//}

		handles[iface.Name] = handle

	}

	scan.handles = handles
	scan.tcpConn4, err = net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", preferredSrcPort))})
	return scan, nil

}

func safeIP(ip net.IP) net.IP {
	if len(ip) == 0 || ip == nil {
		return nil
	}
	// 确保是有效的IP类型
	if ip.To4() != nil || ip.To16() != nil {
		return ip
	}
	_ip := make([]byte, len(ip))

	for i := 0; i < len(ip); i++ {
		_ip[i] = ip[i]
	}

	return net.ParseIP(string(_ip))
}

func (s *Scanner) parseTarget() (map[string]*target.Target, error) {
	var targets []*target.Target
	ipList := s.ipList
	for i := 0; i < len(ipList); i++ {
		var preferredSrc net.IP
		var err error

		_, _, preferredSrc, err = s.router.Route(ipList[i])
		if err != nil {
			return nil, fmt.Errorf("Failed to get default interface: %v", err)
		}
		if s.options.SourceIp != "" {
			preferredSrc = net.ParseIP(s.options.SourceIp)
		}

		t := &target.Target{
			SrcIp:   preferredSrc,
			DstIp:   ipList[i],
			SrcPort: preferredSrcPort,
		}
		targets = append(targets, t)
	}
	targetsMap := make(map[string]*target.Target)
	for _, t := range targets {
		targetsMap[t.DstIp.String()] = t
	}

	return targetsMap, nil
}

func (s *Scanner) GetPcapCount() (count int) {

	return len(s.targets) * len(s.portList) * 3
}

func (s *Scanner) Close() {

	for _, handle := range s.handles {
		handle.Close()
	}

	_ = s.tcpConn4.Close()
}

func (s *Scanner) showRunningBanner() {

}

type ipPorts struct {
	ports map[int]struct{}
	count int
}

var displayLines = 0
var tcpDisplayLines = 0

func ClearLinesUp(n int) {
	for i := 0; i < n; i++ {
		fmt.Print("\033[1A")  // 上移一行
		fmt.Print("\r\033[K") // 清空该行
	}
}

var flag = false
var percent = 0
var tcpFlag = false
var tcpPercent = 0

func (s *Scanner) refreshDisplay(_type string, portMap map[string]*ipPorts) {
	s.Lock()
	defer s.Unlock()
	if _type == "syn" {
		_portMap := make(map[string]*ipPorts)
		for ip, data := range portMap {
			if data.count > s.options.MaxOpenPorts {
				continue
			}

			_portMap[ip] = &ipPorts{
				ports: data.ports,
				count: data.count,
			}
		}

		//fmt.Printf("\033[%dA\033[K", *displayLines) // 回到之前的位置并清除
		////*displayLines = 0
		//// 重新排序 IP
		ips := make([]string, 0, len(_portMap))
		for ip := range _portMap {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool {
			return func(a, b string) int {
				ipA := net.ParseIP(a)
				ipB := net.ParseIP(b)

				if ipA == nil || ipB == nil {
					return strings.Compare(a, b)
				}

				// IPv4放在IPv6前面
				if len(ipA) != len(ipB) {
					return len(ipA) - len(ipB)
				}

				for i := range ipA {
					if ipA[i] != ipB[i] {
						return int(ipA[i]) - int(ipB[i])
					}
				}
				return 0
			}(ips[i], ips[j]) < 0
		})
		if displayLines > 0 && percent < 100 {
			ClearLinesUp(displayLines)
			displayLines = 0
		}
		var portsCount int
		for _, ip := range ips {
			data := _portMap[ip]
			if data.count > s.options.MaxOpenPorts {
				continue
			}

			// 提取并排序端口
			ports := make([]int, 0, len(data.ports))
			for port := range data.ports {
				ports = append(ports, port)
			}
			sort.Ints(ports)

			// 格式化端口列表
			portsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
			portsCount += len(ports)
			if percent < 100 {
				fmt.Printf("\r%s: %s\033[K\n", ip, portsStr)
				// 输出结果
				displayLines++
			}

		}
		pcapCt := s.GetPcapCount()
		seconds := float64(pcapCt) / float64(s.options.Rate)
		seconds *= 1.15 // 增加缓冲
		// 固定进度条宽度
		const barWidth = 50

		// 百分比 & 填充长度计算
		_percent := s.sendPcapCount * 100 / pcapCt
		filled := _percent * barWidth / 100
		bar := strings.Repeat("█", filled) + strings.Repeat(" ", barWidth-filled)

		if percent < 100 {
			// 打印状态信息
			gologger.Print().Msgf("\r总发包量: %d | 预计完成时间: %vs | 速率: %d/s | 进度: %d/%d | 已发现端口: %d\033[K\n",
				pcapCt,
				int(seconds),
				s.options.Rate,
				s.sendPcapCount,
				pcapCt,
				portsCount,
			)
			displayLines++
			// 打印进度条
			gologger.Print().Msgf("[%s] %3d%%\033[K\n", bar, _percent)
			displayLines++
		}

		//displayLines = 0
		// 光标回到上两行以实现刷新
		//fmt.Print("\033[2A")
		//s.showRunningBanner()
		if percent == 100 && !flag {
			gologger.Info().Msgf("发包完成，等待 %v 完成扫描\033[K\n", s.options.WaitTime)
			flag = true
		}
		percent = _percent
		return
	}
	_portMap := make(map[string]*ipPorts)
	for ip, data := range portMap {
		if data.count > s.options.MaxOpenPorts {
			continue
		}
		_portMap[ip] = &ipPorts{
			ports: data.ports,
			count: data.count,
		}
	}
	ips := make([]string, 0, len(_portMap))
	for ip := range _portMap {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return func(a, b string) int {
			ipA := net.ParseIP(a)
			ipB := net.ParseIP(b)

			if ipA == nil || ipB == nil {
				return strings.Compare(a, b)
			}

			// IPv4放在IPv6前面
			if len(ipA) != len(ipB) {
				return len(ipA) - len(ipB)
			}

			for i := range ipA {
				if ipA[i] != ipB[i] {
					return int(ipA[i]) - int(ipB[i])
				}
			}
			return 0
		}(ips[i], ips[j]) < 0
	})
	if tcpDisplayLines > 0 && tcpPercent < 100 {
		ClearLinesUp(tcpDisplayLines)
		tcpDisplayLines = 0
	}
	var portsCount int
	for _, ip := range ips {
		data := _portMap[ip]

		// 提取并排序端口
		ports := make([]int, 0, len(data.ports))
		for port := range data.ports {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		if tcpPercent < 100 {
			for _, port := range ports {
				fmt.Printf("\r%s:%d\033[K\n", ip, port)
				// 输出结果
				tcpDisplayLines++
			}
		}
		// 格式化端口列表
		//portsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
		portsCount += len(ports)
		//if tcpPercent < 100 {
		//	fmt.Printf("\r%s: %s\033[K\n", ip, portsStr)
		//	// 输出结果
		//	tcpDisplayLines++
		//}

	}
	seconds := float64(s.tcpSendPcapCount) / float64(s.options.Rate)
	seconds *= 1.15 // 增加缓冲
	// 固定进度条宽度
	const barWidth = 50
	// 百分比 & 填充长度计算
	_percent := s.tcpSendPcapCount * 100 / s.tcpTotalPcapCount
	filled := _percent * barWidth / 100
	bar := strings.Repeat("█", filled) + strings.Repeat(" ", barWidth-filled)

	if tcpPercent < 100 {
		// 打印状态信息
		gologger.Print().Msgf("\r总发包量: %d | 预计完成时间: %vs | 速率: %d/s | 进度: %d/%d | 已发现端口: %d\033[K\n",
			s.tcpSendPcapCount,
			int(seconds),
			s.options.Rate,
			s.tcpSendPcapCount,
			s.tcpTotalPcapCount,
			portsCount,
		)
		tcpDisplayLines++
		// 打印进度条
		gologger.Print().Msgf("[%s] %3d%%\033[K\n", bar, _percent)
		tcpDisplayLines++
	}

	//displayLines = 0
	// 光标回到上两行以实现刷新
	//fmt.Print("\033[2A")
	//s.showRunningBanner()
	if tcpPercent == 100 && !tcpFlag {
		//gologger.Print().Msgf("\r[+] 发包完成，等待 %v 完成扫描\033[K\n", s.options.Timeout)
		tcpFlag = true
	}
	tcpPercent = _percent
	return
}

var (
	portMap = make(map[string]*ipPorts)

	tcpPortMap = make(map[string]*ipPorts)
)

func (s *Scanner) Scan() []ScanResult {
	defer s.Close()
	// 创建结果通道
	results := make(chan ScanResult, 10000)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 启动抓包goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.captureResponses(ctx, results)
	}()
	// 启动发包goroutine
	wg.Add(1)
	go func() {
		defer func() {
			// 这里打印 等待 N秒 输出 结果
			time.Sleep(s.options.WaitTime)
			wg.Done()
			cancel()
			close(results)
		}()
		s.sendSYNs(ctx)
	}()

	// 收集结果

Loop:
	for {
		select {
		case res, ok := <-results:

			if !ok {
				//gologger.Verbose().Msgf("关闭 通道")
				// 通道关闭，整理最终结果返回
				//for ip, data := range portMap {
				//	for port, _ := range data.ports {
				//		_openPorts = append(_openPorts, ScanResult{
				//			IP:    ip,
				//			Port:  port,
				//			State: "open",
				//		})
				//	}
				//}
				break Loop
			}
			if res.State != "open" {
				continue
			}
			s.Lock()
			// 初始化IP记录
			if _, exists := portMap[res.IP]; !exists {
				portMap[res.IP] = &ipPorts{
					ports: make(map[int]struct{}),
					count: 0,
				}
			}
			data := portMap[res.IP]
			// 添加新端口
			data.ports[res.Port] = struct{}{}
			data.count++
			s.ResultCache.Add(res.IP)
			s.Unlock()
		case <-time.After(200 * time.Millisecond):
			s.refreshDisplay("syn", portMap)
		}
	}
	var ips []string
	// 扫描 openPort 超过 50 的 top 100
	for ip, data := range portMap {
		if data.count >= s.options.MaxOpenPorts {
			ips = append(ips, ip)
		}
	}
	if len(ips) > 0 {
		results = make(chan ScanResult, 10000)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel = context.WithCancel(context.Background())
			s.sendTcp(ctx, results, ips, target.Top100)
			close(results)
			cancel()
		}()
	TCPSend:
		for {
			select {
			case res, ok := <-results:
				if !ok {
					break TCPSend
				}
				if res.State != "open" {
					continue
				}
				s.Lock()
				if _, exists := tcpPortMap[res.IP]; !exists {
					tcpPortMap[res.IP] = &ipPorts{
						ports: make(map[int]struct{}),
						count: 0,
					}
				}
				data := tcpPortMap[res.IP]
				// 添加新端口
				data.ports[res.Port] = struct{}{}
				data.count++
				s.Unlock()
			case <-time.After(200 * time.Millisecond):
				s.refreshDisplay("tcp", tcpPortMap)
			}
		}
	}

	wg.Wait()
	return s.getScanPortList(tcpPortMap, portMap)
}
func (s *Scanner) getScanPortList(tcpPortMap map[string]*ipPorts, synPortMap map[string]*ipPorts) []ScanResult {
	var dataResult []ScanResult
	isExist := func(result ScanResult) bool {
		for d := range dataResult {
			if result.IP == dataResult[d].IP && result.Port == dataResult[d].Port {
				return true
			}
		}

		return false
	}

	for ip, data := range synPortMap {
		if data.count > s.options.MaxOpenPorts {
			continue
		}
		for port, _ := range data.ports {
			if isExist(ScanResult{
				IP:    ip,
				Port:  port,
				State: "open",
			}) {
				continue
			}
			dataResult = append(dataResult, ScanResult{
				IP:    ip,
				Port:  port,
				State: "open",
			})
		}
	}
	for ip, data := range tcpPortMap {
		if data.count > s.options.MaxOpenPorts {
			continue
		}
		for port, _ := range data.ports {
			if isExist(ScanResult{
				IP:    ip,
				Port:  port,
				State: "open",
			}) {
				continue
			}
			dataResult = append(dataResult, ScanResult{
				IP:    ip,
				Port:  port,
				State: "open",
			})

		}
	}
	return dataResult
}
func (s *Scanner) sendSYNs(ctx context.Context) {

	limiter := ratelimit.New(ctx, uint(s.options.Rate), time.Duration(1*time.Second))
	//save := time.Now()
	for _, dstPort := range s.portList {

		for dstIP, _ := range s.targets {

			srcIf := s.targets[dstIP]
			limiter.Take()

			count := s.ResultCache.Get(dstIP)
			if count >= s.options.MaxOpenPorts {
				break
			}

			ip := layers.IPv4{
				Id:       uint16(rand.Intn(65535)),
				Version:  4,
				TTL:      255,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    srcIf.SrcIp,
				DstIP:    net.ParseIP(dstIP),
			}
			tcpOption := layers.TCPOption{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0xB4},
			}
			tcp := layers.TCP{
				SrcPort: layers.TCPPort(srcIf.SrcPort),
				DstPort: layers.TCPPort(dstPort),
				SYN:     true,
				Window:  1024,
				//RST:     true, // RST flag set
				Seq:     tcpsequencer.Next(),
				Options: []layers.TCPOption{tcpOption},
			}
			err := tcp.SetNetworkLayerForChecksum(&ip)
			if err != nil {
				gologger.Verbose().Msgf("Error setting network layer for checksum: %v", err)
				return
			}

			// 序列化数据包
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			if err := gopacket.SerializeLayers(buf, opts, &tcp); err != nil {
				gologger.Verbose().Msgf("Error serializing layers: %v", err)
				continue
			}

			for i := 0; i < 3; i++ {
				_, err := s.tcpConn4.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(dstIP)})
				if err != nil {
					s.sendPcapCount++
					continue
				}

				s.sendPcapCount++
			}

		}
	}
}

func (s *Scanner) sendTcp(ctx context.Context, results chan<- ScanResult, ipList []string, portList []int) {
	wg := sizedwaitgroup.New(s.options.Rate)
	ratelimiter := ratelimit.New(ctx, uint(s.options.Rate), time.Duration(1*time.Second))
	s.tcpTotalPcapCount = len(ipList) * len(portList)
	for _, ip := range ipList {
		for _, port := range portList {
			wg.Add()

			go func(ip string, port int) {
				defer wg.Done()
				ratelimiter.Take()
				address := fmt.Sprintf("%s:%d", ip, port)
				conn, err := s.dialer.DialContext(ctx, "tcp", address)
				if err != nil {
					if s.options.Verbose {
						gologger.Debug().Msgf("%s closed: %v\n", address, err)
					}
					s.Lock()
					s.tcpSendPcapCount++
					s.Unlock()
					return
				}
				defer conn.Close()
				results <- ScanResult{
					IP:    ip,
					Port:  port,
					State: "open",
				}
				s.Lock()
				s.tcpSendPcapCount++
				s.Unlock()
			}(ip, port)
		}
	}

	wg.Wait()

}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "ARP timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func (s *Scanner) captureResponses(ctx context.Context, results chan<- ScanResult) {

	// 创建快速查找表
	ipSet := make(map[string]bool)
	for _, ip := range s.ipList {
		ipSet[ip.String()] = true
	}

	portSet := make(map[int]bool)
	for _, port := range s.portList {
		portSet[port] = true
	}
	_wg := sync.WaitGroup{}
	for _, handle := range s.handles {
		_wg.Add(1)
		go func(handle *pcap.Handle) {
			defer _wg.Done()
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for {
				select {
				case <-ctx.Done():
					return
				case packet, ok := <-packetSource.Packets():
					if !ok {
						return
					}
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					if ipLayer == nil {
						continue
					}

					ip, _ := ipLayer.(*layers.IPv4)

					// 检查是否为目标IP
					if !ipSet[ip.SrcIP.String()] {
						continue
					}

					// 解析传输层
					tcpLayer := packet.Layer(layers.LayerTypeTCP)
					if tcpLayer == nil {
						continue
					}

					tcp, _ := tcpLayer.(*layers.TCP)
					// 检查是否为目标端口
					if !portSet[int(tcp.SrcPort)] {
						continue
					}

					// 确定端口状态
					var state string
					switch {
					case tcp.SYN && tcp.ACK:
						state = "open"
					case tcp.RST:
						state = "closed"
					default:
						state = "filtered"
					}
					select {
					case <-ctx.Done():
						return
					case results <- ScanResult{
						IP:    ip.SrcIP.String(),
						Port:  int(tcp.SrcPort),
						State: state,
					}:
					}
				}
			}
		}(handle)
	}
	_wg.Wait()
}

// 工具函数
func getRandomPort() int {
	return rand.Intn(65535-49152) + 49152
}
