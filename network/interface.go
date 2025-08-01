package network

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/wjlin0/masscan-go/cache"
	"net"
	"time"
)

var (
	macArpCache = cache.NewMacCache()
)

func GetInterface(dstIp net.IP) (iface *net.Interface, gateway net.IP, preferredSrc net.IP, err error) {
	// 1. 创建自动路由选择器
	router, err := routing.New()
	if err != nil {
		return nil, nil, nil, err
	}
	return router.Route(dstIp)
}

func GetInterfaceByName(ifName string) (*net.Interface, error) {
	// 1. 获取指定网卡信息
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("error: cannot get interface %s: %v", ifName, err)
	}
	return iface, nil
}

// getInterfaceIPv4 获取接口的IPv4地址
func getInterfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP, nil
		}
	}

	return nil, fmt.Errorf("接口没有IPv4地址")
}

func getDefaultGateway(iface *net.Interface) (net.IP, error) {
	// 简化实现：返回一个假设的网关IP
	// 实际应该解析系统路由表
	localIP, err := getInterfaceIPv4(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get local IP")
	}

	// 假设网关是本地IP的最后一个字节改为1
	gateway := net.IPv4(localIP[12], localIP[13], localIP[14], 1)
	return gateway, nil
}

// resolveMACWithGopacket 使用纯gopacket实现ARP解析
func resolveMACWithGopacket(iface *net.Interface, targetIP net.IP) (net.HardwareAddr, error) {
	if cacheMac := macArpCache.Get(targetIP.String()); cacheMac != nil {
		return cacheMac, nil
	}

	// 1. 验证输入参数
	if iface == nil {
		return nil, fmt.Errorf("网络接口不能为nil")
	}
	if targetIP == nil || targetIP.To4() == nil {
		return nil, fmt.Errorf("需要有效的IPv4地址")
	}

	// 2. 获取接口IP地址
	srcIP, err := getInterfaceIPv4(iface)
	if err != nil {
		return nil, fmt.Errorf("获取接口IP失败: %v", err)
	}

	// 3. 打开网络接口
	handle, err := pcap.OpenLive(
		iface.Name,    // 设备名
		65536,         // 快照长度
		true,          // 混杂模式
		time.Second*2, // 超时
	)
	if err != nil {
		return nil, fmt.Errorf("打开接口失败: %v", err)
	}
	defer handle.Close()

	// 4. 设置BPF过滤器(只接收ARP响应)
	filter := "arp and ether dst " + iface.HardwareAddr.String()
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("设置过滤器失败: %v", err)
	}

	// 5. 构造ARP请求包
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 广播地址
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0}, // 待填充
		DstProtAddress:    targetIP.To4(),
	}

	// 6. 序列化并发送ARP请求
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return nil, fmt.Errorf("序列化ARP请求失败: %v", err)
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("发送ARP请求失败: %v", err)
	}

	// 7. 接收ARP响应
	start := time.Now()
	for {
		if time.Since(start) > time.Second*5 { // 2秒超时
			return nil, fmt.Errorf("ARP响应超时")
		}

		data, _, err := handle.ReadPacketData()
		if err != nil {
			continue // 跳过读取错误
		}

		// 解析数据包
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arpResponse, _ := arpLayer.(*layers.ARP)

			// 验证是否是我们的目标IP的响应
			if arpResponse.Operation == layers.ARPReply &&
				net.IP(arpResponse.SourceProtAddress).Equal(targetIP) {
				macArpCache.Add(targetIP.String(), net.HardwareAddr(arpResponse.SourceHwAddress))

				return net.HardwareAddr(arpResponse.SourceHwAddress), nil
			}
		}
	}
}

func isSameSubnet(ip net.IP, iface *net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func GetMacAddress(targetIP net.IP, iface *net.Interface, gatewayIP net.IP) (net.HardwareAddr, error) {
	// 如果在同一个子网内，则直接使用arp请求
	// 如果不在同子网内，则使用网关mac
	if !isSameSubnet(targetIP, iface) {
		return resolveMACWithGopacket(iface, gatewayIP)
	}
	return resolveMACWithGopacket(iface, targetIP)

}
