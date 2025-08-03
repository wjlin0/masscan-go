package target

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
)

type Target struct {
	// 本地 ip地址
	SrcIp net.IP
	// src ip
	DstIp   net.IP
	SrcPort int
}

// ParseIps 解析目标IP地址或CIDR
func ParseIps(target []string) ([]net.IP, error) {
	var targets []string

	t := func(target []string) ([]string, error) {
		var _targets []string
		for i := 0; i < len(target); i++ {
			if strings.Contains(target[i], "-") {
				ipRange := strings.Split(target[i], "-")
				endIp := ipRange[1]
				endIpint, _ := strconv.Atoi(endIp)
				startIp := strings.Split(ipRange[0], ".")
				if len(startIp) != 4 {
					return nil, fmt.Errorf("invalid IP address: %s", target[i])
				}
				startIpint, _ := strconv.Atoi(startIp[3])
				for ; startIpint <= endIpint; startIpint++ {
					_targets = append(_targets, fmt.Sprintf("%s.%d", strings.Join(startIp[:3], "."), startIpint))
				}
				continue
			}

			if ip, ipnet, err := net.ParseCIDR(target[i]); err == nil {
				for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
					_targets = append(_targets, ip.String())
				}
				continue
			}
			_targets = append(_targets, target[i])
		}
		// 去重
		var targetsMap = make(map[string]struct{})
		for _, _target := range _targets {
			targetsMap[_target] = struct{}{}
		}
		_targets = make([]string, 0, len(targetsMap))
		for _target := range targetsMap {
			_targets = append(_targets, _target)
		}
		return _targets, nil
	}

	for i := 0; i < len(target); i++ {
		if strings.Contains(target[i], ",") {
			tmps, err := t(strings.Split(target[i], ","))
			if err != nil {
				return nil, err
			}
			targets = append(targets, tmps...)
		} else {
			tmps, err := t([]string{target[i]})
			if err != nil {
				return nil, err
			}
			targets = append(targets, tmps...)
		}

	}

	// 去重
	targetsMap := make(map[string]struct{})
	for _, _target := range targets {
		targetsMap[_target] = struct{}{}
	}
	targets = []string{}
	for _target := range targetsMap {
		targets = append(targets, _target)
	}
	var ParseIps []net.IP
	for _, _t := range targets {
		ParseIps = append(ParseIps, net.ParseIP(_t))
	}
	return ParseIps, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

var Top1000 = []int{2022, 1022, 20443, 30443, 40443, 50443, 60443, 8848, 7, 9, 11, 13, 17, 19, 21, 22, 23, 26, 37, 38, 43, 49, 51, 53, 67, 69, 70, 79, 80, 81, 82, 83, 84, 85, 86, 88, 89, 102, 104, 111, 113, 119, 121, 123, 135, 137, 138, 139, 143, 161, 175, 179, 199, 211, 264, 311, 389, 443, 444, 445, 465, 500, 502, 503, 512, 515, 520, 548, 554, 564, 587, 623, 631, 636, 646, 666, 771, 777, 789, 800, 801, 808, 853, 873, 880, 888, 902, 992, 993, 995, 999, 1000, 1022, 1023, 1024, 1025, 1026, 1027, 1080, 1099, 1177, 1194, 1200, 1201, 1234, 1241, 1248, 1260, 1290, 1311, 1344, 1400, 1433, 1443, 1471, 1494, 1515, 1521, 1554, 1588, 1701, 1720, 1723, 1741, 1777, 1863, 1883, 1900, 1911, 1935, 1962, 1967, 1991, 2000, 2001, 2002, 2020, 2022, 2030, 2031, 2049, 2052, 2053, 2077, 2080, 2082, 2083, 2086, 2087, 2095, 2096, 2121, 2123, 2152, 2181, 2222, 2223, 2252, 2323, 2332, 2375, 2376, 2379, 2401, 2404, 2424, 2427, 2443, 2455, 2480, 2501, 2601, 2628, 3000, 3001, 3002, 3006, 3128, 3260, 3283, 3288, 3299, 3306, 3307, 3310, 3333, 3388, 3389, 3390, 3443, 3460, 3541, 3542, 3689, 3690, 3749, 3780, 4000, 4022, 4040, 4063, 4064, 4111, 4343, 4369, 4430, 4433, 4443, 4444, 4500, 4505, 4567, 4664, 4712, 4730, 4782, 4786, 4840, 4848, 4880, 4911, 4949, 5000, 5001, 5002, 5004, 5005, 5006, 5007, 5009, 5050, 5060, 5084, 5222, 5258, 5269, 5351, 5353, 5357, 5400, 5432, 5443, 5500, 5554, 5555, 5556, 5560, 5577, 5601, 5631, 5672, 5678, 5683, 5800, 5801, 5900, 5901, 5902, 5903, 5938, 5984, 5985, 5986, 6000, 6001, 6002, 6003, 6005, 6006, 6050, 6060, 6068, 6110, 6363, 6379, 6443, 6488, 6560, 6565, 6581, 6588, 6590, 6600, 6664, 6665, 6666, 6667, 6668, 6669, 6699, 6881, 6998, 7000, 7001, 7002, 7003, 7005, 7006, 7010, 7014, 7025, 7070, 7071, 7077, 7080, 7170, 7288, 7306, 7307, 7312, 7401, 7443, 7474, 7493, 7537, 7547, 7548, 7634, 7657, 7777, 7779, 7788, 7911, 8000, 8001, 8002, 8003, 8004, 8006, 8008, 8009, 8010, 8015, 8020, 8025, 8030, 8040, 8060, 8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8111, 8112, 8118, 8123, 8125, 8126, 8139, 8159, 8161, 8180, 8181, 8182, 8200, 8222, 8291, 8333, 8334, 8377, 8378, 8388, 8443, 8500, 8545, 8546, 8554, 8649, 8686, 8800, 8834, 8880, 8883, 8887, 8888, 8889, 8899, 8983, 8999, 9000, 9001, 9002, 9003, 9009, 9010, 9030, 9042, 9050, 9051, 9080, 9083, 9090, 9091, 9100, 9151, 9191, 9200, 9295, 9333, 9418, 9443, 9444, 9527, 9530, 9595, 9600, 9653, 9700, 9711, 9869, 9944, 9981, 9997, 9999, 10000, 10001, 10003, 10162, 10243, 10333, 10443, 10554, 11001, 11211, 11300, 11310, 12300, 12345, 13579, 14000, 14147, 14265, 16010, 16030, 16992, 16993, 17000, 18000, 18001, 18080, 18081, 18245, 18246, 19999, 20000, 20547, 20880, 22105, 22222, 23023, 23424, 25000, 25105, 25565, 27015, 27017, 28017, 28080, 29876, 30001, 32400, 33338, 33890, 37215, 37777, 41795, 45554, 49151, 49152, 49153, 49154, 49155, 50000, 50050, 50070, 50100, 51106, 52869, 55442, 55553, 55555, 60001, 60010, 60030, 60443, 61613, 61616, 62078, 64738}
var Top100 = []int{80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 5900, 8888, 81, 10000, 514, 5060, 2000, 8443, 8000, 32768, 554, 1433, 49152, 2001, 8008, 49154, 5666, 5000, 5631, 49153, 8081, 2049, 88, 79, 5800, 2121, 1110, 49155, 6000, 513, 990, 5357, 543, 544, 5101, 389, 8009, 444, 9999, 5009, 7070, 5190, 3000, 5432, 3986, 1900, 6646, 5051, 49157, 873, 1755, 2717, 4899, 9100, 82, 83, 85, 888, 1521, 3443, 4430, 4433, 4443, 5443, 5985, 6379, 7001, 8001, 8002, 8003, 8010, 8082, 8086, 8088, 8089, 8090, 9000, 9043, 9200, 9443, 10443, 11211, 27017, 8848, 20443}

// ParsePorts 解析端口范围
func ParsePorts(ports string, topPort int) ([]int, error) {
	var portList []int
	parts := strings.Split(ports, ",")
	if len(ports) == 0 {
		if topPort == 1000 {
			return Top1000, nil
		} else {
			return Top100, nil
		}
	}

	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := parsePort(rangeParts[0])
			if err != nil {
				return nil, err
			}

			end, err := parsePort(rangeParts[1])
			if err != nil {
				return nil, err
			}

			if start > end {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}

			for i := start; i <= end; i++ {
				portList = append(portList, i)
			}
		} else {
			port, err := parsePort(part)
			if err != nil {
				return nil, err
			}
			portList = append(portList, port)
		}
	}

	return portList, nil
}

func parsePort(portStr string) (int, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %s", portStr)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return port, nil
}

// ShuffleTargets 随机化目标顺序
func ShuffleTargets(ipList []net.IP, portList []int) {
	// 注意：由于math/rand在scanner中已经初始化，这里我们不重新初始化
	// 在实际使用中，可能需要传递随机数生成器实例
	rand.Shuffle(len(ipList), func(i, j int) {
		ipList[i], ipList[j] = ipList[j], ipList[i]
	})
	rand.Shuffle(len(portList), func(i, j int) {
		portList[i], portList[j] = portList[j], portList[i]
	})
}
