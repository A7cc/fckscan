package fckscan

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// 请求页面获取对应信息
func reqUrl(Url, cookie, ua string) (req resDataType, code int, err error) {
	// 构造第一次请求
	requ, err := http.NewRequest(http.MethodGet, Url, nil)
	if err != nil {
		return
	}
	// 设置请求头信息
	// TODO:=============还有其他请求头
	requ.Header.Set("User-Agent", ua)
	requ.Header.Set("Accept", "*/*")
	requ.Header.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	requ.Header.Set("Connection", "close")
	if cookie != "" {
		requ.Header.Set("Cookie", cookie)
	}
	// 发起第一次请求
	resp, err := Client.Do(requ)
	if err != nil {
		return
	}
	// 使用defer在最后关闭连接
	defer resp.Body.Close()
	// 显示响应状态码信息
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	req = resDataType{
		Url:    Url,
		Header: fmt.Sprintf("%v", resp.Header),
		Body:   body,
	}
	return req, resp.StatusCode, nil
}

// 处理body以及编码
func processBody(body []byte) string {
	// TODO:==================编码问题
	// 判断body是否是完全由有效的UTF-8编码符文组成
	// icon由于需要进行哈希，不能修改任何内容所以需要源内容
	if !utf8.Valid(body) {
		// 如果不是那就改为GBK
		body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
	}
	return string(body)
}

// 处理文件
func processFile(filename string) (tmps string, err error) {
	// 打开文件
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	// 开始读取文件
	scanner := bufio.NewScanner(file)
	// 循环读取
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 判断读取内容是否为空
		if line != "" {
			tmps = tmps + "," + line
		}
	}
	// 去掉最前面的逗号
	tmps = tmps[1:]
	// 判断是否存在终止错误
	if err := scanner.Err(); err != nil {
		return tmps, err
	}
	return tmps, nil
}

// 处理主机
func processIPs(host string) (hostlist []string) {
	// 判断是否有逗号
	if strings.Contains(host, ",") {
		// 如果有逗号将其划分多个IP表
		IPList := strings.Split(host, ",")
		// 循环处理IP表
		for _, ip := range IPList {
			if find := strings.HasPrefix(ip, "http"); find {
				hostlist = append(hostlist, ip)
			} else {
				ips := parseIP(ip)
				hostlist = append(hostlist, ips...)
			}
		}
	} else {
		if find := strings.HasPrefix(host, "http"); find {
			hostlist = append(hostlist, host)
		} else {
			hostlist = parseIP(host)
		}
	}
	return RemoveDuplicate(hostlist)
}

// 根据用户给出的ip形式进行分类
func parseIP(ip string) []string {
	reg := regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case strings.HasSuffix(ip, "/8"):
		// 扫描/8时，由于A段太多了，只扫网关和随机IP，避免扫描过多IP
		return parseIP8(ip)
	case strings.Contains(ip, "/24") || strings.Contains(ip, "/16"):
		// 解析 /24 /16等
		return parseIP2(ip)
	case reg.MatchString(ip):
		// 域名用lookup获取ip
		host, err := net.LookupHost(ip)
		if err != nil {
			return nil
		}
		return host
	case strings.Contains(ip, "-"):
		// 处理192.168.1.1-192.168.1.100或者192.168.1.1-24
		return parseIP1(ip)
	default:
		// 处理单个ip
		testIP := net.ParseIP(ip)
		if testIP == nil {
			return nil
		}
		return []string{ip}
	}
}

// 把 192.168.x.x/xx 转换成IP列表
func parseIP2(host string) (hosts []string) {
	// 使用 net.ParseCIDR() 方法解析给定的网段，返回网段的 IP 地址和子网掩码
	// 检查给定的网段是否正确
	ipone, ipNet, err := net.ParseCIDR(host)
	if err != nil {
		return
	}
	// 把 192.168.x.x/xx 转换成 192.168.x.x-192.168.x.x 并转成IP列表
	hosts = parseIP1(IPRange(ipone.String(), ipNet))
	return
}

// 解析ip段: 192.168.111.1-255，192.168.111.1-192.168.112.255
func parseIP1(ip string) []string {
	// 如果有逗号将其划分多个
	IPRangelist := strings.Split(ip, "-")
	// 确认该IP格式是否为正确IP
	testIP := net.ParseIP(IPRangelist[0])
	// 创建一个存储所有IP列表
	var allIP []string
	// 通过len函数来确认IPRangelist[1]是192.168.1.255形式还是数字形式
	if len(IPRangelist[1]) < 4 {
		// 处理数字形式
		// 将字符串转成数字
		Range, err := strconv.Atoi(IPRangelist[1])
		// 判断合理性
		if testIP == nil || Range > 255 || err != nil {
			return nil
		}
		// 分离IP
		SplitIP := strings.Split(IPRangelist[0], ".")
		// 转换为数字
		ip1, err1 := strconv.Atoi(SplitIP[3])
		// 拼接
		PrefixIP := SplitIP[0] + "." + SplitIP[1] + "." + SplitIP[2]
		// 判断合理性
		if ip1 > Range || err1 != nil {
			return nil
		}
		// 循环拼接IP
		for i := ip1; i <= Range; i++ {
			allIP = append(allIP, PrefixIP+"."+strconv.Itoa(i))
		}
	} else {
		// 处理192.168.1.255形式
		// 分离IP
		SplitIP1 := strings.Split(IPRangelist[0], ".")
		SplitIP2 := strings.Split(IPRangelist[1], ".")
		// 判断合理性
		if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
			return nil
		}
		// 用于存放起始IP和结束IP列表
		start, end := [4]int{}, [4]int{}
		// 循环读取4段IP
		for i := 0; i < 4; i++ {
			// 转换为数字
			ip1, err1 := strconv.Atoi(SplitIP1[i])
			ip2, err2 := strconv.Atoi(SplitIP2[i])
			// 判断合理性
			if ip1 > ip2 || err1 != nil || err2 != nil {
				return nil
			}
			// 添加到起始IP和结束IP列表
			start[i], end[i] = ip1, ip2
		}
		// 通过移位运算，将地址改为数字的形式
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
		// 通过循环将数字转成地址
		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
			allIP = append(allIP, ip)
		}
	}
	return allIP
}

// 获取把 192.168.x.x/xx 转换成 192.168.x.x-192.168.x.x的起始IP、结束IP
func IPRange(start string, c *net.IPNet) string {
	// 16进制子网掩码
	mask := c.Mask
	// 创建一个net.ip类型
	bcst := make(net.IP, len(c.IP))
	// 将dreams值给bcst
	copy(bcst, c.IP)
	// 获取结束IP
	for i := len(mask) - 1; i >= 0; i-- {
		bcst[i] = c.IP[i] | ^mask[i]
	}
	end := bcst.String()
	// 返回用-表示的ip段,192.168.1.1-192.168.255.255
	return fmt.Sprintf("%s-%s", start, end)
}

// 处理B段IP
func parseIP8(ip string) []string {
	// 去掉最后的/8
	realIP := ip[:len(ip)-2]
	// net.ParseIP 这个方法用来检查 ip 地址是否正确，如果不正确，该方法返回 nil
	testIP := net.ParseIP(realIP)
	// 判断该IP是否为正常IP
	if testIP == nil {
		return nil
	}
	// 获取IP的头部
	IP8head := strings.Split(ip, ".")[0]
	// 存放B段IP
	var allIP []string
	// 构造B段的随机IP表
	for a := 0; a <= 255; a++ {
		for b := 0; b <= 255; b++ {
			// 一般情况下网关为1或者254
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", IP8head, a, b, 1))
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", IP8head, a, b, RandInt(2, 80)))
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", IP8head, a, b, RandInt(81, 170)))
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", IP8head, a, b, RandInt(171, 253)))
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", IP8head, a, b, 254))
		}
	}
	return allIP
}

// 随机数
func RandInt(min, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Intn(max-min) + min
}
