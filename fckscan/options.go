package fckscan

import (
	"errors"
	"flag"
	"fmt"
)

// 用户输入指令的解析
var (
	// 主机
	Host string
	// cookie
	Cookie string
	// 代理
	Proxy string
	// 协程
	ThreadNum int
	// 请求超时
	Timeout int
	// 获取文件
	HostFile string
	// 域名反查
	RcDomain int
	// 存储结果日志
	outfile string
	// 用户自定义的dns文件
	DnsServerFile string
	// 用户自定义的dns
	DnsServer string
	// 读取指纹文件
	RuleFile string
	// 日志等级
	DebugLevel int
)

// 处理flag
func Flag() {
	tag()
	flag.StringVar(&Host, "t", "", "设置host")
	flag.StringVar(&HostFile, "tf", "", "读取host文件")
	flag.StringVar(&Cookie, "ck", "", "设置cookie")
	flag.StringVar(&Proxy, "proxy", "", "设置代理，如：socks5://127.0.0.1:1080、http://127.0.0.1:8080")
	flag.StringVar(&RuleFile, "rf", "", "设置指纹文件")
	flag.StringVar(&DnsServerFile, "dsf", "", "读取dns文件")
	flag.StringVar(&DnsServer, "ds", "223.5.5.5,8.8.8.8,180.76.76.76,119.29.29.29,182.254.116.116", "自定义dns")
	flag.StringVar(&outfile, "outfile", "fckscanlog.txt", "保存日志文件")
	flag.IntVar(&RcDomain, "rcd", 0, "域名反查功能,1(只进行域名反查)/2(不显示域名反查结果)/其他数字(全部显示)")
	flag.IntVar(&DebugLevel, "debug", 0, "debug等级日志,0(Basic)/1(Error)/3(Warn)/4(Debug)")
	flag.IntVar(&ThreadNum, "n", 100, "设置线程")
	flag.IntVar(&Timeout, "timeout", 5, "设置请求超时")
	flag.Parse()
}

// 处理数据
func ParseFlag() error {
	// 处理主机
	// 判断是否输入IP
	if Host == "" && HostFile == "" {
		return errors.New("没有检测的主机！")
	}
	// 读取文件
	if HostFile != "" {
		hf, err := processFile(HostFile)
		// 为了防止前面有多个逗号
		if err == nil && Host != "" {
			Host = Host + "," + hf
		} else if err == nil {
			Host = hf
		} else if Host != "" {
			InfoLog("自定义hosts文件读取识别，即将使用Host参数的主机！")
		} else {
			return errors.New("没有可用的URL或者URL文件！")
		}
	}
	// 解析主机
	hosts = processIPs(Host)
	DebugLog("检测的主机为：%v", hosts)
	if len(hosts) == 0 {
		return errors.New("输入的主机不合规！")
	}
	// 处理dns
	// 读取文件
	if DnsServerFile != "" {
		ds, err := processFile(DnsServerFile)
		if err == nil && DnsServer != "" {
			DnsServer = DnsServer + "," + ds
		} else if err == nil {
			DnsServer = ds
		} else {
			InfoLog("自定义dns文件读取识别，即将默认dns！")
		}
	}
	// 解析dns主机
	dnsServerstmp := processIPs(DnsServer)
	for _, i := range dnsServerstmp {
		if ok := ExecCommandPing(i); ok {
			dnsServers = append(dnsServers, i)
		}
	}
	DebugLog("存活的DNS为：%v", dnsServers)

	// 处理指纹文件
	if RuleFile != "" {
		rd, err := Readjsonfile(RuleFile)
		if err == nil {
			ruleDatas = append(rd, ruleDatas...)
		} else {
			InfoLog("自定义指纹文件读取识别错误，即将使用默认规则！")
		}
	}
	return nil
}

// Tag
func tag() {
	fmt.Printf("________   |\\\n")
	fmt.Printf("\\   ___/___| | _______________|\\   ___\n")
	fmt.Printf(" | |__/  __| |/ / __/  __/ _\033[1;34m*\033[0m | \\ |\033[1;34m*\033[0m / \n")
	fmt.Printf(" |  _/\\ \033[1;32m(\033[0m__|   \033[1;31m<\033[0m\\__ \\ \033[1;35m(\033[0m_| \033[0;38;5;214m(\033[0m_| | |\\| | \033[1;31m❤\033[0m\n")
	fmt.Printf(" | |   \\___| |\\__\\__/\\___\\__,_|__\\\\ |\n")
	fmt.Printf(" |/        |/ fckscan ver: %s%-8s%s\\|\n", YELLOW, version, END)
	fmt.Println("")
}
