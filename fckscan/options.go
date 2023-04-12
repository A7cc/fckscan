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
	RcDomain bool
	// 存储结果日志
	outfile string
	// 用户自定义的dns文件
	DnsServerFile string
	// 用户自定义的dns
	DnsServer string
	// 读取指纹文件
	RuleFile string
)

// 处理flag
func Flag() {
	tag()
	flag.StringVar(&Host, "u", "", "设置host")
	flag.StringVar(&HostFile, "hf", "", "读取host文件")
	flag.StringVar(&Cookie, "ck", "", "设置cookie")
	flag.StringVar(&Proxy, "proxy", "", "设置代理")
	flag.StringVar(&RuleFile, "rf", "", "设置指纹文件")
	flag.StringVar(&DnsServerFile, "dsf", "", "读取dns文件")
	flag.StringVar(&DnsServer, "ds", "8.8.8.8,114.114.114.114", "自定义dns")
	flag.StringVar(&outfile, "outfile", "fckscanlog.txt", "保存日志文件")
	flag.BoolVar(&RcDomain, "rcd", false, "是否只进行域名反查")
	flag.IntVar(&ThreadNum, "t", 100, "设置线程")
	flag.IntVar(&Timeout, "timeout", 5, "设置请求超时")
	flag.Parse()

}

// 处理数据
func ParseFlag() error {
	// 处理主机
	// 判断是否输入IP
	if Host == "" && HostFile == "" {
		return errors.New("没有检测的URL！")
	}
	// 读取文件
	if HostFile != "" {
		hf, err := ProcessFile(HostFile)
		if err == nil {
			Host = Host + "," + hf
		} else {
			fmt.Printf("%s 自定义hosts文件读取识别，使用Host参数！\n", ERR)
		}
	}
	// 解析主机
	hosts = ProcessIPs(Host)

	// 处理dns
	// 读取文件
	if DnsServerFile != "" {
		ds, err := ProcessFile(DnsServerFile)
		if err == nil {
			DnsServer = DnsServer + ds
		} else {
			fmt.Printf("%s 自定义dns文件读取识别，使用ds参数！\n", ERR)
		}
	}
	// 解析dns主机
	dnsServers = ProcessIPs(DnsServer)

	// 处理指纹文件
	if RuleFile != "" {
		rd, err := Readjsonfile(RuleFile)
		if err == nil {
			ruleDatas = append(rd, ruleDatas...)
		} else {
			fmt.Printf("%s 自定义指纹文件读取识别，即将使用默认规则！\n", ERR)
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
