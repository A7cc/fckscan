package fckscan

import (
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
	// 本地域名反查
	LocalDomain bool
	// 存储结果日志
	outfile string
)

// 处理flag
func Flag() {
	tag()
	flag.StringVar(&Host, "u", "", "设置host")
	flag.StringVar(&Cookie, "ck", "", "设置cookie")
	flag.StringVar(&Proxy, "proxy", "", "设置代理")
	flag.StringVar(&HostFile, "hf", "", "读取host文件")
	flag.StringVar(&outfile, "outfile", "fckscanlog.txt", "保存日志文件")
	flag.BoolVar(&LocalDomain, "ld", false, "是否只进行本地域名反查")
	flag.IntVar(&ThreadNum, "t", 100, "设置线程")
	flag.IntVar(&Timeout, "timeout", 5, "设置请求超时")
	flag.Parse()
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
