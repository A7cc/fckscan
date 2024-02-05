package fckscan

import (
	"net/http"
	"regexp"
	"runtime"
)

// 存放url信息结构体
type urlDataType struct {
	Url       string   `json:"url"`
	Code      int      `json:"code"`
	Title     string   `json:"title"`
	Length    int      `json:"length"`
	Finger    []string `json:"finger"`
	Subdomain []string `json:"subdomain"`
}

// 指纹识别的内容类型
type ruleType struct {
	// 框架的版本或者设备名字
	Version string `json:"version"`
	// 框架详细性的等级
	Level int `json:"level"`
	// 路径
	Path []string `json:"path"`
	// 身体
	Body string `json:"body"`
	// 请求头
	Header string `json:"header"`
	// 哈希
	Icon_hash string `json:"icon_hash"`
}

// 指纹数据类型
type ruleData struct {
	// 指纹总名字
	Name string `json:"name"`
	// 指纹检测规则
	Rules []ruleType
}

// 存储网页信息
type resDataType struct {
	// url
	Url string `json:"url"`
	// Header
	Header string `json:"header"`
	// body
	Body []byte `json:"body"`
}

// 基本信息
var (
	// 设置操作系统
	OS = runtime.GOOS
	// 版本
	version string = "2.0.1"
	// dns存放列表
	dnsServers []string
	// 存放IP列表
	hosts []string
)

// 设置请求时的信息
var Client *http.Client

// UA
var user_Agents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 YaBrowser/21.6.0.615 Yowser/2.5 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Edge/91.0.864.59",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (Linux; Android 11; SM-G991U Build/RP1A.200720.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
	"Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre",
	"Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60",
	"Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 ",
	"Safari/533.18.5",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5660.225 Safari/537.36",
}

// 正则表达式
var reTitle = regexp.MustCompile(`(?ims)<title.*?>(.*?)</title>`)
