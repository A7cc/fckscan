package fckscan

import (
	"flag"
	"fmt"
	"math/rand"
	"strings"
	"sync"
)

// 运行
func getUrlData(host string) (urldata urlDataType, err error) {
	// 判断是否有添加http
	DebugLog("检测 %v 使用的协议", host)
	if strings.Index(host, "http") != 0 {
		// GetProtocol是判断协议
		host = GetProtocol(host, int64(Timeout)) + "://" + host
	}
	// 判断末尾是否有
	if host[len(host)-1] == '/' {
		host = string(host[:len(host)-1])
	}

	// 域名反查
	DebugLog("对 %v 进行域名反查", host)
	addrs, err := getReDomain(host)
	if err != nil {
		urldata.Code = -1
		return
	}
	// 赋值
	urldata.Url = host
	urldata.Subdomain = addrs
	// 判断是否只进行域名反查
	if RcDomain == 1 {
		urldata.Code = 0
		return urldata, nil
	}
	DebugLog("对 %v 进行指纹识别", host)
	// 获取页面信息
	rdt, code, err := reqUrl(host, Cookie, user_Agents[rand.Intn(len(user_Agents))])
	// 处理错误
	if err != nil {
		WarningLog(err.Error())
		return urldata, nil
	}
	// 赋值
	urldata.Code = code
	urldata.Title = getTitle(rdt)
	urldata.Finger = getFinger(rdt)
	// 有时候获取不到响应体的Content-Length，所以我们只能使用len函数获取
	urldata.Length = len(rdt.Body)
	return
}

// 主函数
func Run() {
	// 处理flag
	Flag()
	// 初始化数据
	err := ParseFlag()
	if err != nil {
		fmt.Println(ERR, err)
		flag.Usage()
		return
	}
	// 初始化http连接信息
	err = InitClient(Proxy, Timeout)
	if err != nil {
		return
	}
	DebugLog("初始化网络连接信息")
	// 声明全局等待组变量
	var wg sync.WaitGroup
	// 创建通道
	host := make(chan string)
	// 开始检测
	InfoLog("开始检测")
	DebugLog("开启 %v 个协程", ThreadNum)
	// 开始执行多协程工作
	for i := 0; i < ThreadNum; i++ {
		go func() {
			for h := range host {
				// 获取
				urldata, err := getUrlData(h)
				if err != nil {
					if urldata.Code < 0 {
						// 必须输出的错误
						ErrorLog(err.Error())
					} else {
						ErrLog(err.Error())
					}
				} else if urldata.Code == 0 && RcDomain != 2 {
					RightLog("Url：%-30s |  Subdomain：%v", urldata.Url, urldata.Subdomain)
				} else if urldata.Code == 200 {
					RightLog("Url：%-30s |  Title：%s%v%s  |  Code：%s%d%s  |  Lenght：%v  |  Finger：%v  |  Subdomain：%v", urldata.Url, BLUE, urldata.Title, END, GREEN, urldata.Code, END, urldata.Length, urldata.Finger, urldata.Subdomain)
				} else if RcDomain != 2 {
					RightLog("Url：%-30s |  Title：%s%v%s  |  Code：%s%d%s  |  Lenght：%v  |  Finger：%v  |  Subdomain：%v", urldata.Url, BLUE, urldata.Title, END, RED, urldata.Code, END, urldata.Length, urldata.Finger, urldata.Subdomain)
				}
				wg.Done()
			}
		}()
	}
	// 添加到隧道里
	for _, val := range hosts {
		host <- val
		wg.Add(1)
	}
	// 关闭通道，让go func运行下去
	close(host)
	wg.Wait() // 阻塞等待登记的goroutine完成
	InfoLog("检测结束！")
}
