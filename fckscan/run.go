package fckscan

import (
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"sync"
)

// 运行
func getUrlData(host string) (urldata urlDataType, err error) {
	// 判断是否有添加http
	if strings.Index(host, "http") != 0 {
		host = "http://" + host
	}
	// todo:需要扩展，可以加在一起
	// //////////////////////////////////////////////////////////////
	// 验证该域名是否为有效域名
	domain, err := url.Parse(host)
	if err != nil {
		return
	}
	// 存放域名
	var addrs []string
	if dnsServers != nil {
		// 进行域名反查，随机选择
		addrs, err = reverse_check_domain(domain.Hostname(), dnsServers[rand.Intn(len(dnsServers))])
		if err != nil {
			fmt.Println(ERR, err)
			// 进行本地域名反查
			addrs, err = local_domain(domain.Hostname())
		}
	} else {
		// 进行本地域名反查
		addrs, err = local_domain(domain.Hostname())
	}
	// 处理错误
	if err != nil {
		err = errors.New(host + " no such host")
		return
	}

	// //////////////////////////////////////////////////////////////////////////
	// 赋值
	urldata.Url = host
	urldata.Subdomain = RemoveDuplicate(addrs)
	// 判断是否只进行域名反查
	if RcDomain {
		urldata.Code = 0
		return
	}
	// 请求运行
	rdt, code, err := reqUrl(host, user_Agents[rand.Intn(len(user_Agents))])
	// 赋值
	urldata.Code = code
	urldata.Title = getTitle(rdt)
	urldata.Finger = getFinger(rdt)
	return
}

// 主函数
func Run() {
	// 声明全局等待组变量
	var wg sync.WaitGroup
	// 处理flag
	Flag()
	// 处理数据
	err := ParseFlag()
	if err != nil {
		fmt.Println(ERR, err)
		flag.Usage()
		return
	}
	// 创建通道
	host := make(chan string)
	// 开始检测
	fmt.Printf("[%s*%s] 开始检测！\n", BLUE, END)
	// 开始执行多协程工作
	for i := 0; i < ThreadNum; i++ {
		go func() {
			for h := range host {
				// 获取
				urldata, err := getUrlData(h)
				var log string
				if err != nil {
					log = "ERROR：" + err.Error()
					fmt.Println(ERR, log)
				} else if urldata.Code == 0 {
					log = fmt.Sprintf("Url：%-30s |  Subdomain：%v", urldata.Url, urldata.Subdomain)
					fmt.Println(RIGHT, log)
				} else if urldata.Code == 200 {
					log = fmt.Sprintf("Url：%-30s |  Title：%v  |  Finger：%v  |  Subdomain：%v  |  Code：%d", urldata.Url, urldata.Title, urldata.Finger, urldata.Subdomain, urldata.Code)
					fmt.Printf("%s Url：%-30s |  Title：%s%v%s  |  Finger：%v  |  Subdomain：%v  |  Code：%s%d%s\n", RIGHT, urldata.Url, ORANGE, urldata.Title, END, urldata.Finger, urldata.Subdomain, GREEN, urldata.Code, END)
				} else {
					log = fmt.Sprintf("Url：%-30s |  Title：%v  |  Finger：%v  |  Subdomain：%v  |  Code：%d", urldata.Url, urldata.Title, urldata.Finger, urldata.Subdomain, urldata.Code)
					fmt.Printf("%s Url：%-30s |  Title：%s%v%s  |  Finger：%v  |  Subdomain：%v  |  Code：%s%d%s\n", RIGHT, urldata.Url, ORANGE, urldata.Title, END, urldata.Finger, urldata.Subdomain, RED, urldata.Code, END)
				}
				// 写入日志
				WriteFile(log, outfile)
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
	fmt.Printf("[%s*%s] 检测结束！\n", BLUE, END)
}
