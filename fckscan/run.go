package fckscan

import (
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"strings"
	"sync"
)

// 运行
func getUrlData(url string) (urldata urlDataType, err error) {
	// 判断是否有添加http
	if strings.Index(url, "http") != 0 {
		url = "http://" + url
	}
	// 进行本地域名反查
	addrs, err := local_domain(url)
	if err != nil {
		err = errors.New(url + " no such host")
		return
	}
	// 赋值
	urldata.Url = url
	urldata.Subdomain = append(urldata.Subdomain, addrs...)
	// 判断是否只进行本地域名反查
	if LocalDomain {
		urldata.Code = 0
		return
	}
	// //////////////////////////////////////////////////////////////
	// // 进行网络webscan.cc域名反查
	// addrs, err = net_domain(urldata.Url)
	// if err != nil {
	// 	err = errors.New(url + " no such host")
	// 	return
	// }
	// urldata.Subdomain = append(urldata.Subdomain, addrs...)
	// //////////////////////////////////////////////////////////////////////////
	// 请求运行
	rdt, code, err := reqUrl(url, user_Agents[rand.Intn(len(user_Agents))])
	// 赋值
	urldata.Code = code
	urldata.Title = getTitle(rdt)
	urldata.Finger = getFinger(rdt)
	urldata.Subdomain = addrs
	return
}

// 主函数
func Run() {
	// 声明全局等待组变量
	var wg sync.WaitGroup
	// 处理flag
	Flag()
	// 判断是否输入IP
	if Host == "" && HostFile == "" {
		fmt.Println("[\033[31;1m-\033[0m] 没有检测的URL！")
		flag.Usage()
		return
	}
	// 读取文件
	if HostFile != "" {
		hf, err := ProcessIPFile(HostFile)
		if err == nil {
			Host = Host + hf
		} else {
			fmt.Printf("%s 文件读取识别，使用Host参数！\n", ERR)
		}
	}
	// 解析主机
	hosts := RemoveDuplicate(ProcessIPs(Host))
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
