package fckscan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// 初始化http客户端连接
func InitClient(Proxy string, Timeout int) error {
	// tcp连接设置连接的时间
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
	}
	// 设置tr
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     5,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}
	// 设置代理
	if Proxy != "" {
		proxyURL, err := url.Parse(Proxy)
		if err != nil {
			return err
		} else {
			// 设置代理
			tr.Proxy = http.ProxyURL(proxyURL)
		}
	}
	// 设置客户端
	Client = &http.Client{
		// 设置请求信息
		Transport: tr,
		// 设置超时时间
		Timeout: time.Duration(Timeout) * time.Second,
	}
	return nil
}

// 请求页面获取对应信息
func reqUrl(Url, ua string) (req resDataType, code int, err error) {
	// 初始化http连接信息
	err = InitClient(Proxy, Timeout)
	if err != nil {
		log.Fatal(err)
	}
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
	// requ.Header.Set("Accept-Encoding", "gzip, deflate")
	if Cookie != "" {
		requ.Header.Set("Cookie", Cookie)
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
	// 判断body是否是完全由有效的UTF-8编码符文组成
	if !utf8.Valid(body) {
		// 如果不是那就改为GBK
		body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
	}
	req = resDataType{
		Url:    Url,
		Header: fmt.Sprintf("%v", resp.Header),
		Body:   string(body),
	}
	return req, resp.StatusCode, nil
}

// 处理主机
func ProcessIPs(host string) (hostlist []string) {
	// 判断是否有逗号
	if strings.Contains(host, ",") {
		// 如果有逗号将其划分多个IP表
		IPList := strings.Split(host, ",")
		// 循环处理IP表
		hostlist = append(hostlist, IPList...)
	} else {
		hostlist = append(hostlist, host)
	}
	return RemoveDuplicate(hostlist)
}

// 处理文件
func ProcessFile(file string) (tmps string, err error) {
	// 打开文件
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// 创建缓存区
	r := bufio.NewReader(f)
	for {
		// 读取'\n'表示结束
		lineS, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}

		line := strings.TrimSpace(lineS)
		// 判断读取内容是否为空
		if line != "" {
			tmps = tmps + "," + line
		}

		// 出现io.EOF就跳出循环
		if err == io.EOF {
			break
		}
	}
	return tmps, nil
}
