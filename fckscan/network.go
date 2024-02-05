package fckscan

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
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

// 创建连接
func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	// 创建连接，设置超时
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	// 判断socket5为空
	if Proxy == "" {
		var err error
		// 建立连接
		conn, err = d.Dial(network, address)
		if err != nil {
			return nil, err
		}
	} else {
		// 使用socks5代理连接
		dailer, err := Socks5Dailer(d)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

// socks5代理连接
func Socks5Dailer(forward *net.Dialer) (proxy.Dialer, error) {
	// 将string解析成*URL格式
	u, err := url.Parse(Proxy)
	if err != nil {
		return nil, err
	}
	// 判断是否使用socker5代理协议
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New("只支持socks5")
	}
	var auth proxy.Auth
	var dailer proxy.Dialer
	if u.User.String() != "" {
		auth = proxy.Auth{}
		auth.User = u.User.Username()
		password, _ := u.User.Password()
		auth.Password = password
		dailer, err = proxy.SOCKS5("tcp", u.Host, &auth, forward)
	} else {
		dailer, err = proxy.SOCKS5("tcp", u.Host, nil, forward)
	}

	if err != nil {
		return nil, err
	}
	return dailer, nil
}

// 获取URL的协议信息
func GetProtocol(host string, Timeout int64) (protocol string) {
	protocol = "http"
	// 如果端口是80或443,跳过Protocol判断
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		return
	} else if strings.HasSuffix(host, ":443") {
		protocol = "https"
		return
	}

	// 创建tcp连接
	socksconn, err := WrapperTcpWithTimeout("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		return
	}
	// 进行连接
	conn := tls.Client(socksconn, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			defer func() {
				// 捕获异常处理
				if err := recover(); err != nil {
					fmt.Println(ERR, err)
				}
			}()
			conn.Close()
		}
	}()
	// 网络超时设置
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}
