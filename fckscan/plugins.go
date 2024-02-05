package fckscan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/spaolacci/murmur3"
)

// 域名反查
func getReDomain(host string) (addrs []string, err error) {
	// todo:需要扩展，可以加在一起
	// 验证该域名是否为有效域名
	domain, err := url.Parse(host)
	if err != nil {
		return
	}
	// fmt.Println(domain.Path)
	// fmt.Println(domain.ForceQuery)
	// fmt.Println(domain.Fragment)
	// fmt.Println(domain.Host)
	// fmt.Println(domain.Opaque)
	// fmt.Println(domain.RawFragment)
	// fmt.Println(domain.RawPath)
	// fmt.Println(domain.RawQuery)
	// fmt.Println(domain.Scheme)
	// fmt.Println(domain.User)
	// 域名反查模块
	if dnsServers != nil {
		// 进行域名反查，随机选择
		// todo:需不需要进行随机
		addrs, err = reverse_check_domain(domain.Hostname(), dnsServers[rand.Intn(len(dnsServers))])
		if err != nil {
			WarningLog(err.Error())
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
	return RemoveDuplicate(addrs), nil
}

// 获取title
func getTitle(resData resDataType) (title string) {
	// fmt.Println(string(resData.Body))
	// 使用正则匹配
	titletmp := reTitle.FindSubmatch(resData.Body)
	if len(titletmp) > 1 {
		title = string(titletmp[1])
		title = strings.TrimSpace(title)
		title = strings.Replace(title, "\n", "", -1)
		title = strings.Replace(title, "\r", "", -1)
		title = strings.Replace(title, "&nbsp;", " ", -1)
		if len(title) > 50 {
			title = title[:50]
		}
	}
	if title == "" {
		title = "None"
	}
	return
}

// icon的base64，该语法符合了fofa的哈希
func StandBase641(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}

// 计算icon的hash32值
func mmh3Hash32(raw []byte) string {
	h32 := murmur3.New32()
	h32.Write(StandBase641(raw))
	return fmt.Sprintf("%d", int32(h32.Sum32()))
}

// 获取内置指纹库
// todo:需要做一个验证了指纹后，不进行后面验证，不然流量太大了，还要通过debug设置识别到的指纹规则
func getFinger(resData resDataType) (fingers []string) {
	// 循环检测指纹的大类型
	for _, rulename := range ruleDatas {
		// 循环检测子类型
		for _, rule := range rulename.Rules {
			// 由于有些规则有path，所以设置一个tmp数据
			restmp := resData
			// 用于存储ok值
			ok := 0
			for _, path := range rule.Path {
				if ok != 0 {
					break
				}
				// 判断是否有rule.Path，防止重复访问
				if path != "/" && path != "" {
					var err error
					// 请求内容赋值
					restmp, _, err = reqUrl(resData.Url+path, Cookie, user_Agents[rand.Intn(len(user_Agents))])
					if err != nil {
						WarningLog("%s Request failed, therefore %s rule detection failed", resData.Url, rule.Version)
						continue
					}
				} else if rule.Version == "Shiro" {
					// 特例：shiro
					var err error
					cookie := "rememberMe=me"
					if Cookie != "" {
						cookie = cookie + "; " + Cookie
					}
					// 请求内容赋值
					restmp, _, err = reqUrl(resData.Url+path, cookie, user_Agents[rand.Intn(len(user_Agents))])
					if err != nil {
						WarningLog("%s Request failed, therefore %s rule detection failed", resData.Url, rule.Version)
						continue
					}
				}
				// 根据规则检测
				if rule.Body != "" {
					tmp, err := regexp.MatchString("(?ims)"+rule.Body, processBody(restmp.Body))
					// if rule.Version == "登录表单" {
					// 	fmt.Println(processBody(restmp.Body))
					// }
					// fmt.Println(processBody(restmp.Body))
					if tmp && err == nil {
						DebugLog("通过Body规则 %v 检测到主机 %v%v 存在 %v 指纹", rule.Body, resData.Url, path, rule.Version)
						ok += 1
					}
				}
				// fmt.Println(restmp.Header)
				if rule.Header != "" {
					tmp, err := regexp.MatchString("(?ims)"+rule.Header, restmp.Header)
					if tmp && err == nil {
						// fmt.Println(restmp.Header)
						DebugLog("通过Header规则 %v 检测到主机 %v%v 存在 %v 指纹", rule.Header, resData.Url, path, rule.Version)
						ok += 1
					}
				}
				if rule.Icon_hash != "" {
					// 计算哈希
					iconhash := mmh3Hash32([]byte(restmp.Body))
					tmp, err := regexp.MatchString(rule.Icon_hash, iconhash)
					if tmp && err == nil {
						// fmt.Println(iconhash)
						DebugLog("通过Icon_hash规则 %v 检测到主机 %v%v 存在 %v 指纹", rule.Icon_hash, resData.Url, path, rule.Version)
						ok += 1
					}
				}
				// 追加内容
				if ok > 0 {
					// 存放指纹
					finger := ""
					if rule.Level == 1 {
						finger = ORANGE + rulename.Name + "_" + rule.Version + END
					} else if rule.Level >= 2 {
						finger = RED + rulename.Name + "_" + rule.Version + END
					} else {
						finger = rulename.Name
					}
					fingers = append(fingers, finger)
				}
			}
		}
	}
	// 判断是否为空
	if fingers == nil {
		fingers = append(fingers, "None")
	}

	// 去重返回
	return RemoveDuplicate(fingers)
}

// 去重
func RemoveDuplicate[T any](old []T) (result []T) {
	temp := map[any]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return
}

// 读取json文件
func Readjsonfile(filename string) ([]ruleData, error) {
	// 设置json文件
	var jsonlist []ruleData
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &jsonlist)
	if err != nil {
		return nil, err
	}
	return jsonlist, nil
}

// 写入文件
func WriteFile(log string, filename string) {
	var text = []byte(log + "\n")
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("打开 %s 失败，%v\n", filename, err)
		return
	}
	defer fl.Close()
	_, err = fl.Write(text)
	if err != nil {
		fmt.Printf("写入 %s 失败，%v\n", filename, err)
	}
}

// 本地域名反查
func local_domain(domainname string) (addrs []string, err error) {
	// 反查域名
	addrs, err = net.LookupHost(domainname)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// 反查域名
func reverse_check_domain(domainname, dnsserver string) (addrs []string, err error) {
	//设置DNS服务器的地址
	resolver := &net.Resolver{
		// PreferGo控制Go的内置DNS解析程序在可用的平台上是否首选
		PreferGo: true,
		// Dial可选择指定一个备用拨号程序，供Go的内置DNS解析程序使用，以建立到DNS服务的TCP和UDP连接
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", dnsserver+":53")
		},
	}
	//解析域名
	addrs, err = resolver.LookupHost(context.Background(), domainname)
	if err != nil {
		return nil, err
	}
	return
}

// 调用系统的ping命令
func ExecCommandPing(ip string) bool {
	// ping对应主机
	var cmd *exec.Cmd
	// 判断操作系统
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", ip, "-n", "1", "-w", "1")
	case "linux":
		cmd = exec.Command("ping", ip, "-c", "1", "-w", "1")
	case "darwin":
		cmd = exec.Command("ping", ip, "-c", "1", "-W", "1")
	}
	// 判断cmd是否为空
	if cmd == nil {
		return false
	}
	// 执行cmd的命令
	err := cmd.Run()
	return err == nil
}
