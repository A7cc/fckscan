package fckscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// 获取title
// Todo:解决乱码问题
func getTitle(resData resDataType) (title string) {
	// 使用正则匹配
	titletmp := reTitle.FindSubmatch([]byte(resData.Body))
	if len(titletmp) > 1 {
		title = string(titletmp[1])
		title = strings.TrimSpace(title)
		title = strings.Replace(title, "\n", "", -1)
		title = strings.Replace(title, "\r", "", -1)
		title = strings.Replace(title, "&nbsp;", " ", -1)
		if len(title) > 100 {
			title = title[:100]
		}
	}
	if title == "" {
		title = "None"
	}
	return
}

// // 获取icon，不好获取
// func getIcon(body []byte) (icon string) {
// 	// 使用正则匹配
// 	icontmp := reIcon.FindSubmatch(body)
// 	if len(icontmp) > 1 {
// 		icon = string(icontmp[1])
// 	}
// 	if icon == "" {
// 		icon = "None"
// 	}
// 	return
// }
// 获取内置指纹库
func getFinger(resData resDataType) (finger []string) {
	var ok bool
	for _, rule := range ruleDatas {
		// 根据类型第二检测项
		switch rule.Type {
		case "code", "body":
			ok, _ = regexp.MatchString(rule.Rule, resData.Body)
		case "headers":
			ok, _ = regexp.MatchString("(?i)"+rule.Rule, resData.Header)
		default:
			ok, _ = regexp.MatchString("(?i)"+rule.Rule, resData.Header)
		}
		if ok {
			finger = append(finger, rule.Name)
		}
	}
	// 判断是否为空
	if finger == nil {
		finger = append(finger, RED+"None"+END)
	}
	// TODO:图片的md5识别
	// 去重返回
	return RemoveDuplicate(finger)
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
	_, err = fl.Write(text)
	fl.Close()
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
	// 创建一个Msg
	var msg dns.Msg
	// 调用fqdn将域转换为可以与DNS服务交换的FQDN
	fqdn := dns.Fqdn(domainname)
	// 设置查询A记录
	msg.SetQuestion(fqdn, dns.TypeA)
	// 将消息发送到DNS服务器
	in, err := dns.Exchange(&msg, dnsserver+":53")
	if err != nil {
		return nil, err
	}
	// 如果长度小于1 则说明没有记录
	if len(in.Answer) < 1 {
		return nil, errors.New("no records")
	}
	// 循环输出
	for _, answer := range in.Answer {
		// 通过断言判断A记录获取A记录
		if res, ok := answer.(*dns.A); ok {
			addrs = append(addrs, res.A.String())
		}
	}
	return
}
