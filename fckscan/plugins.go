package fckscan

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
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
	// 验证该域名是否为有效域名
	domain, err := url.Parse(domainname)
	if err != nil {
		return nil, err
	}
	// 反查域名
	addrs, err = net.LookupHost(domain.Hostname())
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// // 使用网络的网站测试，这个不稳定
// func net_domain(domainname string) (addrs []string, err error) {
// 	netrequ, err := http.NewRequest(http.MethodPost, "https://webscan.cc", strings.NewReader("domain="+domainname))
// 	if err != nil {
// 		return nil, err
// 	}
// 	netrequ.Header.Set("User-Agent", user_Agents[0])
// 	netrequ.Header.Set("Accept", "*/*")
// 	netrequ.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
// 	netrequ.Header.Set("Content-Type", "application/x-www-form-urlencoded")
// 	// 发请求
// 	resp, err := Client.Do(netrequ)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()
// 	// 显示响应信息
// 	body, err3 := ioutil.ReadAll(resp.Body)
// 	if err3 != nil {
// 		return nil, err
// 	}
// 	fmt.Println(string(body))
// 	renet := regexp.MustCompile(`(?ims)"><h1>(.*?)</h1>`)
// 	// 使用正则匹配
// 	nettmp := renet.FindSubmatch([]byte(body))
// 	fmt.Println(nettmp)
// 	// if len(titletmp) > 1 {
// 	// 	title = string(titletmp[1])
// 	// 	title = strings.TrimSpace(title)
// 	// 	title = strings.Replace(title, "\n", "", -1)
// 	// 	title = strings.Replace(title, "\r", "", -1)
// 	// 	title = strings.Replace(title, "&nbsp;", " ", -1)
// 	// 	if len(title) > 100 {
// 	// 		title = title[:100]
// 	// 	}
// 	// }
// 	// if title == "" {
// 	// 	title = "None"
// 	// }
// 	return

// }
