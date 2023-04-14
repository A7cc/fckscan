# 壹 简介

该工具主要是做web指纹识别和域名解析

# 贰 原理

web指纹识别就是通过web指纹库进行对比
域名解析是通过本地域名解析+dns域名解析

# 叁 使用

- 帮助`-h`

![image-20230410180949795](image/image-20230410180949795.png)

- 单url识别

![image-20230410182748465](image/image-20230410182748465.png)

- 多个url识别

![image-20230410182931617](image/image-20230410182931617.png)

- 只进行域名解析

![image-20230410183017422](image/image-20230410183017422.png)

- 添加自定义指纹

> 注意是json格式
> - name是指纹名字
> - type是识别的指纹类型,类型为body,headers
> - rule是规则

```json
[{"name":"cmsname", "type":"body", "rule":"demo1"},{"name":"cms2", "type":"headers", "rule":"demo2"}]
```

![image-20230412173154684](image/image-20230412173154684.png)

- 添加自定义dns

![image-20230412173314368](image/image-20230412173314368.png)