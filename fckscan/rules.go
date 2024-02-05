package fckscan

// 规则
var ruleDatas = []ruleData{
	{
		// 其他指纹
		Name: `Other`,
		Rules: []ruleType{
			{
				Version: "Phpinfo",
				Level:   1,
				Path:    []string{"/"},
				Body:    `phpinfo.+?PHP Version`,
			}, {
				Version: "登录表单",
				Level:   1,
				Path:    []string{"/"},
				Body:    `<input[^>]*?type="password"`,
			}, {
				Version: "UploadFile",
				Level:   1,
				Path:    []string{"/"},
				Body:    `(<input[^>]*?type="file")`,
			}, {
				Version: "Index of /",
				Level:   1,
				Path:    []string{"/"},
				Body:    `(<title>Index of /</title>.*?Index of /)|(<h1>Index of /</h1>)`,
			}, {
				Version:   "LANMP-Default-Page",
				Level:     1,
				Path:      []string{`/`, `/images/poweredby.png`},
				Body:      `(<strong>恭喜.+?http://www.wdlinux.cn/images/lnamp.gif)|(<title>LANMP.+?phpinfo信息)`,
				Header:    `Server:.+?CentOS`,
				Icon_hash: `(1546895308)`,
			}, {
				Version:   "宝塔面板-BT",
				Level:     1,
				Path:      []string{`/`, `/login`, `/favicon.ico`},
				Body:      `(网站防火墙.+?您的请求带有不合法参数，已被网站管理员设置拦截)|(扫码登录更安全.+?宝塔Linux面板.+?app.bt.cn/static/app.png)|(入口校验失败.+?请使用正确的入口登录面板.+?关闭安全入口)`,
				Header:    ``,
				Icon_hash: `(-386189083)`,
			},
		},
	}, {
		// 攻击工具
		Name: `Attack`,
		Rules: []ruleType{
			{
				Version: "NPS",
				Level:   1,
				Path:    []string{"/", "/login/index"},
				Body:    `(<title>nps.+?404 not found,power by <a href=".+?ehang.io/nps")|(href="https://ehang.io/nps".+?/login/verify)`,
			}, {
				Version: "ARL(资产灯塔系统)",
				Level:   1,
				Path:    []string{"/", "/login"},
				Body:    `资产灯塔系统`,
			}, {
				Version: "AWVS",
				Level:   1,
				Path:    []string{"/", "/#/user/login"},
				Body:    `<title>Acunetix</title>`,
			}, {
				Version: "LangSrcCurise资产监控系统",
				Level:   1,
				Path:    []string{"/", "/#/user/login"},
				Body:    `LangSrc`,
			}, {
				Version: "Manjusaka牛屎花C2管理",
				Level:   1,
				Path:    []string{"/", "/#/user/login"},
				Body:    `Manjusaka`,
			}, {
				Version: "Medusa",
				Level:   1,
				Path:    []string{"/", "/#/user/login"},
				Body:    `Medusa doesn't work properly without JavaScript>`,
			}, {
				Version: "Nemo自动化信息收集",
				Level:   1,
				Path:    []string{"/"},
				Body:    `Nemo`,
			}, {
				Version: "Nessus漏洞扫描器",
				Level:   1,
				Path:    []string{"/", "/#/user/login"},
				Body:    `Nessus`,
			}, {
				Version: "NextScan黑盒扫描",
				Level:   1,
				Path:    []string{"/"},
				Body:    `NextScan`,
			}, {
				Version: "GPT",
				Level:   1,
				Path:    []string{"/"},
				Body:    `ChatGPT Next Web`,
			}, {
				Version: "大宝剑",
				Level:   1,
				Path:    []string{"/", "/auth/login"},
				Body:    `大宝剑-实战化攻防对抗系统`,
			}, {
				Version: "H(资产收集)",
				Level:   1,
				Path:    []string{"/", "/login"},
				Body:    `Flask Datta Able`,
			}, {
				Version: "临兵(漏扫)",
				Level:   1,
				Path:    []string{"/", "/#/login?redirect=%2Fdashboard"},
				Body:    `临兵`,
			}, {
				Version: "Viper",
				Level:   1,
				Path:    []string{"/", "/#/user/login"},
				Body:    `VIPER`,
			},
		},
	}, {
		// 语言指纹
		Name: "Language",
		Rules: []ruleType{
			{
				Version: "php",
				Level:   1,
				Path:    []string{"/"},
				Header:  "(X-Powered-By:.+?PHP)|(Cookie:.+?PHPSSIONID=)",
				Body:    "<a[^>]*?href=('|)[^http].*?\\.php(\\?|\\1)",
			}, {
				Version: "asp",
				Level:   1,
				Path:    []string{"/"},
				Header:  "(Cookie:.+?ASPSESSION=)",
				Body:    "<a[^>]*?href=('|)[^http].*?\\.asp(\\?|\\1)",
			}, {
				Version: "aspx",
				Level:   1,
				Path:    []string{"/"},
				Header:  "(X-AspNet-Version:)|(Cookie:.+?ASP.NET_SessionId=)|(X-Powered-By: ASP.NET)",
				Body:    "(<a[^>]*?href=('|)[^http].*?\\.aspx(\\?|\\1))|(<input[^>]+name=\\\"__VIEWSTATE)",
			}, {
				Version: "jsp",
				Level:   1,
				Path:    []string{"/"},
				Header:  "(Cookie:.+?JSESSIONID=)",
				Body:    "<a[^>]*?href=('|)[^http].*?\\.jsp(\\?|\\1)",
			},
		},
	}, {
		// 系统指纹
		Name: "OS",
		Rules: []ruleType{
			{
				Version: "Ubuntu",
				Level:   1,
				Path:    []string{`/`},
				Header:  `Server:.+?Ubuntu`,
			}, {
				Version: "Windows",
				Level:   1,
				Path:    []string{`/`},
				Header:  `Win`,
			}, {
				Version:   "CentOS",
				Level:     1,
				Path:      []string{`/`, `/images/poweredby.png`},
				Body:      `(Testing 123..+?href="http://centos.org")`,
				Header:    `Server:.+?CentOS`,
				Icon_hash: `(1546895308)`,
			},
		},
	}, {
		// 中间件指纹
		Name: "Middleware",
		Rules: []ruleType{
			{
				Version: "Nginx",
				Level:   2,
				Path:    []string{`/`},
				Body:    `Welcome to nginx.*using nginx`,
				Header:  `Server:.+?nginx`,
			}, {
				Version: "Apache",
				Level:   2,
				Path:    []string{`/`},
				Header:  `Server:.+?Apache`,
			}, {
				Version:   "IIS",
				Level:     2,
				Path:      []string{`/`, `/welcome.png`},
				Header:    `Server.+?Microsoft-IIS`,
				Icon_hash: "(-1293473771)",
			}, {
				Version:   "JBoss",
				Level:     2,
				Path:      []string{`/`, `/jboss.css`, `/logo.gif`, `/detestmo_ok`},
				Header:    `(X-Powered-By:.+?JBoss)|(Server:.+?JBoss)`,
				Body:      `(background-image: url."youcandoit.jpg")|(JBoss Web)|(<title>Welcome to JBoss AS.+?Application Server)`,
				Icon_hash: `(-1897272751|-656811182)`,
			}, {
				Version:   "Tomcat",
				Level:     2,
				Path:      []string{`/`, `/manager/status`, `/manager/html`, `/tomcat.css`, `/favicon.ico`, `/tomcat.png`, `/detestmo_ok`},
				Body:      `(<title>Apache Tomcat/.*?</title>|HTTP Status 404 - |Unless required by applicable law or agreed to in writing, software|role rolename="manager-gui")`,
				Header:    `(Server:.+?Tomcat)|(WWW-Authenticate:.+?Tomcat Manager)`,
				Icon_hash: "(-297069493|1944594322)",
			}, {
				Version:   "Weblogic",
				Level:     2,
				Path:      []string{`/`, `/console/css/login.css`, `/console/login/LoginForm.jsp`, `/console/framework/skins/wlsconsole/images/pageIdle.gif`, `/console/login/LoginForm.jsp`, `/detestmo_ok`},
				Header:    `(X-Powered-By:.+?Servlet.+?JSP)|(Server:.+?Weblogic)`,
				Body:      `(WebLogic Server)|(/images/Login_GC_LoginPage_Bg.gif)|(Error 404--Not Found.*<i>Hypertext Transfer Protocol)`,
				Icon_hash: `(891117163)`,
			}, {
				Version: "Jetty",
				Level:   2,
				Path:    []string{`/`},
				Header:  `Server.+?Jetty`,
			}, {
				Version: "IBM-WebSphere",
				Level:   2,
				Path:    []string{`/`},
				Header:  `WebSphere Application Server`,
			}, {
				Version:   "Glassfish",
				Level:     2,
				Path:      []string{`/`, `/resource/js/cj.js`, `/theme/com/sun/webui/jsf/suntheme/images/login/gradlogtop.jpg`},
				Header:    `Server:.+?GlassFish Server`,
				Body:      `(glassfish.dev.java.net.*See the)`,
				Icon_hash: `(1731145522)`,
			}, {
				Version: "Resin",
				Level:   2,
				Path:    []string{`/`},
				Header:  `Server:.+?Resin`,
			}, {
				Version: "Tengine",
				Level:   2,
				Path:    []string{`/`},
			},
		},
	}, {
		// web应用框架
		Name: "WebFramework",
		Rules: []ruleType{
			{
				Version:   "ActiveMQ",
				Level:     3,
				Path:      []string{`/`, `/favicon.ico`, `/images/activemq-logo.png`, `/images/asf-logo.png`, `/styles/site.css`},
				Body:      `(id="activemq_logo".*">ActiveMQ)|(<h2>Welcome to the Apache ActiveMQ!</h2>)|(Manage ActiveMQ broker)|(activemq_logo.*?/images/activemq-logo.png)`,
				Icon_hash: `(1766699363|-78120454|-1227004020)`,
			}, {
				Version:   "Spring",
				Level:     3,
				Path:      []string{`/`, `/favicon.ico`, `/detestmo_ok`},
				Body:      `(Whitelabel Error Page.+?mapping for /error)`,
				Icon_hash: `(116323821)`,
			}, {
				Version: "SpringBoot",
				Level:   3,
				Path:    []string{`/`},
				Header:  `(Www-Authenticate:.+?spring-boot-application)|(X-Application-Context:.+?spring-boot)`,
			}, {
				Version: "Spring-Security",
				Level:   3,
				Path:    []string{`/`},
				Header:  `(Www-Authenticate:.+?Spring Security Application)`,
			}, {
				Version: "Shiro",
				Level:   3,
				Path:    []string{`/`},
				Header:  `(Cookie:.+?=deleteMe)|(Cookie:.+?rememberMe=)`,
			}, {
				Version:   "Solr",
				Level:     3,
				Path:      []string{`/`, `/solr`, `/solr/admin/cores?wt=json&indexInfo=false`, `/solr/img/favicon.ico`, `/favicon.ico`},
				Body:      `((<title>Solr Admin)|(ng-app="solrAdminApp").+?SolrCore Initialization Failures)|("responseHeader":.+?"initFailures":)`,
				Icon_hash: `(850443942|-629047854)`,
			},
		},
	}, {
		// cms框架
		Name: "Cms",
		Rules: []ruleType{
			{
				Version:   "Discuz",
				Level:     3,
				Path:      []string{`/`, `/template/default/common/common.css`, `/robots.txt`, `/static/image/admincp/logo.gif`, `/static/image/admincp/ajax_loader.gif`, `/favicon.ico`},
				Body:      `(name="srhlocality")|(Discuz! X.+?powered by.+?<a href="http://www.discuz.net)|(content="Discuz!)|(Discuz!.+?<script src=".+?logging\.js)`,
				Icon_hash: `(-505448917|-520595642|1065978518|286869869)`,
			}, {
				Version:   "Openfire",
				Level:     3,
				Path:      []string{`/login.jsp?url=%2Findex.jsp`, `/style/global.css`, `/images/header-title_new.gif`, `/favicon.ico`},
				Body:      `(<title>Openfire 管理界面</title>.*+Openfire,)|(<title>Openfire Console Admin</title>.*+Openfire,)|(Global.*?/images/header-title_new.gif)`,
				Icon_hash: `(1211608009|1470783404)`,
			}, {
				Version:   "迅睿Xunrui",
				Level:     3,
				Path:      []string{`/`, `/img/datatable-row-openclose.png`, `/static/assets/global/css/cms.css`, `/favicon.ico`},
				Body:      `(class="menu-area menu-sticky sticky".+?alt="xunruicms")|(powered by.+?Xunruicms)|(/img/datatable-row-openclose.png.+?AEAAAAALAAAAAABAAEAAAIBRAA7)`,
				Icon_hash: `(1349060422|-381571353|-522851036)`,
			},
		},
	}, {
		// 摄像头
		Name: "Camaera",
		Rules: []ruleType{
			{
				Version:   "Hikvision",
				Level:     3,
				Path:      []string{`/`, `/doc/page/login.asp`, `/doc/css/login.css`, `/doc/images/login/login_14.png`, `/favicon.ico`},
				Icon_hash: `(999357577|-479092312)`,
				Header:    `(Server:.+?(Hikvision-Webs|DVRDVS-Webs|DNVRS-Webs|App-webs))`,
				Body:      `/images/login/login_14.png.*?/images/login/inputButton_select.png`,
			}, {
				Version:   "Cctv",
				Level:     3,
				Path:      []string{`/`, `/loginback.jpg`, `/favicon.ico`},
				Icon_hash: `(124273335|90066852)`,
				Header:    `(Server:.+?(JAWS/1.0))`,
			}, {
				Version:   "Zebra",
				Level:     3,
				Path:      []string{`/`, `/logo.png`},
				Icon_hash: `(1586631334|-543419858)`,
				Body:      `(<H1>Zebra Technologies<BR>.*?href="http[s]://www.zebra.com")`,
			}, {
				Version:   "Routeros",
				Level:     3,
				Path:      []string{`/`, `/mikrotik_logo.png`, `/favicon.png`},
				Icon_hash: `(-1033644073|1924358485|-324970212|-1757562887)`,
				Body:      `(RouterOS v.*?&copy; .*?mikrotik)|(<title>RouterOS router configuration page</title>)`,
			}, {
				Version:   "Siemens",
				Level:     3,
				Path:      []string{`/`, `/img/logo_336699.gif`, `/layout/default/img/icon772.ico`, `/favicon.ico`},
				Body:      `(<title>SIEMENS IP-Camera</title>.+?/img/logo_336699.gif)`,
				Header:    `(Server:.+?CP243-1 IT)`,
				Icon_hash: `(2020705580|-1967699010|-336242473)`,
			}, {
				Version:   "Dahua",
				Level:     3,
				Path:      []string{`/`, `/custom_logo/web_logo.png`, `/baseProj/images/favicon.ico`, `/favicon.ico`},
				Icon_hash: `(2019488876|1653394551|396893128|833190513|-1466785234)`,
				Body:      `(<title>WEB SERVICE</title>)`,
				Header:    `Server:.+?dahua drs`,
			}, {
				Version:   "Nuuo",
				Level:     3,
				Path:      []string{`/`, `/imgt/logo_nuuo.gif`, `/imgs/n001.jpg`, `/imgt/login_all.gif`, `/js/common.js`},
				Icon_hash: `(226713501|1662192509|-783462212)`,
				Body:      `(css/text1.css.+?NUUO Inc. All rights reserved.)|(selectedItem.+?menuItemSelected)|(Network Video Recorder Login.+?yui/build/yahoo)`,
				Header:    `Server:.+?dahua drs`,
			},
		},
	}, {
		// OA
		Name: "OA",
		Rules: []ruleType{
			{
				Version:   "致远Seeyon",
				Level:     3,
				Path:      []string{`/`, `/seeyon/common/all-min.css`, `/seeyon/main/login/default/images/m3-qrcode.png`, `/seeyon/common/images/error.gif`, `/seeyon/common/images/A8/favicon.ico`, `/seeyon/common/images/A6/favicon.ico`, `/seeyon/common/skin/default4GOV/images/favicon.ico`, `/favicon.ico`},
				Body:      `(/skin/dist/images/control_icon.png.+?skin/dist/images/noData-2x.png)|(/seeyon/common/.+?seeyon/decorations/js/jquery.loginSlide.js)|(/seeyon/common/.+?/seeyon/common/js)`,
				Icon_hash: `(-1853618686|-187813927|1238198741|-271445657|598125093|-668362876|950360964)`,
			}, {
				Version:   "万户",
				Level:     3,
				Path:      []string{`/`, `/defaultroot/images/bg.png`, `/defaultroot/scripts/util/login.js`, `/defaultroot/images/noliving_middle.gif`, `/defaultroot/Logon!logon.action`, `/favicon.ico`},
				Body:      `(/defaultroot/scripts/.+?公共初始化操作)|(/Logon!getUserToken.action.+?/defaultroot/images/noliving_middle.gif)`,
				Header:    `(Set-Cookie:.+?LocLan)`,
				Icon_hash: `(-1827521324|-1452132748|-1341710500)`,
			},
		},
	}, {
		// 安全设备
		Name: "SafetyEqu",
		Rules: []ruleType{
			{
				Version:   "Ruijie",
				Level:     3,
				Path:      []string{`/`, `/luci-static/ruijie/images/favicon.ico`, `/luci-static/ruijie/imgs/ruijlogo.png`, `/luci-static/ruijie/imgs/icons.png`},
				Icon_hash: `(-399311436|-1204803846|862953025)`,
			}, {
				Version:   "NSFOCUS",
				Level:     3,
				Path:      []string{`/`, `/img/nsfocus.png`, `/favicon.ico`},
				Header:    `(Server:.+?nsfocus)`,
				Icon_hash: `(-1566499661|-1767468400)`,
			}, {
				Version:   "绿盟SAS堡垒机",
				Level:     3,
				Path:      []string{`/`, `/stylesheet/nsfocus_2012/images/logo/login_logo_sas_zh_CN.png`, `/stylesheet/nsfocus_2012/images/logo/nsfocus.png`, `/stylesheet/nsfocus_2012/login_2012.css`},
				Body:      `(NSFOCUS&nbsp;SAS.+?login_logo_sas_zh_CN.png)|(nsfocus_2012.+?/stylesheet/nsfocus_2012/images/logo/login_logo_sas_zh_CN.png)|(login_menu_3.gif.+?images/login/login_language.gif)`,
				Icon_hash: `(239820296|928670882)`,
			}, {
				Version:   "绿盟NF下一代防火墙",
				Level:     3,
				Path:      []string{`/`, `/img/login_logo_auth_zh_CN.jpg`},
				Body:      `(NSFOCUS&nbsp;NF.+?login_logo_auth_zh_CN.jpg)`,
				Icon_hash: `(-683780565)`,
			},
		},
	}, {
		// 平台
		Name: "SystemPlatform",
		Rules: []ruleType{
			{
				Version:   "wdCP-cloud-host-management-system",
				Level:     2,
				Path:      []string{`/`, `/static/images/logo.jpg`, `/templates/images/logo.jpg`, `/favicon.ico`},
				Header:    `(Set-Cookie:.+?wdcpsessionid)`,
				Body:      `(linux云主机.+?http://www.wdlinux.cn/bbs/index.php)|(http://www.wdlinux.cn/bbs/index.php.+?wdcp服务器)`,
				Icon_hash: `(255892555|1786752597|2007765300|2007765300)`,
			}, {
				Version:   "JeecgBoot",
				Level:     3,
				Path:      []string{`/`, `/cdn/font-icon/font_2316098_umqusozousr.js`, `/logo.png`, `/img/logo.b59796ea.svg`},
				Body:      `(Jeecg Boot 是中国最具影响力的.+?http://www.jeecg.com)|(JeecgBoot 企业级低代码平台.+?cdn/babel-polyfill/polyfill_7_2_5.js)|(icon-qiyeweixin1.+?document.addEventListener)`,
				Icon_hash: `(1876106653|1380908726)`,
			},
		},
	}, {
		// 组件
		Name: "Assembly",
		Rules: []ruleType{
			{
				Version: "Ueditor",
				Level:   2,
				Path:    []string{`/`},
				Body:    `(ueditor/ueditor.config.js.+?ueditor/ueditor.all)`,
			}, {
				Version:   "Esri-Arcgis",
				Level:     2,
				Path:      []string{`/`, `/favicon.ico`},
				Body:      `(css/esri/admin.css.+?esri/images/globe-bg.jpg)`,
				Icon_hash: `(229300816)`,
			}, {
				Version: "Alibaba-Druid",
				Level:   2,
				Path:    []string{`/`, `/druid`},
				Body:    `(<title>druid monitor</title>.+?click\(druid.login.lo)`,
			},
		},
	},
}
