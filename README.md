[![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)
[![996.icu](https://img.shields.io/badge/link-996.icu-red.svg)](https://996.icu) 


安装配置可参考：https://blog.whsir.com/post-4141.html


ngx_lua_waf改版基于原[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)作者二次更改，代码很简单，高性能和轻量级。


增加功能如下：

1、增加黑白名单网段IP限制，能力有限，网段不能写成172.16.1.0/24，只能写成172.16.1.0-172.16.1.255了。
ipWhitelist={"127.0.0.1","172.16.1.0-172.16.1.255"}

2、增加User-Agent白名单，用来过滤蜘蛛的。
在wafconf文件夹下white-user-agent文件中添加

3、增加server_name白名单。



目前我的wlnmp一键包默认的nginx已经集成了此版本

wlnmp一键包，支持lnmp环境通过yum方式一键快速部署：https://www.wlnmp.com/


###用途：

	防止sql注入，本地包含，部分溢出，fuzzing测试，xss,SSRF等web攻击
	防止svn/备份之类文件泄漏
	防止ApacheBench之类压力测试工具的攻击
	屏蔽常见的扫描黑客工具，扫描器
	屏蔽异常的网络请求
	屏蔽图片附件类目录php执行权限
	防止webshell上传
	
###推荐安装:

推荐使用lujit2.1做lua支持

ngx_lua如果是0.9.2以上版本，建议正则过滤函数改为ngx.re.find，匹配效率会提高三倍左右。

###使用说明：

nginx安装路径假设为:/usr/local/nginx/conf/

把ngx_lua_waf下载到conf目录下,解压命名为waf

在nginx.conf的http段添加

		lua_package_path "/usr/local/nginx/conf/waf/?.lua";
        lua_shared_dict limit 10m;
        init_by_lua_file  /usr/local/nginx/conf/waf/init.lua; 
    	access_by_lua_file /usr/local/nginx/conf/waf/waf.lua;
		
配置config.lua里的waf规则目录(一般在waf/conf/目录下)

        RulePath = "/usr/local/nginx/conf/waf/wafconf/"

路径如有变动，需对应修改，然后重启nginx即可

###配置文件详细说明：

        RulePath = "/usr/local/nginx/conf/waf/wafconf/"
        --规则存放目录
        attacklog = "off"
        --是否开启攻击信息记录，需要配置logdir
        logdir = "/usr/local/nginx/logs/hack/"
        --log存储目录，该目录需要用户自己新建，切需要nginx用户的可写权限
        UrlDeny="on"
        --是否拦截url访问
        Redirect="on"
        --是否拦截后重定向
        CookieMatch = "on"
        --是否拦截cookie攻击
        postMatch = "on" 
        --是否拦截post攻击
        whiteModule = "on" 
        --是否开启URL白名单
        whiteHostModule="off"
        --是否开启主机(对应nginx里面的server_name)白名单
        black_fileExt={"php","jsp"}
        --填写可上传文件后缀类型
        ipWhitelist={"127.0.0.1","192.168.1.0-192.168.255.255"}}
        --ip白名单，多个ip用逗号分隔
        ipBlocklist={"1.0.0.1","2.0.0.0-2.0.0.255"}
        --ip黑名单，多个ip用逗号分隔
		hostWhiteList = {"blog.whsir.com","down.whsir.com"}
        --server_name白名单，多个用逗号分隔
        CCDeny="on"
        --是否开启拦截cc攻击(需要nginx.conf的http段增加lua_shared_dict limit 10m;)
        CCrate = "100/60"
        --设置cc攻击频率，单位为秒.
        --默认1分钟同一个IP只能请求同一个地址100次
        html=[[......]]
        --警告内容,可在中括号内自定义
        备注:不要乱动双引号，区分大小写
		
###检查规则是否生效

部署完毕可以尝试如下命令：

        curl http://xxxx/test.php?id=../etc/passwd
        返回"Please go away~~"字样，说明规则生效。
		
注意:默认，本机在白名单不过滤，可自行调整config.lua配置
