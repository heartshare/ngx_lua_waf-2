[![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)
[![996.icu](https://img.shields.io/badge/link-996.icu-red.svg)](https://996.icu) 

ngx_lua_waf改版基于原[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)作者二次更改，代码很简单，高性能和轻量级。


**欢迎所有有兴趣的同学进行协同开发，在留言处@我**
=========================================================

##【**】正在二次开发中的功能

1、频繁访问时，不再是单纯返回403，加入可以选功能图片验证码


##【2020.06.18】##

1、获取客户端IP，支持代理，多级代理情况下只取最后一级

2、修改原来单一针对IP做cc检测。添加URL频率cc攻击检测，其次才是Ip 频率cc攻击检测（需要修改nginx配置，lua_shared_dict部分）

3、优化局部变量，减少高并发时变量覆盖

4、优化日志记录参时提醒

5、优化规则执行顺序



##【2020.06.17】

1、增加黑白名单IP段掩码限制方法，例如：ipWhitelist={"127.0.0.1","192.168.1.0/24"}



##【**】增加功能如下：

1、增加黑白名单网段IP限制，例如：ipWhitelist={"127.0.0.1","172.16.1.0-172.16.1.255"}

2、增加User-Agent白名单，用来过滤蜘蛛的。在wafconf文件夹下white-user-agent文件中添加

3、增加server_name白名单。




### 用途：

	防止sql注入，本地包含，部分溢出，fuzzing测试，xss,SSRF等web攻击
	防止svn/备份之类文件泄漏
	防止ApacheBench之类压力测试工具的攻击
	屏蔽常见的扫描黑客工具，扫描器
	屏蔽异常的网络请求
	屏蔽图片附件类目录php执行权限
	防止webshell上传
	
###【1】环境推荐安装:

1.1）推荐使用lujit2.1做lua支持

1.2）ngx_lua如果是0.9.2以上版本，建议正则过滤函数改为ngx.re.find，匹配效率会提高三倍左右。

1.3）推荐直接使用openresty部署，而不是自己手动部署nginx+lua，下面安装示例使用“openresty/1.15.8.3”

1.4）推荐编译安装openresty时添加后端检查模块 “[nginx_upstream_check_module](https://github.com/yaoweibin/nginx_upstream_check_module)”,并添加模块参数“--with-http_geoip_module”


###【2】安装使用说明：
openresty安装路径假设为: /usr/local/openresty

2.1）把ngx_lua_waf下载到/usr/local/openresty/nginx/conf/目录下,解压命名为waf

2.2）在nginx.conf的http段添加

    lua_package_path  "/usr/local/openresty/nginx/conf/waf/?.lua";
    lua_shared_dict urllimit 10m;
    lua_shared_dict iplimit 10m;
    init_by_lua_file   /usr/local/openresty/nginx/conf/waf/init.lua;
    access_by_lua_file /usr/local/openresty/nginx/conf/waf/waf.lua;
		
2.3）配置config.lua里的waf规则目录

    RulePath = "/usr/local/openresty/nginx/conf/waf/wafconf/"

路径如有变动，需对应修改，然后重启nginx即可
2.4）配置config.lua里的日志目录(该目录需要自己提前创建)

    logdir = "/usr/local/openresty/nginx/waflogs/"

2.5）###配置文件详细说明：

	RulePath = "/usr/local/openresty/nginx/conf/waf/wafconf/"
	attacklog = "on"
	logdir = "/usr/local/openresty/nginx/waflogs/"


	UrlDeny="on"
	--是否拦截url访问

	Redirect="on"
	--是否拦截后重定向

	CookieMatch="on"
	--是否拦截cookie攻击

	PostMatch="on"
	--是否拦截post攻击

	whiteModule="off"
	--是否开启URL白名单

	black_fileExt={"php","jsp"}
	--填写可上传文件后缀类型

    ipWhitelist={"127.0.0.1"}
    --ip白名单，多个ip用逗号分隔,
    --支持:
    --1)范围划分法 "192.168.0.70-192.168.0.99"  
    --2)掩码划分法 "192.168.0.0/24"
    ipBlocklist={"1.0.0.1"}
    --ip黑名单，多个ip用逗号分隔
    --支持:
    ----1)范围划分法 "192.168.0.70-192.168.0.99"  
    ----2)掩码划分法 "192.168.0.0/24"

    whiteHostModule="off"
    --是否开启主机(对应nginx里面的server_name)白名单
    hostWhiteList = {"blog.whsir.com"}
    --server_name白名单，多个用逗号分隔

    CCDeny="on"
    --是否开启拦截cc攻击(需要nginx.conf的http段增加lua_shared_dict limit 10m;)
    urlCCrate="100/60"
    -- ip访问特定url频率（次/秒）
    ipCCrate="500/60"
    -- 访问ip频次检测（次/秒）,该值应该是urlCCrate的5-20倍左右


	html=[[
	xxx
	]]

        --警告内容,可在中括号内自定义
        备注:不要乱动双引号，区分大小写
		
###【3】检查规则是否生效
部署完毕可以尝试如下命令：

        curl http://xxxx/test.php?id=/etc/passwd
        返回"Please go away~~"字样，说明规则生效。
		
注意:默认，本机在白名单不过滤，可自行调整config.lua配置





【特别说明】
以上代码参考以下项目：
https://github.com/loveshell/ngx_lua_waf
https://github.com/whsir/ngx_lua_waf
https://github.com/oneinstack/ngx_lua_waf
感谢ngx_lua模块的开发者，感谢openresty的春哥！！！
