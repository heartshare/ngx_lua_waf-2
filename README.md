[![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)
[![996.icu](https://img.shields.io/badge/link-996.icu-red.svg)](https://996.icu) 

ngx_lua_waf改版基于原[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)作者二次更改，代码很简单，高性能和轻量级。


**欢迎所有有兴趣的同学进行协同开发，在留言处@我**
=========================================================

## 【**】正在二次开发中的功能  
1、针对疑似机器人访问行为，浮层滑块验证，不再是单纯返回403，加入可以选功能图片验证码  
2、蜘蛛验证（这个还不确定）  
3、头部字段Referer限制  
4、HTTP请求时，要求headers出现哪些字段，防护低级伪造爬虫  
5、根据连续异常响应码分布，限制IP访问（拦截黑客针对不存在的URL地址发起的大量恶意访问）  
6、支持如wordpress pingback等常见CC变种型攻击防护  
7、封禁libcurl，python脚本等构造的恶意访问  
8、可设置对某些特定URL地址(如管理员登录后台)指定只允许某些IP访问  
9、基于日志服务，提供全量访问日志的攻击比例分析  
  
  
  
## 【2020.06.22】Bug修复，适用于此日期前的所有版本 
1.自己的bug。  
* 描述：针对开启国家地域黑白名单时，出现内网或无法解析的IP采取直接放行，导致后面的规则不生效。  
解决办法：  
  规则优先级应该放在最后    
  
问题来源： https://github.com/loveshell/ngx_lua_waf/issues  
2、waf 记录日志的bug及修复 #129：
* 描述：当nginx 同一个server段的server_name 的list里有多个servername时，log函数只会匹配到第一个servername。并且，如果servername 出现通配符时，log函数会按照原样打入log。  
解决办法（采纳意见）：  
  ngx.var.server_name  
  --改为  
  ngx.var.host  
  
3、正则表达式有问题 #149  或   使用了ngx_lua_waf这个模块后，页面上传超过256M的文件，nginx会报400的错误。请问ngx_lua_waf对文件上传限制在哪儿进行修改？ #123
* 描述：POST匹配文件的表达式中表达式有误，看了很多这个项目的小伙伴后觉得还是不对 
  此处涉及多处修改和逻辑修改  
  
4、通过URL传参时容易造成CC攻击误报  
* 描述：有些架构都需要访问index.php?id=xxx,具体资源有id来指定，那么index.php这个页面容易触发cc规则访问被deny，这样会造成大量的误报，有什么办法解决这个问题吗？ #77  
解决办法：  
  生成token时引入ngx.var.request_uri而不是单纯的uri，并且使用url安全的进行encode_base64url 数据编码方式   
  
5、上传zip文件被post规则匹配到，导致403 #130  
* 描述：原因是 被 post 里面的 匹配到疑似攻击内容  
解决办法：  
  对上传文件新增独立检查开关，而不是直接关闭post检查   
  
6、发现用了waf开启Post功能，上传图片大的会上传不了，请问哪里取消图片容量限制？ #115  
* 描述：原因是应该是nginx允许上传的参数不够大  
解决办法： 
  调整您配置的两个参数，参数含义自己查，生产建议不高于100m。  
  client_body_buffer_size 5m;  
  client_max_body_size 512m;  
  
其他自己发现的bug  
7、匹配文件后缀时，采用match导致部分匹配，误拒绝POST上传  
  if ngx.re.match(ext,rule,"isjo") then  
  --改为  
  if string.lower(rule) == ext then  
  
8、上传文件时，上传js,py,html文件时日志变为cat文件，优化记录日记和错误拦截  
  log("-","file attack with ext "..ext .. " rule: " .. rule)  
  --改为  
  log("-","file attack with ext. rule: " .. rule)   
  --还有log函数，略..。  
  
**【新增功能】**  
1、post文件上传时单独对文件内容检查设置一个小开关  
2、上传文件的后缀黑名单改为允许上传的后缀白名单（因为未知的文件后缀数量太多，而且具有不确定性），并且对文件没有后缀的跳过次检查（ps你也可以强制改为必须有后缀，但感觉意义不大）  
3、对上传成功的文件和，上传失败的，单独记录日志，便于查找  
**【修改nginx配置lua环境参数】**  
    lua_package_path  "/usr/local/openresty/nginx/conf/waf/?.lua;;";  
    lua_package_cpath  "/usr/local/openresty/lualib/?.so;;";  
    lua_shared_dict urllimit 10m;  
    lua_shared_dict iplimit 10m;  
    init_by_lua_file   /usr/local/openresty/nginx/conf/waf/init.lua;  
    access_by_lua_file /usr/local/openresty/nginx/conf/waf/waf.lua;   
  
  
  
  
## 【2020.06.19】  
1、国家级别的地域限制（黑白名单）。国家代码参考[ISO_3166-2](https://en.wikipedia.org/wiki/ISO_3166-2)。"GeoLite2-City.mmdb/GeoLite2-Country.mmdb"后期请自行更新  


## 【2020.06.18】  
1、获取客户端IP，支持代理，多级代理情况下只取最后一级  
2、修改原来单一针对IP做cc检测。添加URL频率cc攻击检测，其次才是Ip 频率cc攻击检测（需要修改nginx配置，lua_shared_dict部分）  
3、优化局部变量，减少高并发时变量覆盖  
4、优化日志记录提醒  
5、优化规则执行顺序  


## 【2020.06.17】  
1、增加黑白名单IP段掩码限制方法，例如：ipWhitelist={"127.0.0.1","192.168.1.0/24"}



## 【**】增加功能如下  
1、增加黑白名单网段IP限制，例如：ipWhitelist={"127.0.0.1","172.16.1.0-172.16.1.255"}  
2、增加User-Agent白名单，用来过滤蜘蛛的。在wafconf文件夹下white-user-agent文件中添加  
3、增加server_name白名单。  




### 初始功能：

	防止sql注入，本地包含，部分溢出，fuzzing测试，xss,SSRF等web攻击
	防止svn/备份之类文件泄漏
	防止ApacheBench之类压力测试工具的攻击
	屏蔽常见的扫描黑客工具，扫描器
	屏蔽异常的网络请求
	屏蔽图片附件类目录php执行权限
	防止webshell上传
	
### 【1】环境推荐安装:  
1.1）推荐使用lujit2.1做lua支持  
1.2）ngx_lua如果是0.9.2以上版本，建议正则过滤函数改为ngx.re.find，匹配效率会提高三倍左右。  
1.3）推荐直接使用openresty部署，而不是自己手动部署nginx+lua，下面安装示例使用“openresty/1.15.8.3”  
1.4）推荐编译安装openresty时添加后端检查模块 “[nginx_upstream_check_module](https://github.com/yaoweibin/nginx_upstream_check_module)”,并添加模块参数“--with-http_geoip_module”  


### 【2】安装使用说明：  
openresty安装路径假设为: /usr/local/openresty  
2.1）下载文件：  
* 把ngx_lua_waf下载到/usr/local/openresty/nginx/conf/目录下,解压命名为waf  
* 确保lua_package_cpath配置中包含cjson.so（openrestym默认包含）  

2.1.1）安装lua 库依赖 libmaxminddb 实现对 mmdb 的高效访问  (使用yum安装的，版本较低。yum install libmaxminddb-devel -y)

    wget https://github.com/maxmind/libmaxminddb/releases/download/1.4.2/libmaxminddb-1.4.2.tar.gz
    tar -zxvf libmaxminddb-1.4.2.tar.gz
    cd libmaxminddb-1.4.2
    ./configure
    make
    make check
    sudo make install
    echo /usr/local/lib  >> /etc/ld.so.conf.d/local.conf
    sudo ldconfig  

2.2）在nginx.conf的http段添加  

    lua_package_path  "/usr/local/openresty/nginx/conf/waf/?.lua";
    lua_package_cpath  "/usr/local/openresty/lualib/?.so;;";  
    lua_shared_dict urllimit 10m;
    lua_shared_dict iplimit 10m;
    init_by_lua_file   /usr/local/openresty/nginx/conf/waf/init.lua;
    access_by_lua_file /usr/local/openresty/nginx/conf/waf/waf.lua;
		
2.3）配置config.lua里的waf规则目录

    RulePath = "/usr/local/openresty/nginx/conf/waf/wafconf/"

路径如有变动，需对应修改，然后重启nginx即可  
2.4）配置config.lua里的日志目录(该目录需要自己提前创建)  

    logdir = "/usr/local/openresty/nginx/waflogs/"

2.5）配置文件详细说明：  

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
		
### 【3】检查规则是否生效  
部署完毕可以尝试如下命令：

        curl http://xxxx/test.php?id=/etc/passwd
        返回"Please go away~~"字样，说明规则生效。
		
注意:默认，本机在白名单不过滤，可自行调整config.lua配置





## 【特别说明】  
以上代码参考以下项目：  
> https://github.com/loveshell/ngx_lua_waf  
> https://github.com/whsir/ngx_lua_waf  
> https://github.com/oneinstack/ngx_lua_waf  
> https://github.com/taihedeveloper/ngx_lua_waf  
感谢ngx_lua模块的开发者，感谢openresty的春哥！！！  


## 【其他资源说明】  
* [GeoLite2-City.mmdb/GeoLite2-Country.mmdb](https://dev.maxmind.com/geoip/geoip2/geolite2/)  
* [maxminddb.lua](https://dev.maxmind.com/geoip/geoip2/downloadable/#MaxMind_APIs)  
* [libmaxminddb](https://github.com/maxmind/libmaxminddb/releases)  
