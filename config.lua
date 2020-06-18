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

whiteModule="on"
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
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>网站防火墙</title>
<style>
p {
        line-height:20px;
}
ul{ list-style-type:none;}
li{ list-style-type:none;}
</style>
</head>

<body style=" padding:0; margin:0; font:14px/1.5 Microsoft Yahei, 宋体,sans-serif; color:#555;">

 <div style="margin: 0 auto; width:1000px; padding-top:70px; overflow:hidden;">
  
        <div style="margin: 0 auto; width:1000px; padding-top:70px; overflow:hidden;">
        <div style="margin: 0 auto; width:600px; padding-top:70px; overflow:hidden;">
  <div style="width:600px; float:left;">
    <div style=" height:40px; line-height:40px; color:#fff; font-size:16px; overflow:hidden; background:#6bb3f6; padding-left:20px;">网站防火墙 </div>
    <div style="border:1px dashed #cdcece; border-top:none; font-size:14px; background:#fff; color:#555; line-height:24px; height:220px; padding:20px 20px 0 20px; overflow-y:auto;background:#f3f7f9;">
      <p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600; color:#fc4f03;">您的请求带有不合法参数，已被网站管理员设置拦截！</span></p>
<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">可能原因：您提交的内容包含危险的攻击请求</p>
<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:1; text-indent:0px;">如何解决：</p>
<ul style="margin-top: 0px; margin-bottom: 0px; margin-left: 0px; margin-right: 0px; -qt-list-indent: 1;"><li style=" margin-top:12px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-in
dent:0; text-indent:0px;">1）检查提交内容；</li>
<li style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">2）如网站托管，请联系空间提供商；</li>
<li style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">3）普通网站访客，请联系网站管理员；</li></ul>
    </div>
  </div>
</div> </div> </div>
</body></html>
]]


