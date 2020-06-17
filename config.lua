RulePath = "/usr/local/nginx/conf/waf/wafconf/"
attacklog = "off"
logdir = "/usr/local/nginx/logs/hack/"
UrlDeny="on"
Redirect="on"
CookieMatch="on"
PostMatch="on" 
whiteModule="off"
whiteHostModule="off"
black_fileExt={"php","jsp"}
ipWhitelist={"127.0.0.1","172.16.1.0-172.16.1.255"}
ipBlocklist={"1.0.0.1","2.0.0.0-2.0.0.255"}
hostWhiteList = {"blog.whsir.com","down.whsir.com"}
CCDeny="off"
CCrate="100/60"
html=[[
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title></title>
<body bgcolor="white">
<center><h1>503 Service Temporarily Unavailable</h1></center>
<hr><center>nginx</center>
</body>
</html>
]]

