#!/usr/bin/env python
# coding=utf-8

"""
This code refers to the modified code of mengzonefire (v1.1.8):
https://greasyfork.org/scripts/397324-%E7%A7%92%E4%BC%A0%E9%93%BE%E6%8E%A5%E6%8F%90%E5%8F%96/code/%E7%A7%92%E4%BC%A0%E9%93%BE%E6%8E%A5%E6%8F%90%E5%8F%96.user.js
"""

import sys
import re
import base64
import json
import traceback

if sys.version_info[0] >= 3:
    from functools import reduce

    def utf8_input(*args):
        return input(*args)

    base64_decodestring = lambda x: base64.decodebytes(x.encode()).decode()
    base64_encodestring = lambda x: base64.encodebytes(x.encode()).decode()
    base64_b64decode = base64.b64decode

    def console(msg, end='\n'):
        sys.stdout.write('%s%s' % (msg, end))
else:
    # reload(sys)
    # sys.setdefaultencoding('utf-8')
    output_encoding = sys.stdout.encoding
    input_encoding = sys.stdin.encoding

    print("encoding=i:%s o:%s" % (input_encoding, output_encoding))

    def utf8_input(*args):
        x = raw_input(*args)
        return x.decode(input_encoding).encode('utf-8')

    base64_decodestring = base64.decodestring
    base64_encodestring = base64.encodestring
    base64_b64decode = lambda x: bytearray(base64.b64decode(x))

    def console(msg, end='\n'):
        sys.stdout.write('%s%s' % (msg if not isinstance(msg, str) else msg.decode('utf-8').encode(output_encoding), end))


__author__ = 'MachineWu'

target_link = 1


class DuFile:
    def __init__(self):
        self.name = None
        self.size = None
        self.md5 = None
        self.md5s = None

    @classmethod
    def make(cls, name, size, md5, md5s):
        c = cls()
        c.name = name
        c.size = size
        c.md5 = md5
        c.md5s = md5s
        return c

    def to_pandownload_link(self):
        a = '%s|%s|%s|%s' % (self.name, self.size, self.md5, self.md5s)
        return 'bdpan://%s' % base64_encodestring('%s|%s|%s|%s' % (self.name, self.size, self.md5, self.md5s)).replace('\n', '')

    def to_mengji_link(self):
        return '%s#%s#%s#%s' % (self.md5.upper(), self.md5s.upper(), self.size, self.name)

    def to_pcsgo_link(self):
        return 'BaiduPCS-Go rapidupload -length=%s -md5=%s -slicemd5=%s "%s"' % (self.size, self.md5.lower(), self.md5s.lower(), self.name.replace('"', '%22'))

    def to_target_link(self):
        global target_link
        if target_link == 1:
            return self.to_pandownload_link()
        elif target_link == 2:
            return self.to_mengji_link()
        elif target_link == 3:
            return self.to_pcsgo_link()
        else:
            return 'unknown link'

    def __repr__(self):
        return 'size: %d, md5: %s, md5s: %s, name: %s' % (self.size, self.md5, self.md5s, self.name)


def analysis_pandownload(url):
    f = re.sub(r'\s', '\n', url).split('\n')
    f = map(lambda x: re.sub(r'^bdpan://', '', x, re.I), f)
    f = map(lambda x: x.strip(), f)
    f = filter(lambda x: len(x) > 0, f)
    f = map(lambda x: str(base64_decodestring(x)), f)
    f = map(lambda x: re.search(r'([\s\S]+)\|([\d]{1,20})\|([\da-f]{32})\|([\da-f]{32})', x, re.I).groups(), f)
    f = map(lambda x: DuFile.make(name=x[0], size=x[1], md5=x[2].lower(), md5s=x[3].lower()), f)
    return list(f)


def analysis_ali213(url):
    f = re.sub(r'\s', '', url)[len('BDLINK'):]
    f = bytearray(base64.b64decode(f))

    if f[0:5] != b'BDFS\x00':
        return None

    def read_number(index, size):
        return reduce(lambda s, x: (s << 8) + x, reversed(f[index: index + size]), 0)

    def read_uint(index):
        return read_number(index, 4)

    def read_ulong(index):
        return read_number(index, 8)

    def read_hex(index, size):
        return ''.join(map(lambda x: '%02x' % x, f[index: index + size]))

    def read_unicode(index, size):
        if size & 1:
            size += 1
        return json.loads('"%s"' % re.sub(r'(\w{2})(\w{2})', r'\\u\2\1', read_hex(index, size)))

    total = read_uint(5)
    ptr = 9
    ff = list()
    for _ in range(total):
        # size (8 bytes)
        # MD5 + MD5S (0x20)
        # nameSize (4 bytes)
        # Name (unicode)
        d = DuFile()
        d.size = read_ulong(ptr + 0)
        d.md5 = read_hex(ptr + 8, 0x10)
        d.md5s = read_hex(ptr + 0x18, 0x10)
        name_size = read_uint(ptr + 0x28) << 1
        ptr += 0x2C
        d.name = read_unicode(ptr, name_size)
        ptr += name_size
        ff.append(d)

    return ff


def analysis_pcsgo(url):
    f = url.split('\n')
    f = map(lambda x: x.strip(), f)
    f = filter(lambda x: len(x) > 0, f)
    f = map(lambda x: re.search(r'-length=([\d]{1,20}) -md5=([\da-f]{32}) -slicemd5=([\da-f]{32}) (?:-crc32=\d{1,20} )?"(.+)"', x, re.I).groups(), f)
    f = map(lambda x: DuFile.make(name=x[3], size=x[0], md5=x[1].lower(), md5s=x[2].lower()), f)
    return list(f)


def analysis_mengji(url):
    f = url.split('\n')
    f = map(lambda x: x.strip(), f)
    f = filter(lambda x: len(x) > 0, f)
    f = map(lambda x: re.search(r'([\dA-F]{32})#([\dA-F]{32})#([\d]{1,20})#([\s\S]+)', x, re.I).groups(), f)
    f = map(lambda x: DuFile.make(name=x[3], size=x[2], md5=x[0].lower(), md5s=x[1].lower()), f)
    return list(f)


def analysis_common_bdlink(url):
    f = url.split('\n')
    f = map(lambda x: x.strip(), f)
    f = filter(lambda x: len(x) > 0, f)
    f = map(lambda x: re.search(r'bdlink=([^&#?]*)', x, re.I).group(1), f)
    f = map(lambda x: base64_decodestring(x), f)
    f = map(lambda x: link_parser(x), f)
    ff = list()
    for x in f:
        ff.extend(x)
    return ff


def link_parser(url):
    url = url.strip()
    if re.search(r'^bdpan:', url, re.I):
        # pandownload
        return analysis_pandownload(url)
    elif re.search(r'^BDLINK', url):
        # ali213
        return analysis_ali213(url)
    elif re.search(r'^(BaiduPCS-Go|rapidupload)', url, re.I):
        # BaiduPCS-Go
        return analysis_pcsgo(url)
    elif re.search(r'^https?://.*?bdlink=', url, re.I):
        return analysis_common_bdlink(url)
    else:
        # MengJi
        return analysis_mengji(url)


def _test():
    global target_link

    test_sample = list()
    test_sample.append('bdpan://44CMMDHjgI0ucmFyfDU3NDA3MTUzNnxiNmE1NTczZjk1MTEyZWQ2NmU1NzE1ZDRlMDQ4MzIyZnxlZTAyOTJlNmY2YzUyMzA4ZGNjZTM3ZjZlNzYyMzUyMw==')
    test_sample.append("""BDLINKQkRGUwAHAAAA0/AgXQEAAABvU6INa3SryWsF1pGpw7ALjjjB7lz4B3zYkhccg7C38ToAAABXAG8AcgBsAGQALgBXAGEAcgAuAFoALgAyADAAMQAzAC4AVQBuAHIAYQB0AGUAZAAuAEMAdQB0
        AC4ANwAyADAAcAAuAEIAbAB1AFIAYQB5AC4AeAAyADYANAAuAEQAVABTAC0AVwBpAEsAaQAuAG0AawB2AO4R0tEAAAAAFRyooon5Gjpr2PNCXDDiicea/BToo7MXRzn+Xqrh9QwdAAAAdgBlAGQAZQ
        B0AHQALQBkAGUAcwBwAGkAYwBhAGIAbABlAG0AZQAyAC0ANwAyADAAcAAuAG0AawB2AIYxraEBAAAA8PUXRFc1LCIAi3+YLQ0xSqBzMBwhiwzN9Q/o7RUU2d49AAAARgBhAHMAdAAuAGEAbgBkAC4A
        RgB1AHIAaQBvAHUAcwAuADYALgAyADAAMQAzAC4ARQBYAFQARQBOAEQARQBEAC4AQgBsAHUAUgBhAHkALgA3ADIAMABwAC4ARABUAFMALgB4ADIANgA0AC0AQwBIAEQALgBtAGsAdgAwr4FAAQAAAG
        tznIezSTcggschTwyDeSpJXXOr1WTZzn1K6Byfvru3LQAAAEUAbgBkAGUAcgBzAC4ARwBhAG0AZQAuADIAMAAxADMALgBCAGwAdQBSAGEAeQAuADcAMgAwAHAALgBEAFQAUwAuAHgAMgA2ADQALQBD
        AEgARAAuAG0AawB2AC90N/wBAAAAzg+7wDIkqZ3dMofyRkiNe/HvEFRva/sn7UaMwnpEUDovAAAARABlAGEAZAAuAE0AYQBuAC4ARABvAHcAbgAuADIAMAAxADMALgAxADAAOAAwAHAALgBCAGwAdQ
        BSAGEAeQAuAHgAMgA2ADQALQBTAFAAQQBSAEsAUwAuAG0AawB2ANs0gBcBAAAAls56xu/daOjUFfYnqAPVizbpxqmp1s/7HIb2xXFohvoUAAAAZABhAGEALQBlAGwAeQBzAGkAdQBtAC0ANwAyADAA
        cAAuAG0AawB2AJrzxRcBAAAAAJ/LCuSf1sSsoG4MPpZcW/Iv+/EEwjAk7n2vqmjPfZIXAAAAYwBiAGcAYgAtAGMAbABhAHMAaAB0AGkAdABhAG4AcwA3ADIAMAAuAG0AawB2AAA=""")
    test_sample.append('3C7E037608405F71810B799EA978EA7A#E25F1F5F27E860C5C67D5589E9E3DCF9#320828643#第268个.rar')
    test_sample.append('BaiduPCS-Go rapidupload -length=504723006 -md5=e4166ab27799d640ffda920415b684ef -slicemd5=dd662581d3028842d7910d35c083e1d2 -crc32=90455140 "在地下城邂逅是否错过了什么Dungeon Machita PC版.rar"')
    test_sample.append('https://pan.baidu.com/#bdlink=MjdFRjI2RDQ5QzZFNDYyRDI0MThCMTQ0QkI1OUM1MDYjOUYyRjgwN0NERjA0MTRFRkZDOEE1OENEQURFNkQ5OTkjOTQyMTc5NDE3I0Z1cmlvbiBDaHJvbmljbGVzLnppcA==')
    test_sample.append('https://pan.baidu.com/#bdlink=YmRwYW46Ly9NVGMwT0RrM01UWTJMamQ2ZkRVM01UYzJOVGMxTkh4a01XSTROREJpTVRJd1pUVmpZemhrWWpnMU1EVTVaVFUyTkRWa09ERTNNWHhrT0RZd1l6QmlOekE0TjJFNU9UUmpaR0UwWXpFME0yWXlaVEl4TkdJek1nPT0=')
    test_sample.append('https://xxx.yyy.com/#bdlink=NzY3M0ZERTAyMkM5OEJEMEM3NzM2NzlGRTUyMEMxQzkjREQyRTFDMUM4Mzg2NEU4MDNDOUM1M0IyNzMxQkVDMkQjMTcxNTI3MjE5MiNbMjAwNDI0XVvjgYLjgYvjgbnjgYfjgZ3jgbXjgajjgaTjgYVdREzniYgK')
    test_sample.append('https://pan.baidu.com/#bdlink=YmRwYW46Ly9ZV0ZoTGpkNmZEVTJOelV5TmpJMU0zeG1ZVEppTm1NME0yWmxOak14WTJKbE9UZ3hPV1ZpT1RnMk5HSXhOV1ZpT0h3M1pqaGxOamswWkRZME5UWmxPRGxtT1RBM09ERTBOalUxWW1ZeU1UQmpNZz09CmJkcGFuOi8vWVdGaExqZDZMakF3TVh3MU1UZ3lPRFV4TVRSOE9ESmpOVFEwWlRRd05HUmhPRFJtTnpFNU4yRTVNV1V6WlRnMFpXSmxNakY4T0RRMU5qQTRNVEptTUdRMlpHRTJOMlEwTXpCaE1XSTFZVEZqWlRVMVpUVT0=')


    console('########## Test pandownload ##########')
    target_link = 1
    for k in range(len(test_sample)):
        console('====== Test sample %d result ======' % (k + 1))
        for df in map(lambda x: x.to_target_link(), link_parser(test_sample[k])):
            console(df)

    console('\n\n\n########## Test mengji ##########')
    target_link = 2
    for k in range(len(test_sample)):
        console('====== Test sample %d result ======' % (k + 1))
        for df in map(lambda x: x.to_target_link(), link_parser(test_sample[k])):
            console(df)

    console('\n\n\n########## Test PCS-Go ##########')
    target_link = 3
    for k in range(len(test_sample)):
        console('====== Test sample %d result ======' % (k + 1))
        for df in map(lambda x: x.to_target_link(), link_parser(test_sample[k])):
            console(df)

    exit(0)


if '__main__' == __name__:
    # _test()
    console(' ==========================================================================')
    console('                         度盘秒传链接格式转换器')
    console('            支持 pandownload/梦姬/PCS-Go/游侠/bdlink 链接格式')
    console('')
    console(' ** 单个游侠链接支持多行录入，需要连续按两次回车键才开始链接转换')
    console(' ** 其他链接只支持单行录入，只需要按一次回车键就开始链接转换')
    console(' ** PCS-Go格式在使用时候不要复制前缀BaiduPCS-Go，从rapidupload开始复制就行')
    console(' ** 退出请直接关闭此窗口')
    console(' ==========================================================================')
    console('')

    while True:
        console(' 目标：需要转换成什么格式？  【1】pandownload    【2】梦姬    【3】PCS-Go')
        console(' 请输入目标格式（1或2或3）：', end='')
        user_target = utf8_input()
        if user_target in ('1', '2', '3'):
            break
        console(' 输入有误！请重新输入！')

    target_link = int(user_target)
    while True:
        console('')
        user_link = ''
        while len(user_link.strip()) == 0:
            console(' 输入秒传链接：', end='')
            user_link = utf8_input('')

        if re.search(r'^\s*BDLINK', user_link):
            # only ali213 link can multiple line input
            tmp_input = list()
            while user_link != '':
                tmp_input.append(user_link)
                user_link = utf8_input('')
            user_link = ''.join(tmp_input)

        try:
            dfs = list(link_parser(user_link))
            console(' 解析到输入链接包含 %d 个文件，将生成 %d 个链接：' % (len(dfs), len(dfs)))
            for df in map(lambda x: x.to_target_link(), dfs):
                console(df)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            console(' 输入链接有误，无法解析！')
