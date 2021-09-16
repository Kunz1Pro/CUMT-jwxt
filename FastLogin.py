# -*- coding: UTF-8 -*-

import requests
import base64
import yaml
import jsFunction
from bs4 import BeautifulSoup
import time

with open('./config.yml') as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

stu_id = config['user'][0]['id']
stu_password = config['user'][1]['password']

TIME = int(round(time.time() * 1000))
URL = f'http://jwxt.cumt.edu.cn/jwglxt/xtgl/login_slogin.html?time={TIME}'


def cookie():
    return 0;


def password_encode(pwd,sessions):
    url = f'http://jwxt.cumt.edu.cn/jwglxt/xtgl/login_getPublicKey.html?time={TIME}&_={TIME-50}'
    ret = sessions.get(url)
    ret = ret.json()
    modulus = ret['modulus']
    exponent = ret['exponent']
    _modulus = base64.b64decode(modulus).hex()
    _exponent = base64.b64decode(exponent).hex()
    rsa = jsFunction.RSAKey()
    rsa.setPublic(_modulus, _exponent)
    pwd_rsa = rsa.encrypt(pwd)
    pwd_byte = bytes.fromhex(pwd_rsa)
    pwd_cry = base64.b64encode(pwd_byte).decode('utf-8')
    return pwd_cry


def get_csrftoken(sessions):
    url = f'http://jwxt.cumt.edu.cn/jwglxt/xtgl/login_slogin.html?time={TIME}'
    r = sessions.get(url)
    r.encoding = r.apparent_encoding
    soup = BeautifulSoup(r.text, 'html.parser')
    token = soup.find('input', attrs={'id': 'csrftoken'}).attrs['value']
    return token


def login():
    sessions = requests.Session()
    token = get_csrftoken(sessions)
    pwd_enc = password_encode(stu_password, sessions)
    data = {
        'csrftoken': token,
        'language':  'zh_CN',
        'yhm': stu_id,
        'mm': pwd_enc,
        'mm': pwd_enc,
        'yzm': ''
    }
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Connection': 'close',
        'Content-Length': '482',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': 'jwxt.cumt.edu.cn',
        'Origin': 'http: // jwxt.cumt.edu.cn',
        'Referer': 'http://jwxt.cumt.edu.cn/jwglxt/xtgl/login_slogin.html',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    ret = sessions.post(url=URL,headers=headers,data=data)
    print(ret.text)

if __name__ == '__main__':
   login()