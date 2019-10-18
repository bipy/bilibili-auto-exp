import random
import asyncio
import requests
import time
import hashlib
import json
import rsa
import base64
import re
import datetime
import getpass
from urllib import parse


def CurrentTime():
    currenttime = str(int(time.mktime(datetime.datetime.now().timetuple())))
    return currenttime

class login():

    try:
        with open("config.json", "r") as conf:
            d = json.load(conf)
            if d["username"] != "null" and d["password"] != "null":
                print("读取本地配置")
                print("WARNING: 非私人电脑请不要使用本地模式")
                username = d["username"]
                password = d["password"]
            else:
                raise FileNotFoundError

    except KeyError:
        flag = input("配置文件错误,是否重置 (y/n)")
        if flag == 'y':
            reset = {"username": "null", "password": "null"}
            with open("config.json", "w") as conf:
                json.dump(reset, conf)
        exit()

    except FileNotFoundError:
        username = input("请输入用户名：")
        password = getpass.getpass("请输入密码：（直接输入，无显示）")

    cookies = ""
    headers = {
        "Host": "api.bilibili.com",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Cookie": cookies
    }
    csrf = ""
    uid = ""
    access_key = ""




    async def calc_sign(self, str):
        str = str + "560c52ccd288fed045859ed18bffd973"
        hash = hashlib.md5()
        hash.update(str.encode('utf-8'))
        sign = hash.hexdigest()
        return sign

    async def get_pwd(self, username, password):
        url = 'https://passport.bilibili.com/api/oauth2/getKey'
        temp_params = 'appkey=1d8b6e7d45233436'
        sign = await self.calc_sign(temp_params)
        params = {'appkey': '1d8b6e7d45233436', 'sign': sign}
        response = requests.post(url, data=params)
        value = response.json()['data']
        key = value['key']
        Hash = str(value['hash'])
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(key.encode())
        password = base64.b64encode(rsa.encrypt(
            (Hash + password).encode('utf-8'), pubkey))
        password = parse.quote_plus(password)
        username = parse.quote_plus(username)
        return username, password

    async def login(self):
        url = "https://passport.bilibili.com/api/v2/oauth2/login"
        user, pwd = await self.get_pwd(login.username, login.password)
        temp_params = 'appkey=1d8b6e7d45233436&password=' + pwd + '&username=' + user
        sign = await self.calc_sign(temp_params)
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        payload = temp_params + "&sign=" + sign
        response = requests.post(url, data=payload, headers=headers)
        try:
            cookie = (response.json()['data']['cookie_info']['cookies'])
            cookie_format = ""
            for i in range(0, len(cookie)):
                cookie_format = cookie_format + \
                                cookie[i]['name'] + "=" + cookie[i]['value'] + ";"
            s1 = re.findall(r'bili_jct=(\S+)', cookie_format, re.M)
            s2 = re.findall(r'DedeUserID=(\S+)', cookie_format, re.M)
            login.cookies = cookie_format
            login.headers = {
                "Host": "api.bilibili.com",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Cookie": login.cookies
            }
            login.csrf = (s1[0]).split(";")[0]
            login.uid = (s2[0].split(";")[0])
            login.access_key = response.json()['data']['token_info']['access_token']
            print("登录成功")
        except:
            print("登录失败，回显为:", response.json())
            exit()


class judge(login):

    video_list = []

    def randomint(self):
        return ''.join(str(random.choice(range(10))) for _ in range(17))

    def CurrentTime(self):
        millis = int((time.time() * 1000))
        return str(millis)

    async def query_reward(self):
        url = "https://account.bilibili.com/home/reward"
        headers = {
            "Referer": "https://account.bilibili.com/account/home",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36",
            "Cookie": login.cookies
        }
        response = requests.get(url, headers=headers)
        iflogin = response.json()['data']['login']
        ifwatch_av = response.json()['data']['watch_av']
        ifshare_av = response.json()['data']['share_av']
        ifgive_coin = response.json()['data']['coins_av']
        return [iflogin, ifwatch_av, ifshare_av, int(ifgive_coin)]

    async def get_attention(self):
        attention_list = []
        url = "https://api.bilibili.com/x/relation/followings?vmid=" + \
              str(login.uid) + "&ps=50&order=desc"
        headers = {
            "Host": "api.bilibili.com",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Cookie": login.cookies
        }
        response = requests.get(url, headers=headers)
        checklen = len(response.json()['data']['list'])
        for i in range(0, checklen if checklen < 20 else 20):
            uids = (response.json()['data']['list'][i]['mid'])
            attention_list.append(uids)
        return attention_list

    async def getsubmit_video(self):
        attention_list = await self.get_attention()
        judge.video_list = []
        for mid in attention_list:
            url = "https://space.bilibili.com/ajax/member/getSubmitVideos?mid=" + \
                  str(mid) + "&pagesize=100&tid=0"
            response = requests.get(url)
            datalen = len(response.json()['data']['vlist'])
            for i in range(0, datalen if datalen < 10 else 10):
                aid = response.json()['data']['vlist'][i]['aid']
                judge.video_list.append(aid)

    async def init_video_list(self):
        while 1:
            print("获取关注列表...")
            await self.getsubmit_video()
            if judge.video_list is None:
                print("获取关注列表出错")
            else:
                print("获取关注列表成功")
                break


    async def givecoin(self):
        url = "https://api.bilibili.com/x/web-interface/coin/add"
        aid = self.video_list[random.randint(0, len(self.video_list))]
        data = {
            "aid": aid,
            "multiply": "1",
            "cross_domain": "true",
            "csrf": login.csrf
        }
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36",
            "Referer": "https://www.bilibili.com/video/av" + str(aid),
            "Origin": "https://www.bilibili.com",
            "Host": "api.bilibili.com",
            "Cookie": login.cookies
        }
        response = requests.post(url, data=data, headers=headers)
        print("投币 * 1")
        print("coin_task:", response.text)

        if response.json()['code'] != 0:
            await self.givecoin()
        await asyncio.sleep(2)

    async def get_cid(self, aid):
        url = "https://www.bilibili.com/widget/getPageList?aid=" + str(aid)
        response = requests.get(url)
        cid = response.json()[0]['cid']
        return cid

    async def share(self):
        aid = self.video_list[random.randint(0, len(self.video_list))]
        url1 = "https://app.bilibili.com/x/v2/view/share/add"
        headers = {
            "User-Agent": "Mozilla/5.0 BiliDroid/5.26.3 (bbcallen@gmail.com)",
            "Host": "app.bilibili.com",
            "Cookie": "sid=8wfvu7i7"
        }
        ts = CurrentTime()
        temp_params = "access_key=" + login.access_key + "&aid=" + \
                      str(
                          aid) + "&appkey=1d8b6e7d45233436&build=5260003&from=7&mobi_app=android&platform=android&ts=" + str(
            ts)
        sign = await self.calc_sign(temp_params)
        data = {
            "access_key": login.access_key,
            "aid": aid,
            "appkey": "1d8b6e7d45233436",
            "build": "5260003",
            "from": "7",
            "mobi_app": "android",
            "platform": "android",
            "ts": ts,
            "sign": sign
        }
        response = requests.post(url1, headers=headers, data=data)
        print("分享视频:", response.json())

    async def watch_av(self, aid, cid):
        url = "https://api.bilibili.com/x/report/web/heartbeat"
        headers = {
            "Host": "api.bilibili.com",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36",
            "Referer": "https://www.bilibili.com/video/av" + str(aid),
            "Cookie": login.cookies
        }
        data = {
            "aid": aid,
            "cid": cid,
            "mid": login.uid,
            "csrf": login.csrf,
            "played_time": "0",
            "realtime": "0",
            "start_ts": self.CurrentTime(),
            "type": "3",
            "dt": "2",
            "play_type": "1"
        }

        response = requests.post(url, headers=headers, data=data)

        print("watch_Av_state:", response.text)

    async def coin_run(self):
        try:
            print("开始投币...")
            i = await self.query_reward()
            coin_exp = i[3]
            while coin_exp < 50:
                await self.givecoin()
                coin_exp = coin_exp + 10
            if coin_exp == 50:
                print("投币任务完成")
        except Exception as e:
            print("coin_run出错")
            print(e)

    async def share_run(self):
        try:
            print("开始分享视频...")
            await self.share()
            print("分享任务完成")
        except Exception as e:
            print("share_run出错")
            print(e)

    async def watch_run(self):
        try:
            print("开始观看视频...")
            aid = self.video_list[random.randint(0, len(self.video_list))]
            cid = await self.get_cid(aid)
            await self.watch_av(aid, cid)
            print("观看视频完成")
        except Exception as e:
            print("watch_run出错")
            print(e)

    async def check(self):
        try:
            i = await self.query_reward()
            print("-" * 50 + "今日经验完成情况统计" + "-" * 50)
            print("每日登录 完成" if i[0] else "每日登录 未完成")
            print("观看视频 完成" if i[1] else "观看视频 未完成")
            print("分享 完成" if i[2] else "分享 未完成")
            print("投币 完成" if i[3] == 50 else ("投币 " + i[3] + "/50"))
            print("-" * 120)

        except Exception as e:
            print("check出错")
            print(e)


loop = asyncio.get_event_loop()


task1 = [
    judge().login()
]

task2 = [
    judge().init_video_list()
]

task3 = [
    judge().coin_run(),
    judge().share_run(),
    judge().watch_run()
]

task4 = [
    judge().check()
]
loop.run_until_complete(asyncio.wait(task1))

loop.run_until_complete(asyncio.wait(task2))

loop.run_until_complete(asyncio.wait(task3))

loop.run_until_complete(asyncio.wait(task4))
