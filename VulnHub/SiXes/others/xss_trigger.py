#!/usr/bin/python3
import requests
import asyncio
import sys
from pyppeteer import launch

url  = 'http://127.0.0.1/admin.php'
user = 'webmaster'
pswd = '6a1eE8X81t3uwsiKqrT5Atf38tkCS6Eh'
data = {'login': user, 'password': pswd}

response = requests.post(url=url, data=data)
cookie = response.request.headers['Cookie'].split('=')
urls = [i.strip() for i in open('/root/xss_simulator/urls.txt').readlines()]

async def main():
    browser = await launch({"executablePath":"/usr/bin/chromium-browser"}, args=['--no-sandbox'])
    page = await browser.newPage()
    for url in urls:
        await page.setCookie({'url': url, 'name': cookie[0], 'value': cookie[1]})
        await page.goto(url)
    await asyncio.sleep(10)
    await browser.close()

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
loop.close()