from fastapi import FastAPI
import os
import subprocess
import asyncio
from typing import Optional
import json
import nmap

# Author: Jubaer

app = FastAPI()

os.environ["GOPATH"] = str(os.getcwd())+"/go/bin/tools"
os.environ["GOBIN"] = str(os.getcwd())+"/go/bin"
subprocess.run(["chmod -R +x "+str(os.getcwd())+"/go/bin/go"], shell=True)

## Local environment (If you don't have go installed or showing errors then try to use this)
## subprocess.run([str(os.getcwd())+"/go/bin/go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"], shell=True)
## subprocess.run([str(os.getcwd())+"/go/bin/go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"], shell=True)

## Local environment (If you have go installed already then use this)
# subprocess.run(["go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"], shell=True)
# subprocess.run(["go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"], shell=True)


@app.get("/api/scanner1/{domain}")
async def subdomain(domain:str):
    special_characters = """"!@# $%^&*'()}{[]|\`+?_=,<>/"""
    if 'http' in domain:
        return "Error Input"
    elif len(domain) < 1:
        return "Error Input"
    elif '.' not in domain:
        return "Error Input"
    elif 'www.' in domain:
        return "Error Input! Please remove WWW"
    elif any(c in special_characters for c in domain):
        return "Error Input"

    out = await asyncio.create_subprocess_shell("/root/go/bin/subfinder -d " + str(domain),
                                                stdout=subprocess.PIPE)
    data = []
    output = await out.communicate()

    for subs in output[0].decode().split('\n'):
        if len(subs) != 0:
            data.append(subs)
    return {'result':data}


@app.get("/api/scanner2/nuclei")
async def nuclei_scanner(target_name: str, autoscan: bool, tags: Optional[str] = None):
    try:

        if autoscan == True:
            out = subprocess.Popen("/root/go/bin/nuclei -u " + str(target_name) + " -as -j", shell=True,
                                   stdout=subprocess.PIPE)
        else:
            # Change the parameters as you require
            out = subprocess.Popen("/root/go/bin/nuclei -u " + str(target_name) + " -j -s " + str(tags),
                                   shell=True, stdout=subprocess.PIPE)

        output = out.communicate()

        data = []
        for result in output[0].decode().split('\n'):
            if len(result) != 0:
                output_json = json.loads(result)
                data.append(output_json)
        return data

    except Exception as e:
        return {'message': "Error, Please try again!"}

#here you run clickjacking scanner in your website 
@app.get("/api/scanner4/{domain}")
async def click(domain:str):
    special_characters = """"!@# $%^&*'()}{[]|\`+?_=,<>/"""
    if 'http' in domain:
        return "Error Input"
    elif len(domain) < 1:
        return "Error Input"
    elif '.' not in domain:
        return "Error Input"
    elif 'www.' in domain:
        return "Error Input! Please remove WWW"
    elif any(c in special_characters for c in domain):
        return "Error Input"

    out = await asyncio.create_subprocess_shell("python3 " + str(os.getcwd()) + "/go/bin/clickjacking.py  https://" + str(domain),
                                                stdout=subprocess.PIPE)
    data = []
    output = await out.communicate()

    for subs in output[0].decode().split('\n'):
        if len(subs) != 0:
            data.append(subs)
    return {'result':data}

#INFO  Search for technologies hided 
@app.get("/api/scanner3/info")
async def info_scanner(target_name: str, autoscan: bool):
    try:

        if autoscan == True:
            out = subprocess.Popen("/root/go/bin/nuclei -u " + str(target_name) + " -s info" + " -j", shell=True,
                                   stdout=subprocess.PIPE)
        else:
            # Change the parameters as you require
            pass

        output = out.communicate()

        data = []
        for result in output[0].decode().split('\n'):
            if len(result) != 0:
                output_json = json.loads(result)
                data.append(output_json)
        return data

    except Exception as e:
        return {'message': "Error, Please try again!"}

#INFO  Search for port scan
@app.get("/api/scanner5/{domain}")
async def Ports(domain:str):
    special_characters = """"!@# $%^&*'()}{[]|\`+?_=,<>/"""
    if 'http' in domain:
        return "Error Input"
    elif len(domain) < 1:
        return "Error Input"
    elif '.' not in domain:
        return "Error Input"
    elif 'www.' in domain:
        return "Error Input! Please remove WWW"
    elif any(c in special_characters for c in domain):
        return "Error Input"

    out = nmap.PortScanner()
    dados = out.scan(str(domain))
    data = json.dumps(dados['scan'])
    
    
    return {data}

@app.get("/api/scanner6/{domain}")
async def Click(domain:str):
    special_characters = """"!@# $%^&*'()}{[]|\`+?_=,<>/"""
    if 'http' in domain:
        return "Error Input"
    elif len(domain) < 1:
        return "Error Input"
    elif '.' not in domain:
        return "Error Input"
    elif 'www.' in domain:
        return "Error Input! Please remove WWW"
    elif any(c in special_characters for c in domain):
        return "Error Input"

    import requests

    def check_clickjacking_vulnerability(url):
        headers = {"Content-Type": "application/json"}

    # Enviar requisição GET para obter os cabeçalhos do site
        response = requests.get(url, headers=headers)
    
    # Verificar se o cabeçalho X-Frame-Options está presente
        if "X-Frame-Options" in response.headers:
            x_frame_options = response.headers["X-Frame-Options"]
        
        # Verificar o valor do cabeçalho X-Frame-Options
            if x_frame_options == "DENY" or x_frame_options == "SAMEORIGIN":
                return {"vulnerable": False, "message": "Site esta protegido contra clickjacking."}
            else:
                return {"vulnerable": True, "message": "O site pode estar vulneravel ao clickjacking."}
        else:
            return {"vulnerable": True, "message": "O site pode estar vulneravel ao clickjacking. O header X-Frame-Options nao foi definido."}

        

    result = json.dumps(check_clickjacking_vulnerability('https://'+str(domain)))
    
    
    return {result}