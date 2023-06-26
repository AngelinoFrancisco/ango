#!/usr/bin/python

import json
from urllib.request import urlopen
from sys import argv, exit

_author_ = 'D4Vinci'

def check(url):
    ''' check given URL is vulnerable or not '''

    try:
        if "http" not in url: url = "http://" + url

        data = urlopen(url)
        headers = data.info()

        if not "X-Frame-Options" in headers: return True

    except: return False


def main():

    ''' Everything comes together '''
sites = str(argv[1])

status = check(sites)

if status:
    dados = [{'info':'Website is Vulnerable'},{'name':'ClickJacking'},{  'poc':'Test you site here: https://tools.nakanosec.com/cj.html'}]
     
    print(dados)
elif not status:
    print(" Website is not vulnerable!")
else: print('Every single thing is crashed, Python got mad, dude wtf you just did?')

if __name__ == '_main_': main()
