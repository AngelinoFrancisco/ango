# Nuclei And Subfinder API
Web API for nuclei and subfinder will help you automate your entire security testing workflow since you can host it anywhere and make it accessible for your other applications.

# How to install?

1. Install the requirements with `pip install -r requirements.txt`
2. Launch it with uvicorn `uvicorn app:app --host 0.0.0.0 --port 1010 --timeout-keep-alive 1000 --workers 5` (change this as you require)

# Usage

To get subdomain results: `http://127.0.0.1/api/scanner1/hackerone.com`

![image](https://user-images.githubusercontent.com/97327489/189568953-12b5af33-19ce-489d-817e-ee79191e54bb.png)


To get nuclei results (WITHOUT AUTOSCAN): `http://127.0.0.1/api/scanner2/nuclei?target_name=itel.gov.ao&autoscan=false&tags=low,medium,high,critical`

![image](https://user-images.githubusercontent.com/97327489/189568842-52aee7f9-dd85-421e-9fca-5f2a384d913e.png)


To get nuclei results (WITH AUTOSCAN): `http://127.0.0.1/api/scanner2/nuclei?target_name=https://jubaeralnazi.com&autoscan=true`

# Issues

Uncomment the local environment portion if you already have go installed and comment out the previous one

![image](https://user-images.githubusercontent.com/97327489/189793211-2fcd3a7f-e012-4b62-9056-1c6ffe578f09.png)

If you face any other issues please create a new issue [here](https://github.com/h33tlit/Nuclei-and-Subfinder-API/issues)
