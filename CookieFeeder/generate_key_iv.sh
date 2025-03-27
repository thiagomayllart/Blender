#!/bin/bash

AES_KEY=$(openssl rand -base64 32)
echo "AES Key (Base64): $AES_KEY"

AES_IV=$(openssl rand -base64 16)
echo "AES IV (Base64): $AES_IV"
