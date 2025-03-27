self.window = self;
importScripts('scripts/forge.min.js');
delete self.window;

const key = forge.util.decode64('YOUR_KEY');  
const iv = forge.util.decode64('YOUR_IV');
let lastKnownData = '';
let firstImportDone = false;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Received message:', message);
    if (message.action === 'fetchAndDecryptCookies') {
        fetchAndDecryptCookies(message.urlPath).then(() => {
            sendResponse({ status: 'Cookies fetched and decrypted' });
        }).catch(error => {
            sendResponse({ status: 'Error', message: error.message });
        });
    }
    return true; 
});

async function fetchAndDecryptCookies(urlPath) {
    console.log('Fetching encrypted cookies from:', urlPath);
    const response = await fetch(urlPath);
    if (!response.ok) {
        throw new Error(`Network response was not ok: ${response.statusText}`);
    }
    const encryptedData = await response.text();
    console.log('Encrypted data fetched:', encryptedData.substring(0, 100)); 
    const encryptedSets = encryptedData.split('\n').filter(Boolean);
    const decryptedSets = [];

    for (const set of encryptedSets) {
        if (!isBase64(set)) {
            throw new Error('Encrypted data set is not valid base64');
        }
        const encryptedArrayBuffer = base64ToArrayBuffer(set); 
        const decryptedData = decryptData(new Uint8Array(encryptedArrayBuffer));
        console.log('Decrypted Set:', decryptedData.substring(0, 100)); 
        decryptedSets.push(decryptedData);
    }

    for (const [index, data] of decryptedSets.entries()) {
        try {
            const parsedData = JSON.parse(data);
            const { url, cookies } = parsedData;
            if (Array.isArray(cookies)) {
                if (!firstImportDone) {
                    chrome.cookies.getAll({ domain: new URL(url).hostname }, function(existingCookies) {
                        let clearCookiesPromises = existingCookies.map(cookie => {
                            const cookieUrl = `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`;
                            return new Promise(resolve => {
                                chrome.cookies.remove({ url: cookieUrl, name: cookie.name }, resolve);
                            });
                        });

                        Promise.all(clearCookiesPromises).then(() => {
                            firstImportDone = true;
                            setCookies(new URL(url).origin, cookies);
                        });
                    });
                } else {
                    setCookies(new URL(url).origin, cookies);
                }
            } else {
                throw new Error(`Decrypted data does not contain an array of cookies: ${JSON.stringify(cookies)}`);
            }
        } catch (err) {
            throw new Error(`Failed to process decrypted set ${index + 1}: ${err.message}`);
        }
    }

    lastKnownData = encryptedData;
}

function setCookies(origin, cookies) {
    cookies.forEach(cookie => {
        const cookieDetails = {
            url: `https://${new URL(origin).hostname}`,
            name: cookie.name,
            value: cookie.value,
            domain: new URL(origin).hostname,
            path: cookie.path || '/',
            secure: cookie.secure || false,
            httpOnly: cookie.httpOnly || false,
            expirationDate: cookie.expirationDate || (Date.now() / 1000) + (60 * 60 * 24 * 365) 
        };

        if (cookie.name.startsWith('__Secure-')) {
            cookieDetails.secure = true;
        }
        if (cookie.name.startsWith('__Host-')) {
            cookieDetails.secure = true;
            cookieDetails.path = '/';
            delete cookieDetails.domain; 
        }

        console.log('Setting cookie with details:', cookieDetails);

        chrome.cookies.set(cookieDetails, function(newCookie) {
            if (chrome.runtime.lastError) {
                console.error(`Error setting cookie ${cookie.name}: ${chrome.runtime.lastError.message}`);
            } else {
                console.log(`Cookie ${newCookie.name} set successfully`);
            }
        });
    });
}

function decryptData(encryptedData) {
    const dataBuffer = forge.util.createBuffer(encryptedData);
    const decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({ iv: iv });
    decipher.update(dataBuffer);
    const result = decipher.finish();
    if (!result) {
        throw new Error('Failed to decrypt data');
    }
    const decrypted = decipher.output.getBytes();
    return forge.util.decodeUtf8(decrypted);
}

function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64.replace(/[\r\n]+/g, ""));
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

function isBase64(str) {
    try {
        return btoa(atob(str.replace(/[\r\n]+/g, ""))) === str.replace(/[\r\n]+/g, "");
    } catch (err) {
        return false;
    }
}

chrome.alarms.create('fetchCookies', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'fetchCookies') {
        chrome.storage.local.get(['selectedUrlPath'], function(result) {
            fetchAndCheckForChanges(result.selectedUrlPath || '');
        });
    }
});

function fetchAndCheckForChanges(urlPath) {
    fetch(urlPath)
        .then(response => {
            if (!response.ok) {
                throw new Error(`Network response was not ok: ${response.statusText}`);
            }
            return response.text();
        })
        .then(encryptedData => {
            if (encryptedData !== lastKnownData) {
                lastKnownData = encryptedData;
                fetchAndDecryptCookies(urlPath);
            }
        })
        .catch(error => {
            console.error(`Failed to fetch or check for changes: ${error.message || error}`);
        });
}
