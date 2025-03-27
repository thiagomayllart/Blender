chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    console.log('Content script received message:', message);
    if (message.cookies) {
        importCookies(message.url, message.cookies);
    }
});

function importCookies(url, cookies) {
    const domain = new URL(url).hostname;

    cookies.forEach(cookie => {
        const cookieDetails = {
            url: `https://${domain}`,
            name: cookie.name,
            value: cookie.value,
            domain: domain,
            path: cookie.path || '/',
            secure: cookie.secure || false,
            httpOnly: cookie.httpOnly || false,
            expirationDate: cookie.expirationDate || (Date.now() / 1000) + (60 * 60 * 24 * 365) // 1 year default
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
