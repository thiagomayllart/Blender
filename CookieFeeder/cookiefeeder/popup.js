document.getElementById('saveButton').addEventListener('click', () => {
    const urlPath = document.getElementById('urlPath').value;
    console.log('Save button clicked. URL Path:', urlPath);
    chrome.storage.local.set({ selectedUrlPath: urlPath }, () => {
        console.log('URL Path saved:', urlPath);
        chrome.runtime.sendMessage({ action: 'fetchAndDecryptCookies', urlPath: urlPath }, (response) => {
            if (chrome.runtime.lastError) {
                console.error('Error sending message:', chrome.runtime.lastError);
            } else {
                console.log('Message sent to background script:', response);
            }
        });
    });
});

document.addEventListener('DOMContentLoaded', () => {
    chrome.storage.local.get(['selectedUrlPath'], function(result) {
        if (result.selectedUrlPath) {
            document.getElementById('urlPath').value = result.selectedUrlPath;
        }
    });
});
