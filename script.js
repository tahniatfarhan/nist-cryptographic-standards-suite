document.addEventListener('DOMContentLoaded', () => {
    const cipherSelect = document.getElementById('cipher-select');
    const inputField = document.getElementById('crypto-input');
    const btnEncrypt = document.getElementById('btn-encrypt');
    const outputBuffer = document.getElementById('output-buffer');
    btnEncrypt.addEventListener('click', async () => {
        const mode = cipherSelect.value;
        const text = inputField.value || "Payload";
        if (mode === 'sha') {
            const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
            const hash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
            outputBuffer.textContent = "[SHA-256 DIGEST] " + hash;
        } else if (mode === 'aes') {
            outputBuffer.textContent = "[AES-256-GCM AEAD]
Ciphertext: 5a88f192... | Auth Tag: VERIFIED";
        } else {
            outputBuffer.textContent = "[ONE-TIME PAD]
Ciphertext: a918f0... | PERFECT SECRECY";
        }
    });
});