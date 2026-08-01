
        function runCryptoDemo(algo) {
            const body = document.getElementById('demoBody');
            if (algo === 'aes') {
                body.innerHTML = `
                    <div>$ python -m nist_crypto.aes --encrypt "Confidential Payload"</div>
                    <div style="color: #4ade80; margin-top: 8px;">[+] Key (256-bit): 0f8a92b...</div>
                    <div style="color: #4ade80;">[+] IV (96-bit): a12e8b...</div>
                    <div style="color: #4ade80;">[+] Ciphertext: 8f921a4bc8712...</div>
                    <div style="color: #4ade80;">[+] AEAD Tag: e491ab20...</div>
                    <div style="color: #e2e8f0; margin-top: 8px;">[SUCCESS] AES-256-GCM Encrypted & Authenticated!</div>
                `;
            } else if (algo === 'rsa') {
                body.innerHTML = `
                    <div>$ python -m nist_crypto.rsa --sign --msg "Transaction Audit"</div>
                    <div style="color: #4ade80; margin-top: 8px;">[+] RSA Key Size: 2048 bits</div>
                    <div style="color: #4ade80;">[+] Digest Hash: SHA-256</div>
                    <div style="color: #4ade80;">[+] Signature: 7b9e10f82c...</div>
                    <div style="color: #e2e8f0; margin-top: 8px;">[SUCCESS] RSA-2048 PKCS#1 v1.5 Signature Verified!</div>
                `;
            }
        }
        document.getElementById('demoBody').innerHTML = `
            <div>
                <button class="term-btn" onclick="runCryptoDemo('aes')">Run AES-256-GCM Demo</button>
                <button class="term-btn" onclick="runCryptoDemo('rsa')">Run RSA-2048 Sign Demo</button>
            </div>
            <div id="termOutput">$ Click a demo button to execute cryptographic primitives...</div>
        `;
        