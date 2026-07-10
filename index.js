const express = require('express');
const whois = require('whois');
const app = express();

const port = process.env.PORT || 10000;

// Gelen JSON verilerini okuyabilmek için
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1. RENDER'IN BEKLEDİĞİ KRİTİK ANA SAYFA (HTML Arayüzü Burada)
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>HostLook-up</title>
        <style>
            body { background-color: #121212; color: #ffffff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { text-align: center; border: 1px solid #333; padding: 30px; border-radius: 8px; background: #1e1e1e; box-shadow: 0 4px 10px rgba(0,0,0,0.5); }
            input { padding: 10px; width: 250px; border-radius: 4px; border: 1px solid #444; background: #2a2a2a; color: white; margin-right: 10px; }
            button { padding: 10px 20px; border: none; border-radius: 4px; background: #007bff; color: white; cursor: pointer; }
            button:hover { background: #0056b3; }
            pre { text-align: left; background: #2d2d2d; padding: 15px; border-radius: 4px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>HostLook-up Sunucu Sorgulama</h2>
            <input type="text" id="domain" placeholder="Örn: google.com">
            <button onclick="sorgula()">Sorgula</button>
            <pre id="output">Sonuçlar burada görünecek...</pre>
        </div>
        <script>
            async function sorgula() {
                const domain = document.getElementById('domain').value;
                const output = document.getElementById('output');
                if(!domain) return alert('Lütfen bir domain girin!');
                output.innerText = 'Sorgulanıyor...';
                try {
                    const res = await fetch('/api/lookup?domain=' + domain);
                    const data = await res.json();
                    output.innerText = data.result || 'Sonuç bulunamadı.';
                } catch(err) {
                    output.innerText = 'Hata oluştu!';
                }
            }
        </script>
    </body>
    </html>
    `);
});

// 2. SORGULAMA YAPACAK API ROTASI
app.get('/api/lookup', (req, res) => {
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: 'Domain parametresi eksik' });
    }
    
    whois.lookup(domain, (err, data) => {
        if (err) {
            return res.json({ result: 'Sorgulama hatası: ' + err.message });
        }
        res.json({ result: data });
    });
});

// Sunucuyu dış dünyaya (0.0.0.0) açıyoruz
app.listen(port, '0.0.0.0', () => {
    console.log(`Sunucu ${port} portunda kesin olarak yayında.`);
});
