const express = require('express');
const whois = require('whois');
const dns = require('dns').promises;
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Basit ve Şık Arayüz (HTML/CSS) - Doğrudan ana sayfada gösterilecek
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>HostLook-up</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-gray-100 min-h-screen flex flex-col items-center justify-center p-4">
        <div class="w-full max-w-2xl bg-gray-800 p-6 rounded-xl shadow-xl border border-gray-700">
            <h1 class="text-3xl font-bold text-center mb-2 text-blue-400">🔍 HostLook-up</h1>
            <p class="text-gray-400 text-center text-sm mb-6">Domain veya IP adreslerini derinlemesine analiz edin</p>
            
            <div class="flex gap-2 mb-6">
                <input id="targetInput" type="text" placeholder="Örn: google.com veya 8.8.8.8" class="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-blue-500">
                <button onclick="startLookup()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium transition-colors">Sorgula</button>
            </div>

            <div id="loading" class="hidden text-center text-blue-400 font-medium my-4 animate-pulse">Analiz ediliyor, lütfen bekleyin...</div>

            <div id="results" class="space-y-4 hidden">
                <div class="bg-gray-700 p-4 rounded-lg">
                    <h3 class="text-lg font-semibold text-green-400 mb-2">⏱️ Hız / Ping Kontrolü</h3>
                    <p id="pingResult" class="text-gray-300"></p>
                </div>
                <div class="bg-gray-700 p-4 rounded-lg">
                    <h3 class="text-lg font-semibold text-purple-400 mb-2">🌍 Konum Bilgisi (IP Geolocation)</h3>
                    <pre id="geoResult" class="text-xs overflow-x-auto text-gray-300 bg-gray-950 p-2 rounded"></pre>
                </div>
                <div class="bg-gray-700 p-4 rounded-lg">
                    <h3 class="text-lg font-semibold text-yellow-400 mb-2">📝 WHOIS Bilgileri</h3>
                    <pre id="whoisResult" class="text-xs h-48 overflow-y-auto text-gray-300 bg-gray-950 p-2 rounded whitespace-pre-wrap"></pre>
                </div>
            </div>
        </div>

        <script>
            async function startLookup() {
                const target = document.getElementById('targetInput').value.trim();
                if(!target) return alert('Lütfen bir domain veya IP girin!');

                document.getElementById('loading').classList.remove('hidden');
                document.getElementById('results').classList.add('hidden');

                try {
                    const response = await fetch('/api/lookup?target=' + target);
                    const data = await response.json();

                    document.getElementById('pingResult').innerText = target + ' yanıt süresi: ' + data.ping + ' ms';
                    document.getElementById('geoResult').innerText = JSON.stringify(data.geo, null, 2);
                    document.getElementById('whoisResult').innerText = data.whois;

                    document.getElementById('results').classList.remove('hidden');
                } catch (error) {
                    alert('Sorgulama sırasında bir hata oluştu.');
                } finally {
                    document.getElementById('loading').classList.add('hidden');
                }
            }
        </script>
    </body>
    </html>
    `);
});

// API Uç Noktası (Lookup İşlemleri)
app.get('/api/lookup', async (req, res) => {
    const target = req.query.target;
    let responseData = { ping: null, geo: {}, whois: 'Bilgi bulunamadı.' };

    if (!target) return res.status(400).json({ error: 'Hedef belirtilmedi' });

    // 1. Simüle Edilen Ping / HTTP İstek Süresi Ölçümü
    const start = Date.now();
    let cleanUrl = target.includes('://') ? target : `http://${target}`;
    try {
        await fetch(cleanUrl, { method: 'HEAD', signal: AbortSignal.timeout(3000) });
        responseData.ping = Date.now() - start;
    } catch (e) {
        responseData.ping = "Zaman aşımı / Bağlanılamadı";
    }

    // 2. IP Çözümleme ve Coğrafi Konum (IP-API Kullanarak)
    try {
        let ipAddress = target;
        if (!/^[0-9.]+$/.test(target)) { // Eğer domain ise IP'ye çevir
            const lookup = await dns.lookup(target);
            ipAddress = lookup.address;
        }
        const geoRes = await fetch(`http://ip-api.com/json/${ipAddress}`);
        responseData.geo = await geoRes.json();
    } catch (e) {
        responseData.geo = { error: "Konum bilgisi alınamadı." };
    }

    // 3. WHOIS Sorgusu
    whois.lookup(target, (err, data) => {
        if (!err) responseData.whois = data;
        res.json(responseData); // Tüm sonuçları tek seferde döndür
    });
});

app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor.`);
});