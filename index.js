const express = require('express');
const whois = require('whois');
const { exec } = require('child_process');
const dns = require('dns');
const net = require('net');
const axios = require('axios');
const svgCaptcha = require('svg-captcha');
const app = express();

const port = process.env.PORT || 10000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- KRİTİK: HEALTH CHECK ---
app.get('/healthost', (req, res) => {
    res.status(200).send('OK');
});

// Sunucu tarafında tutulan captcha kodları
const activeCaptchas = {}; 

// Hız Sınırı (Dakikada 60)
const apiRequestCounts = {};
setInterval(() => { Object.keys(apiRequestCounts).forEach(k => delete apiRequestCounts[k]); }, 60000);

function rateLimiter(req, res, next) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (!apiRequestCounts[ip]) apiRequestCounts[ip] = 0;
    
    if (apiRequestCounts[ip] >= 60) {
        return res.status(429).json({ error: 'Dakikalık limit (60) aşıldı. Lütfen bekleyin.' });
    }
    apiRequestCounts[ip]++;
    next();
}

// Güvenli ve Akıllı Ping Sistemi (ICMP + TCP Fallback)
function performPing(target, callback) {
    const cleanTarget = target.replace(/[^a-zA-Z0-9.-]/g, '');
    
    // 1. Aşama: Standart ICMP Ping dene
    exec(`ping -c 3 -W 2 ${cleanTarget}`, (err, stdout) => {
        if (!err && stdout) {
            return callback(null, stdout);
        }
        
        // 2. Aşama: ICMP başarısız olursa (Sunucu kısıtlaması), TCP Fallback başlat
        const start = Date.now();
        dns.lookup(cleanTarget, (dnsErr, address) => {
            if (dnsErr) {
                return callback(new Error('DNS Çözümleme Hatası: Alan adı bulunamadı.'));
            }
            
            const socket = new net.Socket();
            socket.setTimeout(2500);
            
            socket.on('connect', () => {
                const duration = Date.now() - start;
                socket.destroy();
                callback(null, `PING SUCCESS (TCP FALLBACK)\n-------------------------\nHedef IP: ${address}\nPort: 80 (HTTP)\nGecikme Süresi: ${duration} ms\n\n(Not: Sunucuda ICMP kısıtlı olduğundan bağlantı TCP üzerinden test edilmiştir.)`);
            });

            socket.on('error', () => {
                socket.destroy();
                // Port 80 kapalıysa Port 443'ü dene
                const startSecure = Date.now();
                const secureSocket = new net.Socket();
                secureSocket.setTimeout(2500);
                
                secureSocket.on('connect', () => {
                    const duration = Date.now() - startSecure;
                    secureSocket.destroy();
                    callback(null, `PING SUCCESS (TCP FALLBACK)\n-------------------------\nHedef IP: ${address}\nPort: 443 (HTTPS)\nGecikme Süresi: ${duration} ms\n\n(Not: Sunucuda ICMP kısıtlı olduğundan güvenli TCP üzerinden test edilmiştir.)`);
                });
                
                secureSocket.on('error', (e) => {
                    secureSocket.destroy();
                    callback(null, `PING FAILED\n-------------------------\nHedef IP: ${address}\nHata: Port 80 ve 443 bağlantı isteklerine yanıt vermedi.\nHata Detayı: ${e.message}`);
                });
                secureSocket.connect(443, address);
            });

            socket.on('timeout', () => {
                socket.destroy();
                callback(null, `PING TIMEOUT\n-------------------------\nHedef IP: ${address}\nDurum: 2500ms içinde bağlantı sağlanamadı.`);
            });

            socket.connect(80, address);
        });
    });
}

function parseWhois(rawText) {
    const info = { registrar: 'Bilinmiyor', creationDate: 'Bilinmiyor', expiryDate: 'Bilinmiyor', raw: rawText };
    if (!rawText) return info;

    const lines = rawText.split('\n');
    lines.forEach(line => {
        const lower = line.toLowerCase();
        if ((lower.includes('registrar:') || lower.includes('registrar organization:')) && info.registrar === 'Bilinmiyor') {
            info.registrar = line.split(':')[1]?.trim();
        }
        if ((lower.includes('creation date:') || lower.includes('created:') || lower.includes('registered on:')) && info.creationDate === 'Bilinmiyor') {
            info.creationDate = line.split(':')[1]?.trim();
        }
        if ((lower.includes('registry expiry date:') || lower.includes('expiration date:') || lower.includes('expires on:')) && info.expiryDate === 'Bilinmiyor') {
            info.expiryDate = line.split(':')[1]?.trim();
        }
    });
    return info;
}

// --- KULLANICI IP TESPİTİ ---
app.get('/api/myip', (req, res) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (ip.startsWith('::ffff:')) {
        ip = ip.substring(7);
    }
    res.json({ ip });
});

// --- DEVELOPER API (Doğrulama Yok) ---
app.get('/api/v1/domain', rateLimiter, (req, res) => {
    const target = req.query.target;
    if (!target) return res.status(400).json({ error: 'Target parametresi eksik' });
    whois.lookup(target, (err, data) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ type: 'domain', ...parseWhois(data) });
    });
});

app.get('/api/v1/ip', rateLimiter, async (req, res) => {
    const target = req.query.target;
    if (!target) return res.status(400).json({ error: 'Target parametresi eksik' });
    try {
        const response = await axios.get(`http://ip-api.com/json/${target}?fields=status,message,country,city,isp,mobile,proxy,hosting`);
        if (response.data.status !== 'success') return res.status(400).json({ error: 'IP bilgisi alınamadı' });
        const d = response.data;
        res.json({
            type: 'ip',
            location: `${d.city}, ${d.country}`,
            isp: d.isp,
            infrastructure: (d.hosting || d.proxy) ? 'Kurumsal / Veri Merkezi / VPN' : (d.mobile ? 'Mobil Şebeke' : 'Ev / Bireysel Hat'),
            raw: d
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/v1/ping', rateLimiter, (req, res) => {
    const target = req.query.target;
    if (!target) return res.status(400).json({ error: 'Target parametresi eksik' });
    performPing(target, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ type: 'ping', result });
    });
});

// --- GÜVENLİ VE GERÇEK CAPTCHA RETER ---
app.get('/api/captcha/generate', (req, res) => {
    // svg-captcha harfleri doğrudan eğrilere (path) dönüştürür. HTML'de yazı barınmaz.
    const captcha = svgCaptcha.create({
        size: 5,
        noise: 3,
        color: true,
        background: '#161b22',
        width: 140,
        height: 45,
        fontSize: 36
    });
    
    const captchaId = Math.random().toString(36).substring(2, 9);
    activeCaptchas[captchaId] = captcha.text.toLowerCase(); // Küçük harfe eşitleyip saklıyoruz

    res.json({ id: captchaId, svg: Buffer.from(captcha.data).toString('base64') });
});

// --- FRONTEND GÜVENLİ API ---
app.post('/api/frontend/query', rateLimiter, async (req, res) => {
    const { type, target, captchaId, captchaCode } = req.body;

    if (!captchaId || !activeCaptchas[captchaId] || activeCaptchas[captchaId] !== captchaCode?.trim().toLowerCase()) {
        return res.status(400).json({ error: 'Güvenlik kodu (Captcha) hatalı veya süresi dolmuş!' });
    }
    
    delete activeCaptchas[captchaId]; // Güvenlik için kullanıldığı an imha edilir

    if (type === 'domain') {
        whois.lookup(target, (err, data) => {
            if (err) return res.json({ error: 'Whois sorgusu başarısız.' });
            return res.json(parseWhois(data));
        });
    } else if (type === 'ip') {
        try {
            const response = await axios.get(`http://ip-api.com/json/${target}?fields=status,country,city,isp,hosting,proxy,mobile`);
            if (response.data.status !== 'success') return res.json({ error: 'Geçersiz IP adresi.' });
            const d = response.data;
            return res.json({
                location: `${d.city}, ${d.country}`,
                isp: d.isp,
                infrastructure: (d.hosting || d.proxy) ? 'Kurumsal / Veri Merkezi / VPN' : (d.mobile ? 'Mobil Şebeke' : 'Ev / Bireysel Hat'),
                raw: JSON.stringify(d, null, 2)
            });
        } catch {
            return res.json({ error: 'IP sorgu hatası.' });
        }
    } else if (type === 'ping') {
        performPing(target, (err, result) => {
            if (err) return res.json({ error: err.message });
            return res.json({ raw: result });
        });
    } else {
        return res.status(400).json({ error: 'Geçersiz işlem türü.' });
    }
});

// --- DASHBOARD FRONTEND ---
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>HostLook-up Professional Dashboard</title>
        <style>
            :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; }
            body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; margin: 0; padding: 20px; display: flex; justify-content: center; }
            .dashboard { width: 100%; max-width: 900px; }
            h1 { text-align: center; color: #fff; font-size: 28px; margin-bottom: 5px; }
            .subtitle { text-align: center; color: #8b949e; margin-bottom: 30px; font-size: 14px; }
            .tabs { display: flex; gap: 10px; margin-bottom: 20px; justify-content: center; }
            .tab-btn { background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: 0.2s; }
            .tab-btn.active { background: var(--accent); color: #000; border-color: var(--accent); }
            .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 25px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
            .input-group { display: flex; flex-direction: column; gap: 15px; }
            .search-box { display: flex; gap: 10px; }
            input[type="text"] { flex: 1; background: #010409; border: 1px solid var(--border); padding: 12px; border-radius: 6px; color: #fff; font-size: 16px; }
            input:focus { outline: none; border-color: var(--accent); }
            .captcha-container { display: flex; align-items: center; gap: 15px; margin-top: 5px; background: #010409; padding: 10px; border-radius: 6px; border: 1px solid var(--border); width: max-content; }
            .captcha-img { height: 45px; border-radius: 4px; background: #161b22; display: flex; align-items: center; overflow: hidden; }
            .captcha-img svg { display: block; height: 100%; }
            .captcha-input { width: 100px !important; padding: 10px !important; text-transform: uppercase; }
            .btn-submit { background: var(--accent); color: #000; font-weight: bold; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px; transition: 0.2s; }
            .btn-submit:hover { opacity: 0.9; }
            .results-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-top: 25px; }
            .result-item { background: #010409; border: 1px solid var(--border); padding: 15px; border-radius: 6px; }
            .result-item label { font-size: 12px; color: #8b949e; display: block; margin-bottom: 5px; text-transform: uppercase; letter-spacing: 0.5px; }
            .result-item span { font-size: 16px; color: #fff; font-weight: 500; }
            .raw-output { margin-top: 25px; background: #010409; border: 1px solid var(--border); padding: 15px; border-radius: 6px; max-height: 250px; overflow-y: auto; font-family: monospace; font-size: 13px; white-space: pre-wrap; color: #8b949e; }
            .refresh-captcha { cursor: pointer; color: var(--accent); font-size: 12px; margin-left: 5px; user-select: none; }
            .client-ip-info { font-size: 13px; color: #8b949e; margin-top: -10px; display: none; }
            .client-ip-info span { color: var(--accent); cursor: pointer; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="dashboard">
            <h1>HostLook-up</h1>
            <div class="subtitle">Domain, IP ve Güvenli Ağ Analiz Platformu (v2.1)</div>
            
            <div class="tabs">
                <button class="tab-btn active" onclick="setMode('domain', 'Örn: google.com')">Domain Sorgula</button>
                <button class="tab-btn" onclick="setMode('ip', 'Örn: 8.8.8.8')">IP Sorgula</button>
                <button class="tab-btn" onclick="setMode('ping', 'Örn: google.com')">Ping At</button>
            </div>

            <div class="card">
                <div class="input-group">
                    <div id="ipAutoDisplay" class="client-ip-info">İnternet Çıkış IP Adresiniz: <span id="myIpText" onclick="fillMyIp()">Yükleniyor...</span></div>
                    <div class="search-box">
                        <input type="text" id="targetInput" placeholder="Örn: google.com">
                        <button class="btn-submit" onclick="runQuery()">Sorgula</button>
                    </div>

                    <div class="captcha-container">
                        <div id="captchaBox" class="captcha-img">Yükleniyor...</div>
                        <input type="text" id="captchaInput" class="captcha-input" placeholder="Kod" maxlength="5" autocomplete="off">
                        <span class="refresh-captcha" onclick="loadCaptcha()">🔄 Yenile</span>
                    </div>
                </div>

                <div class="results-grid" id="gridOutput" style="display: none;"></div>
                <div class="raw-output" id="rawOutput" style="display: none;"></div>
            </div>
        </div>

        <script>
            let currentMode = 'domain';
            let currentCaptchaId = '';
            let clientIp = '';

            // IP Tespiti
            async function fetchClientIp() {
                try {
                    const res = await fetch('/api/myip');
                    const data = await res.json();
                    clientIp = data.ip;
                    document.getElementById('myIpText').innerText = clientIp;
                } catch(e) {
                    document.getElementById('myIpText').innerText = 'Tespit edilemedi';
                }
            }

            function fillMyIp() {
                if(clientIp) {
                    document.getElementById('targetInput').value = clientIp;
                }
            }

            function setMode(mode, placeholder) {
                currentMode = mode;
                document.getElementById('targetInput').placeholder = placeholder;
                document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
                if(event) event.target.classList.add('active');
                
                const ipDisplay = document.getElementById('ipAutoDisplay');
                if(mode === 'ip') {
                    ipDisplay.style.display = 'block';
                    fillMyIp();
                } else {
                    ipDisplay.style.display = 'none';
                }
                
                clearOutputs();
            }

            function clearOutputs() {
                document.getElementById('gridOutput').style.display = 'none';
                document.getElementById('rawOutput').style.display = 'none';
                document.getElementById('captchaInput').value = '';
            }

            async function loadCaptcha() {
                try {
                    const res = await fetch('/api/captcha/generate');
                    const data = await res.json();
                    currentCaptchaId = data.id;
                    // base64 ile kodlanmış SVG içeriğini çözüp div içerisine basıyoruz
                    document.getElementById('captchaBox').innerHTML = atob(data.svg);
                } catch (err) {
                    document.getElementById('captchaBox').innerText = 'Captcha Hatası';
                }
            }

            async function runQuery() {
                const target = document.getElementById('targetInput').value.trim();
                const captchaCode = document.getElementById('captchaInput').value.trim();
                const grid = document.getElementById('gridOutput');
                const raw = document.getElementById('rawOutput');

                if(!target || !captchaCode) return alert('Lütfen hedef adresi ve güvenlik kodunu eksiksiz doldurun!');

                grid.style.display = 'none';
                raw.style.display = 'block';
                raw.innerText = 'İşlem yapılıyor, lütfen bekleyin...';

                try {
                    const response = await fetch('/api/frontend/query', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            type: currentMode,
                            target: target,
                            captchaId: currentCaptchaId,
                            captchaCode: captchaCode
                        })
                    });

                    const data = await response.json();

                    if(response.status !== 200 || data.error) {
                        raw.innerText = 'Hata: ' + (data.error || 'Bilinmeyen bir hata oluştu.');
                        loadCaptcha();
                        return;
                    }

                    grid.innerHTML = '';
                    if(currentMode === 'domain') {
                        grid.innerHTML = \`
                            <div class="result-item"><label>Kayıt Şirketi (Registrar)</label><span>\${data.registrar}</span></div>
                            <div class="result-item"><label>Kayıt Tarihi</label><span>\${data.creationDate}</span></div>
                            <div class="result-item"><label>Bitiş Tarihi (Expiry)</label><span>\${data.expiryDate}</span></div>
                        \`;
                        raw.innerText = data.raw || 'Ham veri bulunamadı.';
                        grid.style.display = 'grid';
                    } else if(currentMode === 'ip') {
                        grid.innerHTML = \`
                            <div class="result-item"><label>Tahmini Lokasyon</label><span>\${data.location}</span></div>
                            <div class="result-item"><label>Servis Sağlayıcı (ISP)</label><span>\${data.isp}</span></div>
                            <div class="result-item"><label>Hat Türü</label><span>\${data.infrastructure}</span></div>
                        \`;
                        raw.innerText = data.raw;
                        grid.style.display = 'grid';
                    } else if(currentMode === 'ping') {
                        raw.innerText = data.raw;
                    }

                    loadCaptcha();

                } catch(err) {
                    raw.innerText = 'Sunucuyla iletişim kurulurken bir hata oluştu.';
                    loadCaptcha();
                }
            }

            // İlk yükleme tetikleyicileri
            loadCaptcha();
            fetchClientIp();
        </script>
    </body>
    </html>
    `);
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Sunucu ${port} portunda tam donanımlı ve güvenli olarak yayında.`);
});
