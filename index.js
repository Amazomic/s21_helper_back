require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const Redis = require('ioredis');

const app = express();
const redis = new Redis(process.env.REDIS_URL);

app.use(cors());
app.use(bodyParser.json());

// Валидация InitData (нужна только при линковке)
function parseAndValidateInitData(initData) {
    if (!initData) return null;
    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get('hash');
    urlParams.delete('hash');

    const paramsList = Array.from(urlParams.entries()).map(([k, v]) => `${k}=${v}`);
    paramsList.sort();
    const dataCheckString = paramsList.join('\n');

    const secret = crypto.createHmac('sha256', 'WebAppData').update(process.env.BOT_TOKEN).digest();
    const calculatedHash = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');

    if (calculatedHash === hash) return JSON.parse(urlParams.get('user'));
    return null;
}

// Middleware: Строгая проверка School Token
const requireSchoolAuth = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const userInfoUrl = 'https://auth.21-school.ru/auth/realms/EduPowerKeycloak/protocol/openid-connect/userinfo';
        const response = await axios.get(userInfoUrl, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        req.schoolLogin = response.data.preferred_username; // e.g., "amazomic"
        next();
    } catch (error) {
        console.error("Token verification failed", error.message);
        return res.status(401).json({ error: "Invalid School Token" });
    }
};

// 1. ПРИВЯЗКА (LINK)
app.post('/v1/telegram/link', requireSchoolAuth, async (req, res) => {
    // Ждем initData в теле запроса, чтобы достать ID телеграма
    const { initData } = req.body;
    if (!initData) return res.status(400).json({ error: "InitData required for linking" });

    const tgUser = parseAndValidateInitData(initData);
    if (!tgUser) return res.status(400).json({ error: "Invalid InitData" });

    const login = req.schoolLogin;
    const key = `school_settings:${login}`;

    const userData = {
        telegram_id: tgUser.id,
        telegram_username: tgUser.username,
        visibility: 'public',
        linked_at: new Date().toISOString()
    };

    await redis.set(key, JSON.stringify(userData));

    return res.json({ success: true, data: { ...userData, school_login: login } });
});

// 2. ПОЛУЧЕНИЕ НАСТРОЕК (GET)
app.get('/v1/telegram/settings', requireSchoolAuth, async (req, res) => {
    const login = req.schoolLogin;
    const dataString = await redis.get(`school_settings:${login}`);

    if (!dataString) {
        // 404 - это норм, значит просто не привязан
        return res.status(404).json({ linked: false });
    }

    const data = JSON.parse(dataString);
    return res.json({
        linked: true,
        school_login: login,
        ...data
    });
});

// 3. ОБНОВЛЕНИЕ (PUT)
app.put('/v1/telegram/settings', requireSchoolAuth, async (req, res) => {
    const login = req.schoolLogin;
    const { visibility } = req.body;
    const key = `school_settings:${login}`;

    const dataString = await redis.get(key);
    if (!dataString) return res.status(404).json({ error: "Not linked" });

    const data = JSON.parse(dataString);
    data.visibility = visibility || data.visibility;

    await redis.set(key, JSON.stringify(data));
    return res.json({ success: true, visibility: data.visibility });
});

// 4. УДАЛЕНИЕ (UNLINK)
app.delete('/v1/telegram/link', requireSchoolAuth, async (req, res) => {
    const login = req.schoolLogin;
    await redis.del(`school_settings:${login}`);
    return res.json({ success: true });
});

// 5. ПОИСК ПИРА (ПУБЛИЧНЫЙ)
app.get('/v1/telegram/peer/:login', requireSchoolAuth, async (req, res) => {
    const targetLogin = req.params.login;
    const dataString = await redis.get(`school_settings:${targetLogin}`);

    if (!dataString) return res.status(404).json({ found: false });

    const targetUser = JSON.parse(dataString);
    const visibility = targetUser.visibility || 'public';

    if (visibility === 'private') {
        return res.status(404).json({ found: false });
    }

    if (visibility === 'notify_only') {
        return res.json({ found: true, can_message: false, can_notify: true });
    }

    return res.json({
        found: true,
        can_message: true,
        can_notify: true,
        telegram_username: targetUser.telegram_username
    });
});

// 6. УВЕДОМЛЕНИЕ
app.post('/v1/telegram/notify', requireSchoolAuth, async (req, res) => {
    const { target_login } = req.body;
    const senderLogin = req.schoolLogin;

    const dataString = await redis.get(`school_settings:${target_login}`);
    if (!dataString) return res.status(404).json({ error: "User not found" });

    const targetUser = JSON.parse(dataString);

    if (targetUser.visibility === 'private') {
        return res.status(403).json({ error: "Privacy restricted" });
    }

    try {
        const botMessage = `🔔 Peer <b>${senderLogin}</b> is calling you!`;

        await axios.post(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
            chat_id: targetUser.telegram_id,
            text: botMessage,
            parse_mode: "HTML"
        });

        return res.json({ success: true });
    } catch (e) {
        return res.status(500).json({ error: "Telegram API Error" });
    }
});

// 7. ПОЛУЧЕНИЕ СПИСКА ВСЕХ ПИРОВ
app.get('/v1/telegram/peers', requireSchoolAuth, async (req, res) => {
  try {
    // Получаем все ключи вида school_settings:*
    const keys = await redis.keys('school_settings:*');
    
    if (keys.length === 0) {
      return res.json({ peers: [] });
    }

    // Получаем значения по всем ключам за один запрос (pipeline)
    const pipeline = redis.pipeline();
    keys.forEach(key => pipeline.get(key));
    const values = await pipeline.exec();

    // Формируем результат
    const peers = [];
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const value = values[i]?.[1]; // [error, result] → берем result

      if (!value) continue;

      try {
        const data = JSON.parse(value);
        const login = key.replace('school_settings:', '');
        peers.push({
          school_login: login,
          visibility: data.visibility || 'private'
        });
      } catch (e) {
        // Игнорируем повреждённые записи
        continue;
      }
    }

    return res.json({ peers });
  } catch (error) {
    console.error('Failed to fetch peers list:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

app.listen(PORT, HOST, () => {
  console.log(`Backend running on http://${HOST}:${PORT}`);
});
