import express from 'express';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { Pool } from 'pg';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Allowed IP
const ALLOWED_IP = '173.181.38.127';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(cookieParser());
app.use(express.static('public'));
app.use(express.json());
app.set('trust proxy', true);

// IP Restriction Middleware
app.use((req, res, next) => {
    const xForwardedFor = req.headers['x-forwarded-for'];
    const ip = xForwardedFor ? xForwardedFor.split(',')[0].trim() : req.ip;
  
    console.log('Client IP:', ip); // Debug for logging
  
    if (ip === ALLOWED_IP || ip === `::ffff:${ALLOWED_IP}`) {
      next();
    } else {
      res.status(403).send('Access forbidden');
    }
  });

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const PRIVATE_KEY = process.env.GITHUB_PRIVATE_KEY;

if (!PRIVATE_KEY) {
  console.error('❌ Missing PRIVATE_KEY');
  process.exit(1);
}

// Start GitHub OAuth
app.get('/', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const signedState = jwt.sign({ state }, PRIVATE_KEY, { algorithm: 'RS256' });
  res.cookie('oauth_state', signedState, { httpOnly: true });

  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=user&user:email&login&&state=${state}`;
  res.redirect(githubAuthUrl);
});

// OAuth Callback
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const signedState = req.cookies.oauth_state;

  if (!signedState || !state) {
    return res.status(403).send('Invalid state');
  }

  try {
    const decoded = jwt.verify(signedState, PRIVATE_KEY, { algorithms: ['RS256'] });
    if (state !== decoded.state) {
      return res.status(403).send('State mismatch');
    }

    res.clearCookie('oauth_state');

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI,
      }),
    });

    const tokenData = await tokenRes.json();
    if (tokenData.error) return res.status(400).json({ error: tokenData.error });

    // Get user info
    const userRes = await fetch('https://api.github.com/user', {
      headers: { Authorization: `token ${tokenData.access_token}` },
    });
    const userData = await userRes.json();
    if (!userData.login) return res.status(400).send('GitHub user fetch failed');

    const expiresAt = Date.now() + 7200 * 1000;

    // Insert token data into database
    await pool.query(
      `INSERT INTO tokens (state, access_token, user_email, authentication_status, method, status, ip_address, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [state, tokenData.access_token, userData.email, 'pass', 'GUI', 'pass', req.ip, expiresAt]
    );

    const html = fs.readFileSync(path.resolve('templates/page.html'), 'utf8');
    res.send(html.replace('${ACCESS_TOKEN}', tokenData.access_token));
  } catch (err) {
    console.error(err);
    res.status(500).send('OAuth Error');
  }
});

// Retrieve token by state
app.get('/token/:state', async (req, res) => {
  const { state } = req.params;

  const result = await pool.query(`SELECT access_token, expires_at FROM tokens WHERE state = $1`, [state]);
  if (result.rowCount === 0) return res.status(404).send('Token not found');

  const { access_token, expires_at } = result.rows[0];
  if (Date.now() > expires_at) {
    await pool.query(`DELETE FROM tokens WHERE state = $1`, [state]);
    return res.status(401).send('Token expired');
  }

  res.json({ access_token });
});

// Admin revocation
// Admin revoke with GitHub API call
app.post('/admin/revoke', async (req, res) => {
    const { state, username } = req.body;
  
    if (!state && !username) return res.status(400).send('Provide state or username');
  
    try {
      // Fetch token from DB
      let tokenRes;
      if (state) {
        tokenRes = await pool.query(`SELECT access_token FROM tokens WHERE state = $1`, [state]);
      } else {
        tokenRes = await pool.query(`SELECT access_token FROM tokens WHERE username = $1`, [username]);
      }
  
      if (tokenRes.rowCount === 0) return res.status(404).send('Token not found');
  
      const accessToken = tokenRes.rows[0].access_token;
  
      // Revoke token on GitHub
      const revokeRes = await fetch(`https://api.github.com/applications/${CLIENT_ID}/token`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
          'Accept': 'application/vnd.github.v3+json',
        },
        body: JSON.stringify({ access_token: accessToken }),
      });
  
      if (revokeRes.status === 204) {
        console.log('✅ GitHub token revoked successfully');
      } else {
        const errText = await revokeRes.text();
        console.warn('⚠️ GitHub token revocation failed:', errText);
      }
  
      // Now delete from DB
      if (state) {
        await pool.query(`DELETE FROM tokens WHERE state = $1`, [state]);
      } else {
        await pool.query(`DELETE FROM tokens WHERE username = $1`, [username]);
      }
  
      res.send('Token revoked successfully');
    } catch (error) {
      console.error('Revocation error:', error);
      res.status(500).send('Failed to revoke token');
    }
  });
  

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
