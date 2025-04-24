import express from 'express';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { logAuthAttempt } from './db.mjs';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cookieParser());
app.use(express.static('public'));

const ALLOWED_IP = '173.181.38.127';
app.set('trust proxy', true);

app.use(express.json());
app.use((req, res, next) => {
  const clientIP = req.headers['x-forwarded-for'] || req.ip;
  console.log('Client IP:', clientIP);
  if (clientIP === ALLOWED_IP) {
    next();
  } else {
    res.status(403).send('Access forbidden');
  }
});

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const PRIVATE_KEY = process.env.GITHUB_PRIVATE_KEY?.replace(/\\n/g, '\n');

if (!PRIVATE_KEY) {
  console.error('❌ Private key is missing.');
  process.exit(1);
}

const tokenStore = {};

app.get('/', (req, res) => {
  if (!CLIENT_ID || !REDIRECT_URI || !PRIVATE_KEY) {
    return res.status(500).send('Missing required environment variables');
  }

  const state = crypto.randomBytes(16).toString('hex');
  const signedState = jwt.sign({ state }, PRIVATE_KEY, { algorithm: 'RS256' });

  res.cookie('oauth_state', signedState, { httpOnly: true });

  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=read:org user:email&login&state=${state}`;
  res.redirect(githubAuthUrl);
});

app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const signedState = req.cookies.oauth_state;
  const clientIP = req.headers['x-forwarded-for'] || req.ip;

  if (!signedState || !state) {
    return res.status(403).send('Invalid state. Possible CSRF attack.');
  }

  try {
    const decodedState = jwt.verify(signedState, PRIVATE_KEY, { algorithms: ['RS256'] });
    if (state !== decodedState.state) {
      return res.status(403).send('State mismatch. CSRF risk.');
    }

    res.clearCookie('oauth_state');

    const response = await fetch('https://github.com/login/oauth/access_token', {
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
        expires_in: 7200,
      }),
    });

    const data = await response.json();
    if (data.error) {
      return res.status(400).json({ error: data.error });
    }

    const expirationTime = Date.now() + 7200 * 1000;
    tokenStore[state] = {
      access_token: data.access_token,
      expires_at: expirationTime,
    };

    // Step 1: Get GitHub user info
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `token ${data.access_token}`,
        Accept: 'application/vnd.github+json',
      },
    });
    const userData = await userResponse.json();
    const githubUsername = userData.login || 'unknown';

    // Step 2: Get user's primary email
    const emailResponse = await fetch('https://api.github.com/user/emails', {
      headers: {
        Authorization: `token ${data.access_token}`,
        Accept: 'application/vnd.github+json',
      },
    });
    const emails = await emailResponse.json();
    const primaryEmail = emails.find(e => e.primary)?.email || emails[0]?.email || 'unknown';

    // Step 3: Check GitHub org membership
    const orgName = 'AquaNow';
    const orgResponse = await fetch(`https://api.github.com/orgs/${orgName}/members/${githubUsername}`, {
      headers: {
        Authorization: `token ${data.access_token}`,
        Accept: 'application/vnd.github+json',
      },
    });

    if (orgResponse.status !== 204) {
      console.log(`❌ ${githubUsername} (${primaryEmail}) is NOT a member of ${orgName}`);

      await logAuthAttempt({
        userEmail: primaryEmail,
        authenticationStatus: 'Fail',
        method: 'GUI',
        status: 'Fail - Not an organization member',
        ipAddress: clientIP,
      });

      return res.status(403).send(`${primaryEmail} is NOT authorized to access this system.`);
    }

    // ✅ User is authorized
    await logAuthAttempt({
      userEmail: primaryEmail,
      authenticationStatus: 'Pass',
      method: 'GUI',
      status: 'Pass',
      ipAddress: clientIP,
    });

    const htmlTemplate = fs.readFileSync(path.resolve('templates/page.html'), 'utf8');
    const htmlResponse = htmlTemplate.replace('${ACCESS_TOKEN}', data.access_token);
    res.send(htmlResponse);

  } catch (err) {
    console.error('Callback Error:', err);

    await logAuthAttempt({
      userEmail: 'unknown',
      authenticationStatus: 'Fail',
      method: 'GUI',
      status: 'Fail',
      ipAddress: clientIP,
    });

    res.status(500).send(`Server error: ${err.message}`);
  }
});

app.get('/token/:state', async (req, res) => {
  const { state } = req.params;
  const clientIP = req.headers['x-forwarded-for'] || req.ip;
  const tokenData = tokenStore[state];

  if (!tokenData) {
    return res.status(404).send('Token not found or expired');
  }

  if (Date.now() > tokenData.expires_at) {
    delete tokenStore[state];
    return res.status(401).send('Token expired');
  }

  await logAuthAttempt({
    userEmail: 'cli-user@github.com',
    authenticationStatus: 'Pass',
    method: 'CLI',
    status: 'Pass',
    ipAddress: clientIP,
  });

  res.json({
    state,
    access_token: tokenData.access_token,
  });
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
