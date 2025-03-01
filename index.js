const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const { HttpsProxyAgent }= require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { DateTime } = require('luxon');

global.navigator = { userAgent: 'node' };

// Load configuration from config.json
function loadConfig() {
  try {
    const configPath = path.join(__dirname, 'config.json');
    if (!fs.existsSync(configPath)) {
      const defaultConfig = {
        cognito: {
          region: 'ap-northeast-1',
          clientId: '5msns4n49hmg3dftp2tp1t2iuh',
          userPoolId: 'ap-northeast-1_M22I44OpC',
          username: '',  // To be filled by user
          password: ''   // To be filled by user
        },
        stork: {
          intervalSeconds: 10
        },
        threads: {
          maxWorkers: 10
        }
      };
      fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2), 'utf8');
      return defaultConfig;
    }
    
    const userConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    return userConfig;
  } catch (error) {
    throw new Error('Failed to load configuration');
  }
}

const userConfig = loadConfig();
const config = {
  cognito: {
    region: userConfig.cognito?.region || 'ap-northeast-1',
    clientId: userConfig.cognito?.clientId || '5msns4n49hmg3dftp2tp1t2iuh',
    userPoolId: userConfig.cognito?.userPoolId || 'ap-northeast-1_M22I44OpC',
    username: userConfig.cognito?.username || '',
    password: userConfig.cognito?.password || ''
  },
  stork: {
    baseURL: 'https://app-api.jp.stork-oracle.network/v1',
    authURL: 'https://api.jp.stork-oracle.network/auth',
    tokenPath: path.join(__dirname, 'tokens.json'),
    intervalSeconds: userConfig.stork?.intervalSeconds || 15,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    origin: 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl'
  },
  threads: {
    maxWorkers: userConfig.threads?.maxWorkers || 10,
    proxyFile: path.join(__dirname, 'proxies.txt')
  }
};

const userConfigs = userConfig.cognito.map((accountConfig, index) => ({
  ...config,
  cognito: {
    region: accountConfig.region,
    clientId: accountConfig.clientId,
    userPoolId: accountConfig.userPoolId,
    username: accountConfig.username,
    password: accountConfig.password
  },
  accountIndex: index
}));

function validateConfig() {
  if (!userConfig.cognito || userConfig.cognito.length === 0) {
    console.error('ERROR: At least one account must be set in config.json');
    return false;
  }
  return true;
}

const poolData = { UserPoolId: config.cognito.userPoolId, ClientId: config.cognito.clientId };
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

function getTimestamp() {
  const now = DateTime.now().setZone('Asia/Jakarta');
  return now.toFormat('yyyy-MM-dd HH:mm:ss') + ' WIB';
}

function getFormattedDate() {
  const now = DateTime.now().setZone('Asia/Jakarta');
  return now.toFormat('yyyy-MM-dd HH:mm:ss') + ' WIB';
}

function loadProxies() {
  try {
    if (!fs.existsSync(config.threads.proxyFile)) {
      fs.writeFileSync(config.threads.proxyFile, '', 'utf8');
      return [];
    }
    const proxyData = fs.readFileSync(config.threads.proxyFile, 'utf8');
    const proxies = proxyData
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    return proxies;
  } catch (error) {
    return [];
  }
}

class CognitoAuth {
  constructor(username, password) {
    this.username = username;
    this.password = password;
    this.authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({ Username: username, Password: password });
    this.cognitoUser = new AmazonCognitoIdentity.CognitoUser({ Username: username, Pool: userPool });
  }

  authenticate() {
    return new Promise((resolve, reject) => {
      this.cognitoUser.authenticateUser(this.authenticationDetails, {
        onSuccess: (result) => resolve({
          accessToken: result.getAccessToken().getJwtToken(),
          idToken: result.getIdToken().getJwtToken(),
          refreshToken: result.getRefreshToken().getToken(),
          expiresIn: result.getAccessToken().getExpiration() * 1000 - Date.now()
        }),
        onFailure: (err) => reject(err),
        newPasswordRequired: () => reject(new Error('New password required'))
      });
    });
  }

  refreshSession(refreshToken) {
    const refreshTokenObj = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: refreshToken });
    return new Promise((resolve, reject) => {
      this.cognitoUser.refreshSession(refreshTokenObj, (err, result) => {
        if (err) reject(err);
        else resolve({
          accessToken: result.getAccessToken().getJwtToken(),
          idToken: result.getIdToken().getJwtToken(),
          refreshToken: refreshToken,
          expiresIn: result.getAccessToken().getExpiration() * 1000 - Date.now()
        });
      });
    });
  }
}

class TokenManager {
  constructor(accountConfig) {
    this.accessToken = null;
    this.refreshToken = null;
    this.idToken = null;
    this.expiresAt = null;
    this.auth = new CognitoAuth(accountConfig.cognito.username, accountConfig.cognito.password);
    this.tokenPath = path.join(__dirname, `tokens_${accountConfig.accountIndex}.json`);
  }

  async getValidToken() {
    if (!this.accessToken || this.isTokenExpired()) await this.refreshOrAuthenticate();
    return this.accessToken;
  }

  isTokenExpired() {
    return Date.now() >= this.expiresAt;
  }

  async refreshOrAuthenticate() {
    try {
      let result = this.refreshToken ? await this.auth.refreshSession(this.refreshToken) : await this.auth.authenticate();
      await this.updateTokens(result);
    } catch (error) {
      throw error;
    }
  }

  async updateTokens(result) {
    this.accessToken = result.accessToken;
    this.idToken = result.idToken;
    this.refreshToken = result.refreshToken;
    this.expiresAt = Date.now() + result.expiresIn;
    const tokens = { accessToken: this.accessToken, idToken: this.idToken, refreshToken: this.refreshToken, isAuthenticated: true, isVerifying: false };
    await saveTokens(tokens, this.tokenPath);
  }
}

async function getTokens(tokenPath) {
  try {
    if (!fs.existsSync(tokenPath)) throw new Error(`Tokens file not found at ${tokenPath}`);
    const tokensData = await fs.promises.readFile(tokenPath, 'utf8');
    const tokens = JSON.parse(tokensData);
    if (!tokens.accessToken || tokens.accessToken.length < 20) throw new Error('Invalid access token');
    return tokens;
  } catch (error) {
    throw error;
  }
}

async function saveTokens(tokens, tokenPath) {
  try {
    await fs.promises.writeFile(tokenPath, JSON.stringify(tokens, null, 2), 'utf8');
    return true;
  } catch (error) {
    return false;
  }
}

function getProxyAgent(proxy) {
  if (!proxy) return null;
  if (proxy.startsWith('http')) return new HttpsProxyAgent(proxy);
  if (proxy.startsWith('socks4') || proxy.startsWith('socks5')) return new SocksProxyAgent(proxy);
  throw new Error(`Unsupported proxy protocol: ${proxy}`);
}

async function refreshTokens(refreshToken) {
  try {
    const response = await axios({
      method: 'POST',
      url: `${config.stork.authURL}/refresh`,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': config.stork.userAgent,
        'Origin': config.stork.origin
      },
      data: { refresh_token: refreshToken }
    });
    const tokens = {
      accessToken: response.data.access_token,
      idToken: response.data.id_token || '',
      refreshToken: response.data.refresh_token || refreshToken,
      isAuthenticated: true,
      isVerifying: false
    };
    await saveTokens(tokens);
    return tokens;
  } catch (error) {
    throw error;
  }
}

async function getSignedPrices(tokens) {
  try {
    const response = await axios({
      method: 'GET',
      url: `${config.stork.baseURL}/stork_signed_prices`,
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': config.stork.origin,
        'User-Agent': config.stork.userAgent
      }
    });
    const dataObj = response.data.data;
    const result = Object.keys(dataObj).map(assetKey => {
      const assetData = dataObj[assetKey];
      return {
        asset: assetKey,
        msg_hash: assetData.timestamped_signature.msg_hash,
        price: assetData.price,
        timestamp: new Date(assetData.timestamped_signature.timestamp / 1000000).toISOString(),
        ...assetData
      };
    });
    return result;
  } catch (error) {
    throw error;
  }
}

async function sendValidation(tokens, msgHash, isValid, proxy) {
  try {
    const agent = getProxyAgent(proxy);
    const response = await axios({
      method: 'POST',
      url: `${config.stork.baseURL}/stork_signed_prices/validations`,
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': config.stork.origin,
        'User-Agent': config.stork.userAgent
      },
      httpsAgent: agent,
      data: { msg_hash: msgHash, valid: isValid }
    });
    //console.log(`✓ Validation successful for ${msgHash.substring(0, 10)}... via ${proxy || 'direct'}`);
    return response.data;
  } catch (error) {
    //console.log(`✗ Validation failed for ${msgHash.substring(0, 10)}...: ${error.message}`);
    throw error;
  }
}

async function getUserStats(tokens) {
  try {
    const response = await axios({
      method: 'GET',
      url: `${config.stork.baseURL}/me`,
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': config.stork.origin,
        'User-Agent': config.stork.userAgent
      }
    });
    return response.data.data;
  } catch (error) {
    throw error;
  }
}

function validatePrice(priceData) {
  try {
    if (!priceData.msg_hash || !priceData.price || !priceData.timestamp) {
      return false;
    }
    const currentTime = Date.now();
    const dataTime = new Date(priceData.timestamp).getTime();
    const timeDiffMinutes = (currentTime - dataTime) / (1000 * 60);
    if (timeDiffMinutes > 60) {
      return false;
    }
    return true;
  } catch (error) {
    return false;
  }
}

if (!isMainThread) {
  const { priceData, tokens, proxy } = workerData;

  async function validateAndSend() {
    try {
      const isValid = validatePrice(priceData);
      await sendValidation(tokens, priceData.msg_hash, isValid, proxy);
      parentPort.postMessage({ success: true, msgHash: priceData.msg_hash, isValid, proxy });
    } catch (error) {
      parentPort.postMessage({ success: false, error: error.message, msgHash: priceData.msg_hash, proxy });
    }
  }

  validateAndSend();
} else {
  let previousStats = userConfigs.map(() => ({ validCount: 0, invalidCount: 0, lastValidatedAt: 'Never', status: 'Active', proxy: 'None' }));

  async function runValidationProcess(tokenManager, accountIndex) {
    try {
      const tokens = await getTokens(tokenManager.tokenPath);
      const initialUserData = await getUserStats(tokens);

      if (!initialUserData || !initialUserData.stats) {
        throw new Error('Could not fetch initial user stats');
      }

      const initialValidCount = initialUserData.stats.stork_signed_prices_valid_count || 0;
      const initialInvalidCount = initialUserData.stats.stork_signed_prices_invalid_count || 0;

      if (previousStats[accountIndex].validCount === 0 && previousStats[accountIndex].invalidCount === 0) {
        previousStats[accountIndex].validCount = initialValidCount;
        previousStats[accountIndex].invalidCount = initialInvalidCount;
      }

      const signedPrices = await getSignedPrices(tokens);
      const proxies = loadProxies();

      if (!signedPrices || signedPrices.length === 0) {
        const userData = await getUserStats(tokens);
        updateStats(userData, accountIndex, null);
        return;
      }

      const workers = [];

      const chunkSize = Math.ceil(signedPrices.length / config.threads.maxWorkers);
      const batches = [];
      for (let i = 0; i < signedPrices.length; i += chunkSize) {
        batches.push(signedPrices.slice(i, i + chunkSize));
      }

      for (let i = 0; i < Math.min(batches.length, config.threads.maxWorkers); i++) {
        const batch = batches[i];
        const proxy = proxies.length > 0 ? proxies[i % proxies.length] : null;

        batch.forEach(priceData => {
          workers.push(new Promise((resolve) => {
            const worker = new Worker(__filename, {
              workerData: { priceData, tokens, proxy }
            });
            worker.on('message', resolve);
            worker.on('error', (error) => resolve({ success: false, error: error.message, proxy }));
            worker.on('exit', () => resolve({ success: false, error: 'Worker exited', proxy }));
          }));
        });
      }

      const results = await Promise.all(workers);
      const successCount = results.filter(r => r.success).length;

      const updatedUserData = await getUserStats(tokens);
      const newValidCount = updatedUserData.stats.stork_signed_prices_valid_count || 0;
      const newInvalidCount = updatedUserData.stats.stork_signed_prices_invalid_count || 0;

      const actualValidIncrease = newValidCount - previousStats[accountIndex].validCount;
      const actualInvalidIncrease = newInvalidCount - previousStats[accountIndex].invalidCount;

      previousStats[accountIndex].validCount = newValidCount;
      previousStats[accountIndex].invalidCount = newInvalidCount;

      updateStats(updatedUserData, accountIndex, proxies.length > 0 ? proxies[accountIndex % proxies.length] : null);
    } catch (error) {
      previousStats[accountIndex].status = `Error: ${error.message}`;
    }
  }

  function updateStats(userData, accountIndex, proxy) {
    if (!userData || !userData.stats) {
      return;
    }

    previousStats[accountIndex].validCount = userData.stats.stork_signed_prices_valid_count || 0;
    previousStats[accountIndex].invalidCount = userData.stats.stork_signed_prices_invalid_count || 0;
    previousStats[accountIndex].lastValidatedAt = getFormattedDate();
    previousStats[accountIndex].status = 'Active';
    previousStats[accountIndex].proxy = proxy || 'None';
  }

  function displayAllStats() {
    console.clear();
    console.log('=============================================');
    console.log('   STORK ORACLE AUTO BOT - ALL ACCOUNTS  ');
    console.log('=============================================');
    console.log(`Time: ${getTimestamp()}`);
    console.log(`Total Accounts: ${userConfigs.length}`);
    const proxies = loadProxies();
    console.log(`Total Proxies: ${proxies.length}`);
    
    const errorCount = previousStats.filter(stat => stat.status.startsWith('Error')).length;
    let summaryStatus = 'All accounts are being processed';
    if (errorCount > 0 && errorCount < userConfigs.length) {
      summaryStatus = 'Some accounts have errors';
    } else if (errorCount === userConfigs.length) {
      summaryStatus = 'All accounts have errors';
    }
    console.log(`Summary Status: ${summaryStatus}`);
    console.log('---------------------------------------------');

    const headers = ['Account', 'Valid', 'Invalid', 'Percentage', 'Last Validated At', 'Status', 'Proxy'];
    const rows = userConfigs.map((config, index) => {
      const stats = previousStats[index];
      const total = stats.validCount + stats.invalidCount;
      const percentage = total > 0 ? ((stats.validCount / total) * 100).toFixed(2) : '0.00';
      return {
        Account: config.cognito.username,
        Valid: stats.validCount,
        Invalid: stats.invalidCount,
        Percentage: `${percentage}%`,
        'Last Validated At': stats.lastValidatedAt,
        Status: stats.status || 'Active',
        Proxy: stats.proxy
      };
    });

    console.table(rows.map(({ Account, Valid, Invalid, Percentage, 'Last Validated At': LastValidatedAt, Status, Proxy }) => ({
      Account, Valid, Invalid, Percentage, 'Last Validated At': LastValidatedAt, Status, Proxy
    })), headers);
    console.log('=============================================');
    console.log('Telegram Channel: https://t.me/khampretairdrop');
    console.log('Credit: https://t.me/AirdropInsiderID');

    // Countdown timer
    let countdown = config.stork.intervalSeconds;
    const countdownInterval = setInterval(() => {
      process.stdout.write(`\rNext update in: ${countdown--} seconds`);
      if (countdown < 0) {
        clearInterval(countdownInterval);
        //process.stdout.write('\rNext update in: 0 seconds\n');
      }
    }, 1000);
  }

  async function main() {
    if (!validateConfig()) {
      process.exit(1);
    }
    
    const tokenManagers = userConfigs.map(config => new TokenManager(config));
    previousStats = userConfigs.map(() => ({ validCount: 0, invalidCount: 0, lastValidatedAt: 'Never', status: 'Active', proxy: 'None' }));

    try {
      console.log('Processing... Please wait.');
      await Promise.all(tokenManagers.map(tm => tm.getValidToken()));

      userConfigs.forEach((_, index) => {
        runValidationProcess(tokenManagers[index], index);
        setInterval(() => runValidationProcess(tokenManagers[index], index), config.stork.intervalSeconds * 1000);
        setInterval(async () => {
          await tokenManagers[index].getValidToken();
        }, 50 * 60 * 1000);
      });

      setInterval(displayAllStats, config.stork.intervalSeconds * 1000);
    } catch (error) {
      console.error(`Application failed to start: ${error.message}`);
      process.exit(1);
    }
  }

  main();
}