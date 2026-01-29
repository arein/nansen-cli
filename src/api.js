/**
 * Nansen API Client
 * Handles all HTTP communication with the Nansen API
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadConfig() {
  // Try config file first
  const configPath = path.join(__dirname, '..', 'config.json');
  if (fs.existsSync(configPath)) {
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
  }
  
  // Fall back to environment variables
  return {
    apiKey: process.env.NANSEN_API_KEY,
    baseUrl: process.env.NANSEN_BASE_URL || 'https://api.nansen.ai'
  };
}

const config = loadConfig();

export class NansenAPI {
  constructor(apiKey = config.apiKey, baseUrl = config.baseUrl) {
    if (!apiKey) {
      throw new Error('API key required. Set NANSEN_API_KEY env var or create config.json');
    }
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
  }

  async request(endpoint, body = {}, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': this.apiKey,
        ...options.headers
      },
      body: JSON.stringify(body)
    });

    const data = await response.json();

    if (!response.ok) {
      const error = new Error(data.message || data.error || `API error: ${response.status}`);
      error.status = response.status;
      error.data = data;
      throw error;
    }

    return data;
  }

  // ============= Smart Money Endpoints =============
  
  async smartMoneyNetflow(params = {}) {
    const { chains = ['solana'], filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/smart-money/netflow', {
      chains,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async smartMoneyDexTrades(params = {}) {
    const { chains = ['solana'], filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/smart-money/dex-trades', {
      chains,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async smartMoneyPerpTrades(params = {}) {
    const { filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/smart-money/perp-trades', {
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async smartMoneyHoldings(params = {}) {
    const { chains = ['solana'], filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/smart-money/holdings', {
      chains,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async smartMoneyDcas(params = {}) {
    const { filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/smart-money/dcas', {
      filters,
      order_by: orderBy,
      pagination
    });
  }

  // ============= Profiler Endpoints =============

  async addressBalance(params = {}) {
    const { address, entityName, chain = 'ethereum', hideSpamToken = true, filters = {}, orderBy } = params;
    return this.request('/api/v1/profiler/address/current-balance', {
      address,
      entity_name: entityName,
      chain,
      hide_spam_token: hideSpamToken,
      filters,
      order_by: orderBy
    });
  }

  async addressLabels(params = {}) {
    const { address, chain = 'ethereum', pagination = { page: 1, recordsPerPage: 100 } } = params;
    return this.request('/api/beta/profiler/address/labels', {
      parameters: { address, chain },
      pagination
    });
  }

  async addressTransactions(params = {}) {
    const { address, chain = 'ethereum', filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/profiler/address/transactions', {
      address,
      chain,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async addressPnl(params = {}) {
    const { address, chain = 'ethereum' } = params;
    return this.request('/api/v1/profiler/address/pnl-and-trade-performance', {
      address,
      chain
    });
  }

  async entitySearch(params = {}) {
    const { query, pagination } = params;
    return this.request('/api/beta/profiler/entity-name-search', {
      parameters: { query },
      pagination
    });
  }

  // ============= Token God Mode Endpoints =============

  async tokenScreener(params = {}) {
    const { chains = ['solana'], timeframe = '24h', filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/token-screener', {
      chains,
      timeframe,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async tokenHolders(params = {}) {
    const { tokenAddress, chain = 'ethereum', filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/token-god-mode/holders', {
      token_address: tokenAddress,
      chain,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async tokenFlows(params = {}) {
    const { tokenAddress, chain = 'ethereum', filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/token-god-mode/flows', {
      token_address: tokenAddress,
      chain,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async tokenDexTrades(params = {}) {
    const { tokenAddress, chain = 'ethereum', filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/token-god-mode/dex-trades', {
      token_address: tokenAddress,
      chain,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async tokenPnlLeaderboard(params = {}) {
    const { tokenAddress, chain = 'ethereum', filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/token-god-mode/pnl-leaderboard', {
      token_address: tokenAddress,
      chain,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  async tokenWhoBoughtSold(params = {}) {
    const { tokenAddress, chain = 'ethereum', filters = {}, orderBy, pagination } = params;
    return this.request('/api/v1/token-god-mode/who-bought-sold', {
      token_address: tokenAddress,
      chain,
      filters,
      order_by: orderBy,
      pagination
    });
  }

  // ============= Portfolio Endpoints =============

  async portfolioDefiHoldings(params = {}) {
    const { walletAddress } = params;
    return this.request('/api/v1/portfolio/defi-holdings', {
      wallet_address: walletAddress
    });
  }
}

export default NansenAPI;
