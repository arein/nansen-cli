#!/usr/bin/env node
/**
 * Nansen CLI - Command-line interface for Nansen API
 * Designed for AI agents with structured JSON output
 * 
 * Usage: nansen <command> [options]
 * 
 * All output is JSON for easy parsing by AI agents.
 * Use --pretty for human-readable formatting.
 */

import { NansenAPI } from './api.js';

// Parse command line arguments
function parseArgs(args) {
  const result = { _: [], flags: {}, options: {} };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = args[i + 1];
      
      if (key === 'pretty' || key === 'help') {
        result.flags[key] = true;
      } else if (next && !next.startsWith('-')) {
        // Try to parse as JSON first
        try {
          result.options[key] = JSON.parse(next);
        } catch {
          result.options[key] = next;
        }
        i++;
      } else {
        result.flags[key] = true;
      }
    } else if (arg.startsWith('-')) {
      result.flags[arg.slice(1)] = true;
    } else {
      result._.push(arg);
    }
  }
  
  return result;
}

// Output helper
function output(data, pretty = false) {
  if (pretty) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(JSON.stringify(data));
  }
}

// Error output
function errorOutput(error, pretty = false) {
  const errorData = {
    success: false,
    error: error.message,
    status: error.status,
    details: error.data
  };
  output(errorData, pretty);
  process.exit(1);
}

// Help text
const HELP = `
Nansen CLI - Command-line interface for Nansen API
Designed for AI agents with structured JSON output.

USAGE:
  nansen <command> [subcommand] [options]

COMMANDS:
  smart-money    Smart Money analytics (netflow, dex-trades, holdings, dcas)
  profiler       Wallet profiling (balance, labels, transactions, pnl)
  token          Token God Mode (screener, holders, flows, trades, pnl)
  portfolio      Portfolio analytics (defi-holdings)
  help           Show this help message

GLOBAL OPTIONS:
  --pretty       Format JSON output for readability
  --chain        Blockchain to query (ethereum, solana, base, etc.)
  --chains       Multiple chains as JSON array
  --limit        Number of results (shorthand for pagination)
  --filters      JSON object with filters
  --order-by     JSON array with sort order

EXAMPLES:
  # Get Smart Money netflow on Solana
  nansen smart-money netflow --chain solana

  # Get top tokens by Smart Money activity
  nansen token screener --chain solana --timeframe 24h --pretty

  # Get wallet balance
  nansen profiler balance --address 0x123... --chain ethereum

  # Get wallet labels
  nansen profiler labels --address 0x123... --chain ethereum

  # Search for entity
  nansen profiler search --query "Vitalik"

  # Get token holders with filters
  nansen token holders --token 0x123... --filters '{"only_smart_money":true}'

SMART MONEY LABELS:
  Fund, Smart Trader, 30D Smart Trader, 90D Smart Trader, 
  180D Smart Trader, Smart HL Perps Trader

SUPPORTED CHAINS:
  ethereum, solana, base, bnb, arbitrum, polygon, optimism,
  avalanche, linea, scroll, zksync, mantle, ronin, sei,
  plasma, sonic, unichain, monad, hyperevm, iotaevm

For more info: https://docs.nansen.ai
`;

// Command handlers
const commands = {
  'help': async (args, api, flags) => {
    console.log(HELP);
  },

  'smart-money': async (args, api, flags, options) => {
    const subcommand = args[0] || 'help';
    const chain = options.chain || 'solana';
    const chains = options.chains || [chain];
    const filters = options.filters || {};
    const orderBy = options['order-by'];
    const pagination = options.limit ? { page: 1, per_page: options.limit } : undefined;

    // Add smart money label filter if specified
    if (options.labels) {
      filters.include_smart_money_labels = Array.isArray(options.labels) 
        ? options.labels 
        : [options.labels];
    }

    const handlers = {
      'netflow': () => api.smartMoneyNetflow({ chains, filters, orderBy, pagination }),
      'dex-trades': () => api.smartMoneyDexTrades({ chains, filters, orderBy, pagination }),
      'perp-trades': () => api.smartMoneyPerpTrades({ filters, orderBy, pagination }),
      'holdings': () => api.smartMoneyHoldings({ chains, filters, orderBy, pagination }),
      'dcas': () => api.smartMoneyDcas({ filters, orderBy, pagination }),
      'help': () => ({
        commands: ['netflow', 'dex-trades', 'perp-trades', 'holdings', 'dcas'],
        description: 'Smart Money analytics endpoints',
        example: 'nansen smart-money netflow --chain solana --labels Fund'
      })
    };

    if (!handlers[subcommand]) {
      return { error: `Unknown subcommand: ${subcommand}`, available: Object.keys(handlers) };
    }

    return handlers[subcommand]();
  },

  'profiler': async (args, api, flags, options) => {
    const subcommand = args[0] || 'help';
    const address = options.address;
    const entityName = options.entity || options['entity-name'];
    const chain = options.chain || 'ethereum';
    const filters = options.filters || {};
    const orderBy = options['order-by'];
    const pagination = options.limit ? { page: 1, recordsPerPage: options.limit } : undefined;

    const handlers = {
      'balance': () => api.addressBalance({ address, entityName, chain, filters, orderBy }),
      'labels': () => api.addressLabels({ address, chain, pagination }),
      'transactions': () => api.addressTransactions({ address, chain, filters, orderBy, pagination }),
      'pnl': () => api.addressPnl({ address, chain }),
      'search': () => api.entitySearch({ query: options.query, pagination }),
      'help': () => ({
        commands: ['balance', 'labels', 'transactions', 'pnl', 'search'],
        description: 'Wallet profiling endpoints',
        example: 'nansen profiler balance --address 0x123... --chain ethereum'
      })
    };

    if (!handlers[subcommand]) {
      return { error: `Unknown subcommand: ${subcommand}`, available: Object.keys(handlers) };
    }

    return handlers[subcommand]();
  },

  'token': async (args, api, flags, options) => {
    const subcommand = args[0] || 'help';
    const tokenAddress = options.token || options['token-address'];
    const chain = options.chain || 'solana';
    const chains = options.chains || [chain];
    const timeframe = options.timeframe || '24h';
    const filters = options.filters || {};
    const orderBy = options['order-by'];
    const pagination = options.limit ? { page: 1, per_page: options.limit } : undefined;

    // Convenience filter for smart money only
    if (options['smart-money'] || flags['smart-money']) {
      filters.only_smart_money = true;
    }

    const handlers = {
      'screener': () => api.tokenScreener({ chains, timeframe, filters, orderBy, pagination }),
      'holders': () => api.tokenHolders({ tokenAddress, chain, filters, orderBy, pagination }),
      'flows': () => api.tokenFlows({ tokenAddress, chain, filters, orderBy, pagination }),
      'dex-trades': () => api.tokenDexTrades({ tokenAddress, chain, filters, orderBy, pagination }),
      'pnl': () => api.tokenPnlLeaderboard({ tokenAddress, chain, filters, orderBy, pagination }),
      'who-bought-sold': () => api.tokenWhoBoughtSold({ tokenAddress, chain, filters, orderBy, pagination }),
      'help': () => ({
        commands: ['screener', 'holders', 'flows', 'dex-trades', 'pnl', 'who-bought-sold'],
        description: 'Token God Mode endpoints',
        example: 'nansen token screener --chain solana --timeframe 24h --smart-money'
      })
    };

    if (!handlers[subcommand]) {
      return { error: `Unknown subcommand: ${subcommand}`, available: Object.keys(handlers) };
    }

    return handlers[subcommand]();
  },

  'portfolio': async (args, api, flags, options) => {
    const subcommand = args[0] || 'help';
    const walletAddress = options.wallet || options.address;

    const handlers = {
      'defi': () => api.portfolioDefiHoldings({ walletAddress }),
      'defi-holdings': () => api.portfolioDefiHoldings({ walletAddress }),
      'help': () => ({
        commands: ['defi', 'defi-holdings'],
        description: 'Portfolio analytics endpoints',
        example: 'nansen portfolio defi --wallet 0x123...'
      })
    };

    if (!handlers[subcommand]) {
      return { error: `Unknown subcommand: ${subcommand}`, available: Object.keys(handlers) };
    }

    return handlers[subcommand]();
  }
};

// Main entry point
async function main() {
  const rawArgs = process.argv.slice(2);
  const { _: positional, flags, options } = parseArgs(rawArgs);
  
  const command = positional[0] || 'help';
  const subArgs = positional.slice(1);
  const pretty = flags.pretty || flags.p;

  if (command === 'help' || flags.help || flags.h) {
    console.log(HELP);
    return;
  }

  if (!commands[command]) {
    output({ 
      error: `Unknown command: ${command}`,
      available: Object.keys(commands)
    }, pretty);
    process.exit(1);
  }

  try {
    const api = new NansenAPI();
    const result = await commands[command](subArgs, api, flags, options);
    output({ success: true, data: result }, pretty);
  } catch (error) {
    errorOutput(error, pretty);
  }
}

main();
