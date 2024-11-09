import NodeCache from 'node-cache';

// Cache DNS records for 1 hour by default
const dnsCache = new NodeCache({ 
  stdTTL: 3600,
  checkperiod: 120
});

export const cacheService = {
  get: (key) => dnsCache.get(key),
  set: (key, value) => dnsCache.set(key, value),
  del: (key) => dnsCache.del(key),
  flush: () => dnsCache.flushAll()
}; 