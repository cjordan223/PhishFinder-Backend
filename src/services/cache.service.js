import NodeCache from 'node-cache';
import logger from '../config/logger.js';

class CacheService {
  constructor() {
    this.cache = new NodeCache({ stdTTL: 3600 }); // Cache TTL of 1 hour
  }

  get(key) {
    const value = this.cache.get(key);
    if (value) {
      logger.info(`Cache hit for key: ${key}`);
    } else {
      logger.info(`Cache miss for key: ${key}`);
    }
    return value;
  }

  set(key, value) {
    this.cache.set(key, value);
    logger.info(`Cache set for key: ${key}`);
  }
}

const cacheService = new CacheService();
export { cacheService };