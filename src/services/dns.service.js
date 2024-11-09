// src/services/dns-service.js

// Helper functions to fetch the email security info from the DNS records

import dns from 'dns';
import logger from '../config/logger.js';
import { cacheService } from './cache.service.js';
import UrlUtils from '../utils/urlUtils.js';


async function getSPFRecord(domain) {
  const cacheKey = `spf:${domain}`;
  const cachedRecord = cacheService.get(cacheKey);
  
  if (cachedRecord) {
    logger.info(`Cache hit for SPF record: ${domain}`);
    return cachedRecord;
  }

  return new Promise((resolve, reject) => {
    dns.resolveTxt(domain, (err, records) => {
      if (err) {
        return reject(err);
      }
      const spfRecord = records.flat().find(record => record.startsWith('v=spf1'));
      const result = spfRecord || 'No SPF record found';
      
      // Cache the result
      cacheService.set(cacheKey, result);
      resolve(result);
    });
  });
}

async function getDKIMRecord(domain) {
  const cacheKey = `dkim:${domain}`;
  const cachedRecord = cacheService.get(cacheKey);
  
  if (cachedRecord) {
    logger.info(`Cache hit for DKIM record: ${domain}`);
    return cachedRecord;
  }

  return new Promise((resolve, reject) => {
    const selectors = ['default._domainkey', 'selector1._domainkey', 'selector2._domainkey'];
    let found = false;

    const checkSelector = async (index) => {
      if (index >= selectors.length) {
        if (!found) {
          const result = 'No DKIM record found';
          cacheService.set(cacheKey, result);
          resolve(result);
        }
        return;
      }

      const selector = selectors[index];
      try {
        const records = await dns.promises.resolveTxt(`${selector}.${domain}`);
        if (records && records.length > 0) {
          const dkimRecord = records.flat().join('');
          if (dkimRecord) {
            found = true;
            cacheService.set(cacheKey, dkimRecord);
            return resolve(dkimRecord);
          }
        }
        checkSelector(index + 1);
      } catch (err) {
        if (err.code !== 'ENOTFOUND') {
          return reject(err);
        }
        checkSelector(index + 1);
      }
    };

    checkSelector(0);
  });
}

async function getDMARCRecord(domain) {
  const cacheKey = `dmarc:${domain}`;
  const cachedRecord = cacheService.get(cacheKey);
  
  if (cachedRecord) {
    logger.info(`Cache hit for DMARC record: ${domain}`);
    return cachedRecord;
  }

  try {
    const records = await dns.promises.resolveTxt(`_dmarc.${domain}`);
    const dmarcRecord = records.flat().join('');
    const result = dmarcRecord || 'No DMARC record found';
    cacheService.set(cacheKey, result);
    return result;
  } catch (err) {
    const result = 'No DMARC record found';
    cacheService.set(cacheKey, result);
    return result;
  }
}

export async function getEmailAuthenticationDetails(domain) {
  try {
    const [spf, dkim, dmarc] = await Promise.all([
      getSPFRecord(domain),
      getDKIMRecord(domain),
      getDMARCRecord(domain),
    ]);

    return {
      spf,
      dkim,
      dmarc,
      summary: `SPF: ${spf !== 'No SPF record found' ? 'Pass' : 'Fail'}, DKIM: ${dkim !== 'No DKIM record found' ? 'Pass' : 'Fail'}, DMARC: ${dmarc !== 'No DMARC record found' ? 'Pass' : 'Fail'}`,
    };
  } catch (error) {
    logger.error('Error fetching email authentication details:', error);
    return {
      spf: 'Error fetching SPF record',
      dkim: 'Error fetching DKIM record',
      dmarc: 'Error fetching DMARC record',
      summary: 'Error fetching authentication details',
    };
  }
}

// Replace domain parsing functions with UrlUtils calls
export function extractRootDomain(url) {
  return UrlUtils.extractDomain(url);
}

export function isValidDomain(domain) {
  return UrlUtils.isValidDomain(domain);
}

export function getDomainInfo(url) {
  return UrlUtils.getDomainInfo(url);
}