// src/services/dns-service.js
import dns from 'dns';

function getSPFRecord(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt(domain, (err, records) => {
      if (err) {
        return reject(err);
      }
      const spfRecord = records.flat().find(record => record.startsWith('v=spf1'));
      resolve(spfRecord || 'No SPF record found');
    });
  });
}

function getDKIMRecord(domain) {
  return new Promise((resolve, reject) => {
    const selectors = ['default._domainkey', 'selector1._domainkey', 'selector2._domainkey']; // Common selectors
    let found = false;

    const checkSelector = (index) => {
      if (index >= selectors.length) {
        if (!found) {
          resolve('No DKIM record found');
        }
        return;
      }

      const selector = selectors[index];
      dns.resolveTxt(`${selector}.${domain}`, (err, records) => {
        if (err && err.code !== 'ENOTFOUND') {
          return reject(err);
        }
        if (records && records.length > 0) {
          const dkimRecord = records.flat().join('');
          if (dkimRecord) {
            found = true;
            return resolve(dkimRecord);
          }
        }
        checkSelector(index + 1);
      });
    };

    checkSelector(0);
  });
}

function getDMARCRecord(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt(`_dmarc.${domain}`, (err, records) => {
      if (err) {
        return reject(err);
      }
      const dmarcRecord = records.flat().join('');
      resolve(dmarcRecord || 'No DMARC record found');
    });
  });
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
    console.error('Error fetching email authentication details:', error);
    return {
      spf: 'Error fetching SPF record',
      dkim: 'Error fetching DKIM record',
      dmarc: 'Error fetching DMARC record',
      summary: 'Error fetching authentication details',
    };
  }
}