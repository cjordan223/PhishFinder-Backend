// src/controllers/dns.controller.js
export const getDNSRecords = async (req, res) => {
  const { domain } = req.params;
  logger.info(`Fetching DNS records for domain: ${domain}`);
  
  try {
    const db = await connectDB();
    
    // First check if we have recent records (less than 24h old)
    const existingAuth = await db.collection('domain_authentication').findOne({
      domain,
      createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });

    if (existingAuth) {
      return res.json(existingAuth.authentication);
    }

    // If not, fetch new records
    const dnsRecords = await getEmailAuthenticationDetails(domain);
    
    // Save to domain_authentication collection
    await db.collection('domain_authentication').updateOne(
      { domain },
      { 
        $set: {
          authentication: {
            spf: {
              record: dnsRecords.spf,
              status: dnsRecords.summary.includes('SPF: Pass') ? 'pass' : 'fail'
            },
            dkim: {
              record: dnsRecords.dkim,
              status: dnsRecords.summary.includes('DKIM: Pass') ? 'pass' : 'fail'  
            },
            dmarc: {
              record: dnsRecords.dmarc,
              policy: dnsRecords.dmarc.includes('p=reject') ? 'reject' : 
                     dnsRecords.dmarc.includes('p=quarantine') ? 'quarantine' : 'none'
            },
            summary: dnsRecords.summary,
            lastUpdated: new Date()
          },
          createdAt: new Date()
        }
      },
      { upsert: true }
    );

    logger.info(`Saved authentication records for domain: ${domain}`);
    res.json(dnsRecords);

  } catch (error) {
    logger.error('Error fetching DNS records:', error);
    res.status(500).json({ error: 'Error fetching DNS records' });
  }
};