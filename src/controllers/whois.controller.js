import fetch from 'node-fetch';

export async function getWhoisData(req, res) {
  const { domain } = req.params;
  const whoisApiUrl = `http://localhost:8081/${domain}`; // Updated to use port 8081

  try {
    const response = await fetch(whoisApiUrl);
    if (!response.ok) {
      return res.status(response.status).json({ error: response.statusText });
    }
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Error fetching WHOIS data:', error);
    res.status(500).json({ error: 'Error fetching WHOIS data' });
  }
}