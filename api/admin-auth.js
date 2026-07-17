export default function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false });
  }

  const adminPass = process.env.ADMIN_PASS;
  if (!adminPass) return res.status(500).json({ ok: false });

  const pass = typeof req.body === 'string'
    ? JSON.parse(req.body || '{}').pass
    : req.body?.pass;

  if (pass === adminPass) return res.status(200).json({ ok: true });
  return res.status(401).json({ ok: false });
}
