export default function handler(req, res) {
  const { region = 'ID', count = '1' } = req.query;
  const c = Math.max(1, Math.min(50, parseInt(count, 10) || 1));
  const items = Array.from({ length: c }, (_, i) => ({ id: i + 1, region }));
  res.status(200).json({ ok: true, items });
}
