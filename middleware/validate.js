/**
 * Input validation middleware for OSINT queries.
 */
function validate(req, res, next) {
  const { query } = req.body;

  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'Query is required and must be a string' });
  }

  const trimmed = query.trim();
  if (trimmed.length < 2 || trimmed.length > 255) {
    return res.status(400).json({ error: 'Query must be between 2 and 255 characters' });
  }

  // Sanitize — strip any HTML/script tags
  const sanitized = trimmed.replace(/<[^>]*>/g, '').replace(/[<>]/g, '');
  req.body.query = sanitized;

  next();
}

module.exports = validate;
