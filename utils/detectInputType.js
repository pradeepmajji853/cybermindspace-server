function detectInputType(query) {
  const q = query.trim();
  if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(q)) return 'email';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(q)) return 'ip';
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?$/.test(q)) return 'domain';
  return 'username';
}

module.exports = detectInputType;
