const router = require('express').Router();
const auth = require('../middleware/auth');
const { db } = require('../config/firebase');

/**
 * GET /api/workspaces — List all workspaces
 */
router.get('/', auth, async (req, res) => {
  try {
    const snap = await db.collection('workspaces')
      .where('userId', '==', req.user.uid)
      .get();
    
    const workspaces = snap.docs
      .map(d => ({ id: d.id, ...d.data() }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    
    res.json({ workspaces });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load workspaces' });
  }
});

/**
 * POST /api/workspaces — Create a new workspace
 */
router.post('/', auth, async (req, res) => {
  try {
    const { name, targets } = req.body;
    if (!name) return res.status(400).json({ error: 'Workspace name is required' });

    const ref = await db.collection('workspaces').add({
      userId: req.user.uid,
      name,
      targets: Array.isArray(targets) ? targets : [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    res.json({ id: ref.id, name, targets });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create workspace' });
  }
});

/**
 * PATCH /api/workspaces/:id — Update targets or name
 */
router.patch('/:id', auth, async (req, res) => {
  try {
    const { name, targets } = req.body;
    const ref = db.collection('workspaces').doc(req.params.id);
    const doc = await ref.get();

    if (!doc.exists) return res.status(404).json({ error: 'Workspace not found' });
    if (doc.data().userId !== req.user.uid) return res.status(403).json({ error: 'Forbidden' });

    const updates = { updatedAt: new Date().toISOString() };
    if (name) updates.name = name;
    if (targets) updates.targets = targets;

    await ref.update(updates);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

/**
 * DELETE /api/workspaces/:id
 */
router.delete('/:id', auth, async (req, res) => {
  try {
    const ref = db.collection('workspaces').doc(req.params.id);
    const doc = await ref.get();

    if (!doc.exists) return res.status(404).json({ error: 'Workspace not found' });
    if (doc.data().userId !== req.user.uid) return res.status(403).json({ error: 'Forbidden' });

    await ref.delete();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

module.exports = router;
