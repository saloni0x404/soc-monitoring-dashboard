const express = require('express');
const { Op } = require('sequelize');
const { Asset, AuditLog } = require('../models');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

router.get('/assets', requireAuth, async (req, res) => {
  try {
    const { search } = req.query;
    const where = search
      ? {
          [Op.or]: [
            { hostname: { [Op.like]: `%${search}%` } },
            { ip: { [Op.like]: `%${search}%` } },
            { owner: { [Op.like]: `%${search}%` } },
          ],
        }
      : {};
    const assets = await Asset.findAll({ where, order: [['hostname', 'ASC']] });
    res.render('assets', { title: 'Assets', assets, search: search || '' });
  } catch (err) {
    console.error('Assets page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load assets.', user: req.session.user });
  }
});

router.post('/assets', requireAuth, requireRole('ADMIN', 'ANALYST'), async (req, res) => {
  try {
    const { hostname, ip, operating_system, owner, criticality, status } = req.body;
    if (!hostname) return res.redirect('/assets');

    await Asset.create({
      hostname, ip, operating_system, owner,
      criticality: criticality || 'MEDIUM',
      status: status || 'ACTIVE',
      last_seen: new Date(),
    });

    await AuditLog.create({
      user_id: req.session.user.id, action: 'ASSET_CREATED', target: hostname, ip: req.ip,
    }).catch(() => {});

    res.redirect('/assets');
  } catch (err) {
    console.error('Asset create error:', err);
    res.redirect('/assets');
  }
});

router.post('/assets/:id/delete', requireAuth, requireRole('ADMIN'), async (req, res) => {
  try {
    const asset = await Asset.findByPk(req.params.id);
    if (asset) {
      await AuditLog.create({
        user_id: req.session.user.id, action: 'ASSET_DELETED', target: asset.hostname, ip: req.ip,
      }).catch(() => {});
      await asset.destroy();
    }
    res.redirect('/assets');
  } catch (err) {
    console.error('Asset delete error:', err);
    res.redirect('/assets');
  }
});

module.exports = router;
