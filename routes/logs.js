const express = require('express');
const { Op } = require('sequelize');
const { Log } = require('../models');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const PAGE_SIZE = 25;

router.get('/logs', requireAuth, async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const { search, severity, source, dateFrom, dateTo } = req.query;

    const where = {};

    if (severity) where.severity = severity;
    if (source) where.source = source;

    if (dateFrom || dateTo) {
      where.timestamp = {};
      if (dateFrom) where.timestamp[Op.gte] = new Date(dateFrom);
      if (dateTo) where.timestamp[Op.lte] = new Date(dateTo);
    }

    if (search) {
      where[Op.or] = [
        { message: { [Op.like]: `%${search}%` } },
        { source_ip: { [Op.like]: `%${search}%` } },
        { hostname: { [Op.like]: `%${search}%` } },
        { username: { [Op.like]: `%${search}%` } },
        { event_type: { [Op.like]: `%${search}%` } },
      ];
    }

    const { rows: logs, count: total } = await Log.findAndCountAll({
      where,
      order: [['timestamp', 'DESC']],
      limit: PAGE_SIZE,
      offset: (page - 1) * PAGE_SIZE,
    });

    const totalPages = Math.max(Math.ceil(total / PAGE_SIZE), 1);

    res.render('logs', {
      title: 'Logs',
      logs,
      total,
      page,
      totalPages,
      filters: { search: search || '', severity: severity || '', source: source || '', dateFrom: dateFrom || '', dateTo: dateTo || '' },
    });
  } catch (err) {
    console.error('Logs page error:', err);
    res.status(500).render('error', {
      title: 'Server Error',
      message: 'Could not load logs.',
      user: req.session.user,
    });
  }
});

module.exports = router;
