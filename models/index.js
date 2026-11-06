const sequelize = require('../config/database');
const User = require('./User');
const AuditLog = require('./AuditLog');
const Log = require('./Log');
const Rule = require('./Rule');
const Alert = require('./Alert');
const Incident = require('./Incident');
const Asset = require('./Asset');
const ThreatIntel = require('./ThreatIntel');

AuditLog.belongsTo(User, { foreignKey: 'user_id', as: 'user' });

module.exports = {
  sequelize, User, AuditLog, Log, Rule, Alert, Incident, Asset, ThreatIntel,
};
