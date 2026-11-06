const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Log = sequelize.define('Log', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  timestamp: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW,
  },
  source: {
    // e.g. Windows, Linux, Firewall, Web Server
    type: DataTypes.STRING,
    allowNull: false,
  },
  event_type: {
    // e.g. FAILED_LOGIN, PORT_SCAN, POWERSHELL, PRIV_ESCALATION, MALWARE, WEB_ATTACK
    type: DataTypes.STRING,
    allowNull: false,
  },
  severity: {
    type: DataTypes.ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'),
    allowNull: false,
    defaultValue: 'INFO',
  },
  username: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  source_ip: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  destination_ip: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  hostname: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  message: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  raw_log: {
    // the "original" unparsed log line - simulated here, real log text in production
    type: DataTypes.TEXT,
    allowNull: true,
  },
}, {
  tableName: 'logs',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
  indexes: [
    { fields: ['source_ip'] },
    { fields: ['event_type'] },
    { fields: ['severity'] },
    { fields: ['timestamp'] },
  ],
});

module.exports = Log;
