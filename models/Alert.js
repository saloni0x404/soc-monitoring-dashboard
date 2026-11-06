const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Alert = sequelize.define('Alert', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  title: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  severity: {
    type: DataTypes.ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
    allowNull: false,
  },
  risk_score: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
  },
  source_ip: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  hostname: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  rule_name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  mitre_id: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  status: {
    type: DataTypes.ENUM('NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'),
    allowNull: false,
    defaultValue: 'NEW',
  },
  // JSON-stringified array of related Log ids, used for the alert detail
  // "Evidence" view. Kept simple (no join table) per the "avoid
  // over-engineering" brief - can be normalized later if needed.
  related_log_ids: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  risk_explanation: {
    // human-readable breakdown of how the risk_score was calculated
    type: DataTypes.TEXT,
    allowNull: true,
  },
}, {
  tableName: 'alerts',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  indexes: [
    { fields: ['severity'] },
    { fields: ['status'] },
    { fields: ['source_ip'] },
  ],
});

module.exports = Alert;
