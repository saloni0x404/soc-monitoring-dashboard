const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Rule = sequelize.define('Rule', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  name: {
    // machine key, e.g. "brute-force" - matches rules/*.json filenames
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  title: {
    // human-readable, e.g. "Brute Force Attack"
    type: DataTypes.STRING,
    allowNull: false,
  },
  description: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  severity: {
    type: DataTypes.ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
    allowNull: false,
  },
  enabled: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true,
  },
  rule_type: {
    // 'threshold' (needs counting over time) or 'immediate' (single event match)
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'immediate',
  },
  mitre_id: {
    type: DataTypes.STRING,
    allowNull: true,
  },
}, {
  tableName: 'rules',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

module.exports = Rule;
