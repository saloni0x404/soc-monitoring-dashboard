const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const ThreatIntel = sequelize.define('ThreatIntel', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  indicator: { type: DataTypes.STRING, allowNull: false },
  indicator_type: { type: DataTypes.ENUM('IP', 'DOMAIN', 'HASH'), allowNull: false },
  reputation: {
    type: DataTypes.ENUM('MALICIOUS', 'SUSPICIOUS', 'CLEAN', 'UNKNOWN'),
    allowNull: false,
    defaultValue: 'UNKNOWN',
  },
  country: { type: DataTypes.STRING, allowNull: true },
  provider: { type: DataTypes.STRING, allowNull: true },
  details: { type: DataTypes.TEXT, allowNull: true },
  checked_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
}, {
  tableName: 'threat_intel',
  timestamps: false,
  indexes: [{ fields: ['indicator'] }],
});

module.exports = ThreatIntel;
