const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Asset = sequelize.define('Asset', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  hostname: { type: DataTypes.STRING, allowNull: false, unique: true },
  ip: { type: DataTypes.STRING, allowNull: true },
  operating_system: { type: DataTypes.STRING, allowNull: true },
  owner: { type: DataTypes.STRING, allowNull: true },
  criticality: {
    type: DataTypes.ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
    allowNull: false,
    defaultValue: 'MEDIUM',
  },
  status: {
    type: DataTypes.ENUM('ACTIVE', 'INACTIVE', 'DECOMMISSIONED'),
    allowNull: false,
    defaultValue: 'ACTIVE',
  },
  last_seen: { type: DataTypes.DATE, allowNull: true },
}, {
  tableName: 'assets',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
});

module.exports = Asset;
