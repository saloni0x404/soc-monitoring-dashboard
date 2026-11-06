const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Incident = sequelize.define('Incident', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  title: { type: DataTypes.STRING, allowNull: false },
  description: { type: DataTypes.TEXT, allowNull: true },
  severity: { type: DataTypes.ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'), allowNull: false },
  status: {
    type: DataTypes.ENUM('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'),
    allowNull: false,
    defaultValue: 'OPEN',
  },
  assigned_to: { type: DataTypes.STRING, allowNull: true },
  notes: { type: DataTypes.TEXT, allowNull: true },
  resolution: { type: DataTypes.TEXT, allowNull: true },
  related_alert_ids: { type: DataTypes.TEXT, allowNull: true },
}, {
  tableName: 'incidents',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
});

module.exports = Incident;
