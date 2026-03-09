const express = require('express');
const { body, validationResult } = require('express-validator');
const { pool } = require('../db/pool');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/asyncHandler');

const router = express.Router();

/**
 * POST /api/v1/investments/proportion
 * Body: { proportions: [ { assetId, percentage }, ... ] }
 * Sum of percentages must be 100. Asset IDs must exist in assets table.
 */
router.post(
  '/proportion',
  requireAuth(),
  [
    body('proportions')
      .isArray({ min: 1 })
      .withMessage('Proportions array is required'),
    body('proportions.*.assetId').isString().trim().notEmpty(),
    body('proportions.*.percentage').isFloat({ min: 0, max: 100 }),
  ],
  asyncHandler(async (req, res) => {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      return res.status(400).json({
        status: 'error',
        message: errs.array().map((e) => e.msg).join('; '),
      });
    }

    const { proportions } = req.body;
    const total = proportions.reduce((sum, p) => sum + Number(p.percentage), 0);
    if (Math.abs(total - 100) > 0.01) {
      return res.status(400).json({
        status: 'error',
        message: 'Total proportion must sum up to exactly 100%',
      });
    }

    const userId = req.user.userId;
    const client = await pool.connect();
    try {
      const assetIds = [...new Set(proportions.map((p) => p.assetId))];
      const placeholders = assetIds.map(() => '?').join(',');
      const assetCheck = await client.query(
        `SELECT asset_id FROM assets WHERE asset_id IN (${placeholders})`,
        assetIds
      );
      const validIds = new Set(assetCheck.rows.map((r) => r.asset_id));
      const invalid = assetIds.filter((id) => !validIds.has(id));
      if (invalid.length > 0) {
        return res.status(422).json({
          status: 'error',
          message: `Asset '${invalid[0]}' does not exist in our portfolio.`,
        });
      }

      await client.query('DELETE FROM user_investments_proportion WHERE user_id = ?', [userId]);
      for (const p of proportions) {
        await client.query(
          `INSERT INTO user_investments_proportion (user_id, asset_id, percentage, updated_at)
           VALUES (?, ?, ?, NOW())`,
          [userId, p.assetId, p.percentage]
        );
      }

      return res.status(200).json({
        status: 'success',
        message: 'Investment proportions updated successfully',
        data: {
          updatedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
          totalAllocation: 100,
        },
      });
    } finally {
      client.release();
    }
  })
);

module.exports = router;
