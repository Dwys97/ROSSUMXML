const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const db = require('../db');

const userService = {
    async getProfile(userId) {
        const result = await db.query(
            `SELECT 
                u.id, u.username, u.email, u.created_at,
                s.status as subscription_status,
                s.level as subscription_level,
                s.expires_at as subscription_expires,
                b.card_last4,
                b.card_brand,
                b.billing_address,
                b.billing_city,
                b.billing_country,
                b.billing_zip
            FROM users u
            LEFT JOIN subscriptions s ON u.id = s.user_id
            LEFT JOIN billing_details b ON u.id = b.user_id
            WHERE u.id = $1`,
            [userId]
        );
        return result.rows[0];
    },

    async updateBillingDetails(userId, billingData) {
        const {
            cardNumber,
            cardExpiry,
            cardCvv,
            billingAddress,
            billingCity,
            billingCountry,
            billingZip
        } = billingData;

        // В реальном проекте здесь была бы интеграция с платежной системой
        const last4 = cardNumber.slice(-4);
        const cardBrand = this.detectCardBrand(cardNumber);

        await db.query(
            `INSERT INTO billing_details (
                user_id, card_last4, card_brand,
                billing_address, billing_city, billing_country, billing_zip
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (user_id) DO UPDATE SET
                card_last4 = $2,
                card_brand = $3,
                billing_address = $4,
                billing_city = $5,
                billing_country = $6,
                billing_zip = $7`,
            [userId, last4, cardBrand, billingAddress, billingCity, billingCountry, billingZip]
        );

        return { success: true };
    },

    async changePassword(userId, { currentPassword, newPassword }) {
        // Проверяем текущий пароль
        const { rows } = await db.query('SELECT password FROM users WHERE id = $1', [userId]);
        if (!rows.length) throw new Error('User not found');

        const isValid = await bcrypt.compare(currentPassword, rows[0].password);
        if (!isValid) throw new Error('Current password is incorrect');

        // Хэшируем и сохраняем новый пароль
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query(
            'UPDATE users SET password = $1 WHERE id = $2',
            [hashedPassword, userId]
        );

        return { success: true };
    },

    detectCardBrand(cardNumber) {
        // Простая проверка бренда карты по первым цифрам
        if (cardNumber.startsWith('4')) return 'visa';
        if (/^5[1-5]/.test(cardNumber)) return 'mastercard';
        if (/^3[47]/.test(cardNumber)) return 'amex';
        return 'unknown';
    }
};

module.exports = userService;