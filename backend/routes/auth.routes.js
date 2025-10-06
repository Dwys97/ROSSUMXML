const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');

// Регистрация
router.post('/register', async (req, res) => {
    const { email, fullName, password, enableBilling, billingDetails } = req.body;

    if (!email || !password || !fullName) {
        return res.status(400).json({
            error: 'Необходимо заполнить email, имя и пароль'
        });
    }

    try {
        // Создаем имя пользователя из email
        const username = email.split('@')[0];
        
        // Начинаем транзакцию
        const client = await db.getClient();
        
        try {
            await client.query('BEGIN');

            // Проверяем существование пользователя
            const userExists = await client.query(
                'SELECT id FROM users WHERE email = $1 OR username = $2',
                [email, username]
            );

            if (userExists.rows.length > 0) {
                throw new Error('Пользователь с таким email или именем уже существует');
            }

            // Хэшируем пароль
            const hashedPassword = await bcrypt.hash(password, 10);

            // Создаем пользователя
            const userResult = await client.query(
                `INSERT INTO users (email, username, full_name, password)
                VALUES ($1, $2, $3, $4)
                RETURNING id`,
                [email, username, fullName, hashedPassword]
            );

            const userId = userResult.rows[0].id;

            // Создаем начальную подписку (бесплатную)
            await client.query(
                `INSERT INTO subscriptions (user_id, status, level)
                VALUES ($1, 'active', 'free')`,
                [userId]
            );

            // Если есть платежные данные, сохраняем их
            if (enableBilling && billingDetails) {
                const last4 = billingDetails.cardNumber.slice(-4);
                const cardBrand = detectCardBrand(billingDetails.cardNumber);

                await client.query(
                    `INSERT INTO billing_details (
                        user_id, card_last4, card_brand,
                        billing_address, billing_city,
                        billing_country, billing_zip
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                    [
                        userId,
                        last4,
                        cardBrand,
                        billingDetails.address,
                        billingDetails.city,
                        billingDetails.country || 'RU',
                        billingDetails.zip
                    ]
                );
            }

            await client.query('COMMIT');
            
            res.status(201).json({
                message: 'Регистрация успешна',
                user: { id: userId, email, username }
            });

        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('Registration error:', err);
        
        // Определяем тип ошибки
        if (err.code === '23505') {
            // Нарушение уникальности (duplicate key)
            return res.status(409).json({
                error: 'Пользователь с таким email уже существует'
            });
        } else if (err.code === '23503') {
            // Нарушение foreign key
            return res.status(400).json({
                error: 'Ошибка при создании связанных данных'
            });
        } else if (err.message) {
            return res.status(400).json({
                error: err.message
            });
        } else {
            // Все остальные ошибки логируем детально, но пользователю отправляем общее сообщение
            console.error('Detailed error:', err);
            return res.status(500).json({
                error: 'Внутренняя ошибка сервера. Пожалуйста, попробуйте позже.'
            });
        }
    }
});

// Вход
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Ищем пользователя
        const result = await db.query(
            'SELECT id, email, username, password FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            throw new Error('Пользователь не найден');
        }

        const user = result.rows[0];

        // Проверяем пароль
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            throw new Error('Неверный пароль');
        }

        // Создаем JWT токен
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Вход успешен',
            token,
            user: {
                id: user.id,
                email: user.email,
                username: user.username
            }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(400).json({
            error: err.message || 'Ошибка при входе'
        });
    }
});

// Определение бренда карты
function detectCardBrand(cardNumber) {
    const patterns = {
        visa: /^4/,
        mastercard: /^5[1-5]/,
        amex: /^3[47]/,
        discover: /^6/
    };

    for (const [brand, pattern] of Object.entries(patterns)) {
        if (pattern.test(cardNumber)) {
            return brand;
        }
    }

    return 'unknown';
}

// Экспортируем отдельные обработчики для возможности прямого вызова
module.exports = {
    post: (path, req, res) => {
        if (path === '/register') {
            return router.post('/register', req, res);
        } else if (path === '/login') {
            return router.post('/login', req, res);
        }
    }
};