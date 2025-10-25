const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const invitationService = require('../services/invitation.service');

// Регистрация
router.post('/register', async (req, res) => {
    const { email, fullName, password, enableBilling, billingDetails, invitationToken } = req.body;

    if (!email || !password || !fullName) {
        return res.status(400).json({
            error: 'Необходимо заполнить email, имя и пароль'
        });
    }

    try {
        let invitation = null;
        
        // Validate invitation token if provided
        if (invitationToken) {
            invitation = await invitationService.validateInvitationToken(invitationToken);
            
            if (!invitation) {
                return res.status(400).json({
                    error: 'Недействительный или истекший код приглашения'
                });
            }
            
            // Verify email matches
            if (invitation.email !== email) {
                return res.status(400).json({
                    error: 'Email не совпадает с приглашением',
                    message: `Это приглашение предназначено для ${invitation.email}`
                });
            }
        }
        
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
            
            // If invitation exists, accept it and link to organization
            if (invitation) {
                await invitationService.acceptInvitation(invitationToken, userId);
            }

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
                user: { id: userId, email, username },
                organization_joined: invitation ? invitation.organization_name : null
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

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Get user profile
router.get('/profile', verifyToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                u.id,
                u.email,
                u.username,
                u.full_name,
                u.created_at,
                u.phone,
                u.address,
                u.city,
                u.country,
                u.zip_code,
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
            LEFT JOIN subscriptions s ON s.user_id = u.id
            LEFT JOIN billing_details b ON b.user_id = u.id
            WHERE u.id = $1
        `, [req.userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error fetching user profile:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user profile
router.put('/profile', verifyToken, async (req, res) => {
    const {
        fullName,
        phone,
        address,
        city,
        country,
        zipCode
    } = req.body;

    try {
        const result = await db.query(`
            UPDATE users
            SET 
                full_name = $1,
                phone = $2,
                address = $3,
                city = $4,
                country = $5,
                zip_code = $6,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $7
            RETURNING *
        `, [fullName, phone, address, city, country, zipCode, req.userId]);

        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating user profile:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Change password
router.post('/change-password', verifyToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    try {
        const user = await db.query('SELECT password FROM users WHERE id = $1', [req.userId]);
        const validPassword = await bcrypt.compare(currentPassword, user.rows[0].password);
        
        if (!validPassword) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.userId]);

        res.json({ message: 'Password updated successfully' });
    } catch (err) {
        console.error('Error changing password:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Export handlers for direct invocation
module.exports = {
    post: (path, req, res) => {
        if (path === '/register') {
            return router.post('/register', req, res);
        } else if (path === '/login') {
            return router.post('/login', req, res);
        } else if (path === '/profile') {
            return router.post('/profile', verifyToken, req, res);
        } else if (path === '/change-password') {
            return router.post('/change-password', verifyToken, req, res);
        }
    },
    get: (path, req, res) => {
        if (path === '/profile') {
            return router.get('/profile', verifyToken, req, res);
        }
    },
    put: (path, req, res) => {
        if (path === '/profile') {
            return router.put('/profile', verifyToken, req, res);
        }
    }
};