const { Pool } = require('pg');

// Создаем пул соединений с явными параметрами
const pool = new Pool({
    user: process.env.POSTGRES_USER || 'postgres',
    password: process.env.POSTGRES_PASSWORD || 'postgres',
    host: process.env.POSTGRES_HOST || 'postgres',
    port: process.env.POSTGRES_PORT || 5432,
    database: process.env.POSTGRES_DB || 'rossumxml'
});

// Обработчик ошибок подключения
pool.on('error', (err, client) => {
    console.error('Unexpected error on idle client', err);
    process.exit(-1);
});

// Проверяем подключение к базе данных
async function testConnection() {
    try {
        const client = await pool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('Database connection successful');
        return true;
    } catch (err) {
        console.error('Database connection error:', err);
        return false;
    }
}

// Вызываем проверку при запуске
testConnection();

module.exports = {
    /**
     * Выполняет SQL-запрос с параметрами
     * @param {string} text - SQL запрос
     * @param {Array} params - параметры запроса
     */
    query: async function(text, params) {
        const client = await pool.connect();
        try {
            return await client.query(text, params);
        } finally {
            client.release();
        }
    },

    /**
     * Получает клиент из пула для транзакций
     */
    getClient: async function() {
        return await pool.connect();
    },

    /**
     * Инициализирует базу данных
     */
    initDatabase: async function() {
        const client = await pool.connect();
        try {
            const fs = require('fs');
            const path = require('path');
            const initSQL = fs.readFileSync(path.join(__dirname, 'init.sql'), 'utf8');
            
            // Выполняем инициализационный скрипт
            await client.query(initSQL);
            console.log('Database initialized successfully');
        } catch (err) {
            console.error('Error initializing database:', err);
            throw err;
        } finally {
            client.release();
        }
    }
};