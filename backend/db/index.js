const { Pool } = require('pg');

// Database connection pool
const pool = new Pool({
    user: process.env.POSTGRES_USER || 'postgres',
    password: process.env.POSTGRES_PASSWORD || 'postgres',
    host: process.env.POSTGRES_HOST || 'localhost',  // Use localhost (port is exposed in docker-compose)
    port: process.env.POSTGRES_PORT || 5432,
    database: process.env.POSTGRES_DB || 'rossumxml'
});

// Handle client errors to prevent aborted transactions
pool.on('connect', (client) => {
    const originalQuery = client.query.bind(client);
    client.query = function(...args) {
        return originalQuery(...args).catch(err => {
            // On any query error, ensure we rollback
            if (err.code === '25P02') {
                // Transaction is aborted, rollback silently
                originalQuery('ROLLBACK').catch(() => {});
            }
            throw err;
        });
    };
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

// Функция для повторных попыток подключения
async function waitForDatabase(retries = 5, delay = 2000) {
    for (let i = 0; i < retries; i++) {
        if (await testConnection()) {
            return true;
        }
        console.log(`Attempt ${i + 1} failed, retrying in ${delay/1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, delay));
    }
    throw new Error('Failed to connect to database after multiple attempts');
}

// Вызываем проверку при запуске с повторными попытками
waitForDatabase();

// Экспортируем сам пул и дополнительные методы
module.exports = pool;