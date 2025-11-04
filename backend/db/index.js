const { Pool } = require('pg');

// Database connection pool
const pool = new Pool({
    user: process.env.POSTGRES_USER || 'postgres',
    password: process.env.POSTGRES_PASSWORD || 'postgres',
    host: process.env.POSTGRES_HOST || 'localhost',  // Use localhost (port is exposed in docker-compose)
    port: process.env.POSTGRES_PORT || 5432,
    database: process.env.POSTGRES_DB || 'rossumxml'
});

// Override connect to ensure clean transaction state
const originalConnect = pool.connect.bind(pool);
pool.connect = async function() {
    const client = await originalConnect();
    
    // Try to rollback any aborted transaction from previous use
    try {
        await client.query('ROLLBACK');
    } catch (err) {
        // Ignore errors - no transaction may be active
    }
    
    return client;
};

// Helper to safely release client even if transaction is aborted
pool.safeRelease = async (client) => {
    try {
        // Try to rollback any active transaction
        await client.query('ROLLBACK');
    } catch (err) {
        // Ignore rollback errors (transaction may not exist or already rolled back)
    } finally {
        client.release();
    }
};

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