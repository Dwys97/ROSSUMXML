const db = require('./index');

async function testDatabaseConnection() {
    try {
        // Проверяем подключение к базе данных
        const result = await db.query('SELECT NOW()');
        console.log('Database connection test successful:', result.rows[0]);

        // Проверяем наличие таблиц
        const tables = await db.query(`
            SELECT tablename 
            FROM pg_catalog.pg_tables 
            WHERE schemaname = 'public'
        `);
        console.log('Available tables:', tables.rows.map(r => r.tablename));

        return true;
    } catch (err) {
        console.error('Database connection test failed:', err);
        return false;
    }
}

testDatabaseConnection()
    .then(success => {
        if (!success) {
            process.exit(1);
        }
    })
    .catch(err => {
        console.error('Error running connection test:', err);
        process.exit(1);
    });