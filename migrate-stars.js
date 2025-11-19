// migrate-stars.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
    // Tabela de ratings (estrelas)
    db.run(`CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        stars INTEGER CHECK(stars >= 1 AND stars <= 5) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(image_id, user_id),
        FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
    )`);

    // Colunas na tabela images para performance
    db.run(`ALTER TABLE images ADD COLUMN total_stars INTEGER DEFAULT 0`, () => {});
    db.run(`ALTER TABLE images ADD COLUMN rating_count INTEGER DEFAULT 0`, () => {});
    db.run(`ALTER TABLE images ADD COLUMN avg_rating REAL DEFAULT 0`, () => {});
});

db.close(() => {
    console.log('MIGRAÇÃO DE ESTRELAS CONCLUÍDA – 1 A 5 ESTRELAS POR UTILIZADOR');
    console.log('AGORA CADA IMAGEM TEM CLASSIFICAÇÃO – TU DECIDES A BELEZA');
});