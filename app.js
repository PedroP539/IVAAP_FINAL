const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const axios = require('axios');

const app = express();
const PORT = 3000;

fs.mkdirSync('./public/uploads', { recursive: true });

// ABRE A DB ASSINCRONAMENTE  NÃO BLOQUEIA O START DO SERVIDOR
const db = new sqlite3.Database('./database.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('ERRO FATAL AO ABRIR DATABASE:', err.message);
        process.exit(1);
    } else {
        console.log('Database conectada.');
    }
});

// CRIA TABELAS E ADMIN ASSINCRONAMENTE (não bloqueia o app.listen)
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        nome TEXT,
        apelido TEXT,
        cargo TEXT,
        email TEXT,
        telefone TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_url TEXT NOT NULL,
        species TEXT,
        variety TEXT,
        botanical_name TEXT,
        origem TEXT,
        colheitaFloracao TEXT,
        exposicaoSolar TEXT,
        rega TEXT,
        profundidadeSementeira TEXT,
        sementeiraDireta INTEGER DEFAULT 0,
        sementeiraAlfobre INTEGER DEFAULT 0,
        sementeira TEXT,
        transplante TEXT,
        compasso TEXT,
        caracteristicas TEXT,
        conselhos_de_cultivo TEXT,
        shutterstock INTEGER DEFAULT 0,
        shutterstock_info TEXT,
        comentarios TEXT,
        status TEXT DEFAULT 'pending',
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        uploaded_by TEXT,
        reviewed_at DATETIME,
        reviewed_by TEXT,
        total_stars INTEGER DEFAULT 0,
        rating_count INTEGER DEFAULT 0,
        avg_rating REAL DEFAULT 0,
        gama_id INTEGER,
        marca_id INTEGER,
        approvals INTEGER DEFAULT 0,
        rejections INTEGER DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS marcas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT UNIQUE NOT NULL
    )`);
    const marcas = ['Flora Lusitana', 'Jardinflora', 'Planto'];
    marcas.forEach(marca => {
        db.run(`INSERT OR IGNORE INTO marcas (nome) VALUES (?)`, [marca]);
    });
    db.run(`CREATE TABLE IF NOT EXISTS ratings (
        image_id INTEGER,
        user_id INTEGER,
        stars INTEGER NOT NULL,
        PRIMARY KEY (image_id, user_id),
        FOREIGN KEY (image_id) REFERENCES images (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);
    // CRIA ADMIN SÓ SE NÃO EXISTIR (bcrypt só roda se necessário)
    db.get('SELECT id FROM users WHERE username = "admin"', (err, row) => {
        if (!row) {
            bcrypt.hash('flora2025', 10, (err, hash) => {
                if (err) return console.error('ERRO AO GERAR HASH ADMIN:', err);
                db.run(`INSERT INTO users (username, password, nome, apelido, cargo, email, telefone)
                        VALUES ('admin', ?, 'Admin', 'IVAAP', 'Administrador', 'admin@ivaap.pt', '912345678')`, [hash], (err) => {
                    if (err) console.error('ERRO AO INSERIR ADMIN:', err);
                    else console.log('ADMIN CRIADO ? admin / flora2025');
                });
            });
        }
    });
    db.run(`ALTER TABLE users ADD COLUMN nome TEXT`, () => { });
    db.run(`ALTER TABLE users ADD COLUMN apelido TEXT`, () => { });
    db.run(`ALTER TABLE users ADD COLUMN cargo TEXT`, () => { });
    db.run(`ALTER TABLE users ADD COLUMN email TEXT`, () => { });
    db.run(`ALTER TABLE users ADD COLUMN telefone TEXT`, () => { });
    db.run(`ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP`, () => { });
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + ext);
    }
});
const upload = multer({ storage });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'ivaap2025',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24h
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy((username, password, done) => {
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) return done(err);
        if (!user) return done(null, false, { message: 'Utilizador não encontrado' });
        bcrypt.compare(password, user.password, (err, isValid) => {
            if (err) return done(err);
            if (isValid) return done(null, user);
            return done(null, false, { message: 'Password incorreta' });
        });
    });
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    db.get('SELECT id, username, nome, apelido, cargo, email, telefone FROM users WHERE id = ?', [id], (err, user) => {
        done(err, user);
    });
});

app.use((req, res, next) => {
    res.locals.user = req.user || null;
    res.locals.error = req.flash('error')[0] || null;
    res.locals.success = req.flash('success')[0] || null;
    next();
});

app.use((req, res, next) => {
    req.clientIP = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
        req.headers['cf-connecting-ip'] ||
        req.headers['x-real-ip'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        req.ip ||
        'Desconhecido';
    next();
});

const ensureAuth = (req, res, next) => req.user ? next() : res.redirect('/login');

app.get('/register', (req, res) => {
    res.render('register', {
        error: req.flash('error')[0] || null,
        success: req.flash('success')[0] || null
    });
});

app.post('/register', async (req, res) => {
    const { username, password, nome, apelido, cargo, email, telefone } = req.body;
    if (!username || !password || !nome || !apelido) {
        req.flash('error', 'Preenche todos os campos obrigatórios!');
        return res.redirect('/register');
    }
    if (password.length < 6) {
        req.flash('error', 'A password deve ter pelo menos 6 caracteres!');
        return res.redirect('/register');
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        req.flash('error', 'O utilizador só pode ter letras, números e underscores!');
        return res.redirect('/register');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO users (username, password, nome, apelido, cargo, email, telefone)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [username, hashedPassword, nome, apelido, cargo || '', email || '', telefone || ''],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        req.flash('error', 'Este utilizador já existe!');
                    } else {
                        console.error('ERRO NO REGISTO:', err);
                        req.flash('error', 'Erro ao criar conta. Tenta novamente.');
                    }
                    return res.redirect('/register');
                }
                req.flash('success', `Conta criada com sucesso, ${nome}! Agora faz login.`);
                res.redirect('/login');
            }
        );
    } catch (err) {
        console.error('ERRO CRÍTICO:', err);
        req.flash('error', 'Erro interno. Tenta mais tarde.');
        res.redirect('/register');
    }
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', passport.authenticate('local', {
    successRedirect: '/statistics',
    failureRedirect: '/login',
    failureFlash: 'Credenciais erradas'
}));

app.get('/logout', (req, res) => { req.logout(() => res.redirect('/login')); });

app.get('/', (req, res) => res.redirect(req.user ? '/statistics' : '/login'));

function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

app.get('/statistics', ensureAuth, async (req, res) => {
    const clientIP = req.clientIP;
    const isAdmin = req.user.cargo === 'Administrador';
    try {
        const userStatsQueries = await Promise.all([
            dbGet('SELECT COUNT(*) as count FROM images WHERE uploaded_by = ?', [req.user.username]),
            dbGet('SELECT COUNT(*) as count FROM images WHERE reviewed_by = ?', [req.user.username]),
            dbGet('SELECT COUNT(*) as count FROM images WHERE reviewed_by = ? AND status = "approved"', [req.user.username]),
            dbGet('SELECT COUNT(*) as count FROM images WHERE reviewed_by = ? AND status = "rejected"', [req.user.username]),
            dbGet('SELECT * FROM images WHERE uploaded_by = ? ORDER BY uploaded_at DESC LIMIT 1', [req.user.username]),
            dbGet('SELECT * FROM images WHERE reviewed_by = ? AND status = "approved" ORDER BY reviewed_at DESC LIMIT 1', [req.user.username]),
            dbGet('SELECT * FROM images WHERE reviewed_by = ? AND status = "rejected" ORDER BY reviewed_at DESC LIMIT 1', [req.user.username]),
            dbGet('SELECT * FROM images WHERE uploaded_by = ? AND status = "pending" ORDER BY uploaded_at DESC LIMIT 1', [req.user.username]),
            dbGet('SELECT COUNT(*) as count FROM images WHERE uploaded_by = ? AND status = "pending"', [req.user.username])
        ]);
        const userStats = {
            totalUploaded: userStatsQueries[0]?.count || 0,
            reviewedByUser: userStatsQueries[1]?.count || 0,
            approvedByUser: userStatsQueries[2]?.count || 0,
            rejectedByUser: userStatsQueries[3]?.count || 0,
            userApprovalRate: userStatsQueries[1]?.count > 0
                ? Math.round((userStatsQueries[2]?.count / userStatsQueries[1]?.count) * 100)
                : 0
        };
        const latestUser = {
            uploaded: userStatsQueries[4] || null,
            approved: userStatsQueries[5] || null,
            rejected: userStatsQueries[6] || null,
            pending: userStatsQueries[7] || null
        };
        const userPendingCount = userStatsQueries[8]?.count || 0;
        const userActivity = await new Promise((resolve, reject) => {
            db.all(`
                SELECT id, image_url, species, variety, 'upload' as action, uploaded_at as timestamp
                FROM images WHERE uploaded_by = ?
                UNION ALL
                SELECT id, image_url, species, variety,
                       CASE WHEN status = 'approved' THEN 'approve' ELSE 'reject' END as action,
                       reviewed_at as timestamp
                FROM images WHERE reviewed_by = ?
                ORDER BY timestamp DESC
                LIMIT 10
            `, [req.user.username, req.user.username], (err, rows) => {
                if (err) return reject(err);
                resolve((rows || []).map(row => ({
                    id: row.id,
                    image_url: row.image_url,
                    species: row.species,
                    variety: row.variety || '',
                    action: row.action,
                    timestamp: row.timestamp
                })));
            });
        });
        const globalLatestQueries = await Promise.all([
            dbGet('SELECT * FROM images ORDER BY uploaded_at DESC LIMIT 1'),
            dbGet('SELECT * FROM images WHERE status = "approved" ORDER BY reviewed_at DESC LIMIT 1'),
            dbGet('SELECT * FROM images WHERE status = "rejected" ORDER BY reviewed_at DESC LIMIT 1'),
            dbGet('SELECT COUNT(*) as count FROM images WHERE status = "pending"')
        ]);
        const latestImages = {
            uploaded: globalLatestQueries[0] || null,
            approved: globalLatestQueries[1] || null,
            rejected: globalLatestQueries[2] || null
        };
        const globalPendingCount = globalLatestQueries[3]?.count || 0;

        const newMetricsQueries = await Promise.all([
            dbGet('SELECT * FROM images WHERE status = "pending" ORDER BY approvals DESC, uploaded_at ASC LIMIT 1'),
            dbGet('SELECT * FROM images WHERE status = "pending" ORDER BY rejections DESC, uploaded_at ASC LIMIT 1'),
            dbGet('SELECT * FROM images WHERE uploaded_by = ? ORDER BY approvals DESC, uploaded_at ASC LIMIT 1', [req.user.username]),
            dbGet('SELECT * FROM images WHERE uploaded_by = ? ORDER BY rejections DESC, uploaded_at ASC LIMIT 1', [req.user.username])
        ]);
        const newMetrics = {
            globalPendingVoted: newMetricsQueries[0] || null,
            globalPendingRejected: newMetricsQueries[1] || null,
            userMostVoted: newMetricsQueries[2] || null,
            userMostRejected: newMetricsQueries[3] || null
        };

        if (isAdmin) {
            const globalQueries = await Promise.all([
                dbGet('SELECT COUNT(*) as count FROM images'),
                dbGet('SELECT COUNT(*) as count FROM images WHERE status = "approved"'),
                dbGet('SELECT COUNT(*) as count FROM images WHERE status = "rejected"'),
                dbGet('SELECT COUNT(*) as count FROM images WHERE status = "pending"'),
                dbGet('SELECT uploaded_by as user, COUNT(*) as count FROM images GROUP BY uploaded_by ORDER BY count DESC LIMIT 1'),
                dbGet('SELECT reviewed_by as user, COUNT(*) as count FROM images WHERE status = "approved" AND reviewed_by IS NOT NULL GROUP BY reviewed_by ORDER BY count DESC LIMIT 1'),
                dbGet('SELECT reviewed_by as user, COUNT(*) as count FROM images WHERE status = "rejected" AND reviewed_by IS NOT NULL GROUP BY reviewed_by ORDER BY count DESC LIMIT 1'),
                dbGet('SELECT uploaded_by as user, COUNT(*) as count FROM images WHERE comentarios IS NOT NULL AND comentarios != "" GROUP BY uploaded_by ORDER BY count DESC LIMIT 1'),

            ]);
            const globalStats = {
                total: globalQueries[0]?.count || 0,
                approved: globalQueries[1]?.count || 0,
                rejected: globalQueries[2]?.count || 0,
                pending: globalQueries[3]?.count || 0,
                latestImages,
                topUsers: {
                    uploads: globalQueries[4] ? { user: globalQueries[4].user || 'Ninguém', count: globalQueries[4].count } : { user: 'Ninguém', count: 0 },
                    approvals: globalQueries[5] ? { user: globalQueries[5].user || 'Ninguém', count: globalQueries[5].count } : { user: 'Ninguém', count: 0 },
                    rejections: globalQueries[6] ? { user: globalQueries[6].user || 'Ninguém', count: globalQueries[6].count } : { user: 'Ninguém', count: 0 },
                    comments: globalQueries[7] ? { user: globalQueries[7].user || 'Ninguém', count: globalQueries[7].count } : { user: 'Ninguém', count: 0 }
                },

            };
            return res.render('statistics', {
                stats: globalStats,
                userStats,
                latestUser,
                latestImages,
                userActivity, newMetrics,
                userPendingCount: globalPendingCount,
                user: req.user,
                clientIP,
                isAdmin: true,
                success: req.flash('success')[0] || null
            });
        }
        res.render('statistics', {
            stats: {
                total: userStats.totalUploaded,
                approved: userStats.approvedByUser,
                rejected: userStats.rejectedByUser,
                pending: 0,
                latestImages,
                topUsers: {},

            },
            userStats,
            latestUser,
            latestImages,
            userActivity, newMetrics,
            userPendingCount,
            user: req.user,
            clientIP,
            isAdmin: false,
            success: req.flash('success')[0] || null
        });
    } catch (err) {
        console.error('ERRO CRÍTICO NAS ESTATÍSTICAS:', err);
        req.flash('error', 'Erro ao carregar estatísticas. Tenta novamente.');
        res.redirect('/statistics');
    }
});

app.get('/upload', ensureAuth, (req, res) => {
    db.all('SELECT id, nome FROM marcas ORDER BY id', [], (err, marcas) => {
        if (err) {
            console.error('Erro ao carregar marcas:', err);
            marcas = [];
        }
        db.all('SELECT id, nome FROM gamas ORDER BY nome', [], (err, gamas) => {
            if (err) {
                console.error('Erro ao carregar gamas:', err);
                gamas = [];
            }
            res.render('upload', { marcas, gamas });
        });
    });
});

app.post('/upload', ensureAuth, upload.fields([
    { name: 'image0', maxCount: 1 },
    { name: 'image1', maxCount: 1 },
    { name: 'image2', maxCount: 1 }
]), async (req, res) => {
    try {
        const hasImage =
            (req.files['image0'] && req.files['image0'].length) ||
            (req.body.imageFromUrl0 && req.body.imageFromUrl0.trim()) ||
            (req.files['image1'] && req.files['image1'].length) ||
            (req.body.imageFromUrl1 && req.body.imageFromUrl1.trim()) ||
            (req.files['image2'] && req.files['image2'].length) ||
            (req.body.imageFromUrl2 && req.body.imageFromUrl2.trim());
        if (!hasImage) {
            req.flash('error', 'Carrega pelo menos uma imagem!');
            return res.redirect('/upload');
        }
        const commonData = {
            species: req.body.species,
            variety: req.body.variety,
            botanical_name: req.body.botanical_name,
            origem: req.body.origem,
            colheitaFloracao: req.body.colheitaFloracao,
            exposicaoSolar: req.body.exposicaoSolar,
            rega: req.body.rega,
            profundidadeSementeira: req.body.profundidadeSementeira,
            sementeiraDireta: req.body.sementeiraDireta ? 1 : 0,
            sementeiraAlfobre: req.body.sementeiraAlfobre ? 1 : 0,
            sementeira: req.body.sementeira,
            transplante: req.body.transplante,
            compasso: req.body.compasso,
            caracteristicas: req.body.caracteristicas,
            conselhos_de_cultivo: req.body.conselhos_de_cultivo,
            uploaded_by: req.user.username
        };
        let uploadedCount = 0;
        const insertImage = async (filename, marca_id, shutterstock, shutterstock_info) => {
            if (!filename) return;
            return new Promise((resolve, reject) => {
                db.run(`INSERT INTO images (
                    image_url, species, variety, botanical_name, origem, colheitaFloracao,
                    exposicaoSolar, rega, profundidadeSementeira, sementeiraDireta, sementeiraAlfobre,
                    sementeira, transplante, compasso, caracteristicas, conselhos_de_cultivo,
                    shutterstock, shutterstock_info, comentarios, uploaded_by, marca_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        filename, commonData.species, commonData.variety, commonData.botanical_name,
                        commonData.origem, commonData.colheitaFloracao, commonData.exposicaoSolar, commonData.rega,
                        commonData.profundidadeSementeira, commonData.sementeiraDireta, commonData.sementeiraAlfobre,
                        commonData.sementeira, commonData.transplante, commonData.compasso,
                        commonData.caracteristicas, commonData.conselhos_de_cultivo,
                        shutterstock ? 1 : 0, shutterstock_info || '', commonData.comentarios || '',
                        commonData.uploaded_by, marca_id
                    ], function (err) {
                        if (err) {
                            console.error('Erro ao inserir imagem:', err);
                            return reject(err);
                        }
                        uploadedCount++;
                        resolve();
                    });
            });
        };
        const tasks = [];
        for (let i = 0; i < 3; i++) {
            let filename = null;
            if (req.files[`image${i}`] && req.files[`image${i}`].length) {
                filename = req.files[`image${i}`][0].filename;
            }
            else if (req.body[`imageFromUrl${i}`] && req.body[`imageFromUrl${i}`].trim()) {
                const url = req.body[`imageFromUrl${i}`].trim();
                try {
                    const response = await axios({ url, method: 'GET', responseType: 'stream', timeout: 20000 });
                    filename = `url_${Date.now()}_${Math.random().toString(36).substr(2, 9)}_${i}.jpg`;
                    const filePath = path.join('public/uploads', filename);
                    const writer = fs.createWriteStream(filePath);
                    response.data.pipe(writer);
                    await new Promise((resolve, reject) => {
                        writer.on('finish', resolve);
                        writer.on('error', reject);
                    });
                } catch (err) {
                    console.error(`Erro ao baixar imagem da marca ${i}:`, err.message);
                }
            }
            const shutterstock = req.body[`shutterstock${i}`] === 'on';
            const shutterstock_info = req.body[`shutterstock_info${i}`] || '';
            tasks.push(insertImage(filename, i + 1, shutterstock, shutterstock_info));
        }
        await Promise.all(tasks);
        if (uploadedCount === 0) {
            req.flash('error', 'Nenhuma imagem foi carregada com sucesso.');
            return res.redirect('/upload');
        }
        req.flash('success', `Carregadas ${uploadedCount} imagem(ns) com sucesso!`);
        res.redirect('/statistics');
    } catch (err) {
        console.error('Erro geral no upload:', err);
        req.flash('error', 'Erro inesperado ao carregar imagens.');
        res.redirect('/upload');
    }
});

app.get('/review', ensureAuth, (req, res) => {
    const uploadedBy = req.query.uploaded_by;
    let whereClause = 'i.status = "pending"';
    let params = [];
    if (uploadedBy) {
        whereClause += ' AND i.uploaded_by = ?';
        params.push(uploadedBy);
    }
    db.all(`
        SELECT
            i.id, i.image_url, i.species, i.variety, i.uploaded_by, i.uploaded_at,
            m.nome AS marca_nome,
            g.nome AS gama_nome,
            i.approvals, i.rejections
        FROM images i
        LEFT JOIN marcas m ON i.marca_id = m.id
        LEFT JOIN gamas g ON i.gama_id = g.id
        WHERE ${whereClause}
        ORDER BY i.uploaded_at DESC
    `, params, (err, rows) => {
        if (err) {
            console.error('Erro na query review:', err);
            req.flash('error', 'Erro ao carregar imagens pendentes');
            return res.render('review', {
                images: [],
                success: req.flash('success')[0] || null
            });
        }

        if (rows.length === 0) {
            return res.render('review', {
                images: [],
                success: req.flash('success')[0] || null
            });
        }

        const groups = {};
        rows.forEach(row => {
            const date = new Date(row.uploaded_at);
            const timeKey = date.toISOString().slice(0, 10);
            const key = `${row.species || ''}|${row.variety || ''}|${row.uploaded_by}|${timeKey}`;

            if (!groups[key]) {
                groups[key] = {
                    species: row.species || 'Sem espécie',
                    variety: row.variety || '',
                    uploaded_by: row.uploaded_by,
                    uploaded_at: row.uploaded_at,
                    gama_nome: row.gama_nome || 'Não definido',
                    images: []
                };
            }

            groups[key].images.push({
                id: row.id,
                image_url: row.image_url,
                marca_nome: row.marca_nome || 'Sem marca',
                approvals: row.approvals || 0,
                rejections: row.rejections || 0
            });
        });

        const groupedImages = Object.values(groups);

        res.render('review', {
            images: groupedImages,
            success: req.flash('success')[0] || null
        });
    });
});

app.get('/approved', ensureAuth, (req, res) => {
    const reviewedBy = req.query.reviewed_by;
    let whereClause = 'i.status = "approved"';
    let params = [];
    if (reviewedBy) {
        whereClause += ' AND i.reviewed_by = ?';
        params.push(reviewedBy);
    }
    db.all(`
        SELECT
            i.id,
            i.species,
            i.variety,
            i.gama_id,
            g.nome AS gama_nome,
            i.reviewed_by,
            i.reviewed_at,
            i.uploaded_at,
            i.uploaded_by,
            w.image_url AS winning_image_url,
            w.id AS winning_id
        FROM images i
        LEFT JOIN gamas g ON i.gama_id = g.id
        INNER JOIN (
            SELECT
                species,
                variety,
                uploaded_by,
                strftime('%Y-%m-%d', uploaded_at) AS upload_day,
                MAX(approvals) AS max_approvals
            FROM images
            WHERE status = 'approved'
            GROUP BY species, variety, uploaded_by, upload_day
        ) max_votes ON i.species = max_votes.species
                   AND (i.variety = max_votes.variety OR (i.variety IS NULL AND max_votes.variety IS NULL))
                   AND i.uploaded_by = max_votes.uploaded_by
                   AND strftime('%Y-%m-%d', i.uploaded_at) = max_votes.upload_day
                   AND i.approvals = max_votes.max_approvals
        LEFT JOIN images w ON w.species = i.species
                          AND (w.variety = i.variety OR (w.variety IS NULL AND i.variety IS NULL))
                          AND w.uploaded_by = i.uploaded_by
                          AND strftime('%Y-%m-%d', w.uploaded_at) = strftime('%Y-%m-%d', i.uploaded_at)
                          AND w.approvals = i.approvals
        WHERE ${whereClause}
        GROUP BY i.species, i.variety, i.uploaded_by, strftime('%Y-%m-%d', i.uploaded_at)
        ORDER BY i.reviewed_at DESC
    `, params, (err, images) => {
        if (err) {
            console.error('Erro ao carregar imagens aprovadas:', err);
            return res.render('approved', {
                error: 'Erro ao carregar imagens',
                images: [],
                success: null
            });
        }
        if (images.length === 0) {
            return res.render('approved', {
                images: [],
                success: req.flash('success')[0] || req.query.success || null,
                error: null
            });
        }
        const imagesWithRating = [];
        let done = 0;
        images.forEach(img => {
            db.get(
                'SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?',
                [img.winning_id || img.id, req.user.id],
                (e, r) => {
                    img.userRating = r ? r.stars : 0;
                    imagesWithRating.push(img);

                    if (++done === images.length) {
                        res.render('approved', {
                            images: imagesWithRating,
                            success: req.flash('success')[0] || req.query.success || null,
                            error: null
                        });
                    }
                }
            );
        });
    });
});

app.get('/rejected', ensureAuth, (req, res) => {
    const reviewedBy = req.query.reviewed_by;
    let whereClause = 'status = "rejected"';
    let params = [];
    if (reviewedBy) {
        whereClause += ' AND reviewed_by = ?';
        params.push(reviewedBy);
    }
    db.get(`SELECT COUNT(*) as total FROM images WHERE ${whereClause}`, params, (err, countResult) => {
        const totalRejected = countResult ? countResult.total : 0;
        db.all(`
            SELECT
                species,
                variety,
                uploaded_by,
                strftime('%Y-%m-%d', uploaded_at) AS upload_day,
                reviewed_by,
                reviewed_at,
                MIN(id) AS sample_id,
                (SELECT nome FROM gamas WHERE id = (
                    SELECT gama_id FROM images i2
                    WHERE i2.species = i.species
                      AND (i2.variety = i.variety OR (i2.variety IS NULL AND i.variety IS NULL))
                      AND i2.uploaded_by = i.uploaded_by
                      AND strftime('%Y-%m-%d', i2.uploaded_at) = strftime('%Y-%m-%d', i.uploaded_at)
                    LIMIT 1
                )) AS gama_nome
            FROM images i
            WHERE ${whereClause}
            GROUP BY species, variety, uploaded_by, upload_day
            ORDER BY reviewed_at DESC
        `, params, (err, groupRows) => {
            if (err || groupRows.length === 0) {
                return res.render('rejected', {
                    images: [],
                    groupedImages: [],
                    totalRejected: 0,
                    success: req.flash('success')[0] || null
                });
            }
            const groups = {};
            groupRows.forEach(row => {
                const key = `${row.species || ''}|${row.variety || ''}|${row.uploaded_by}|${row.upload_day}`;
                groups[key] = {
                    key: key,
                    species: row.species || 'Sem espécie',
                    variety: row.variety || '',
                    gama_nome: row.gama_nome || 'Não definido',
                    reviewed_by: row.reviewed_by,
                    reviewed_at: row.reviewed_at,
                    sample_id: row.sample_id,
                    images: []
                };
            });
            const groupKeys = Object.keys(groups);
            let completed = 0;
            groupKeys.forEach(key => {
                const group = groups[key];
                const [species, variety, uploaded_by, upload_day] = key.split('|');
                db.all(`
                    SELECT id, image_url
                    FROM images
                    WHERE species = ?
                      AND (variety = ? OR (variety IS NULL AND ? IS NULL))
                      AND uploaded_by = ?
                      AND strftime('%Y-%m-%d', uploaded_at) = ?
                      AND status = 'rejected'
                    ORDER BY marca_id ASC
                `, [species, variety, variety, uploaded_by, upload_day], (err, imgs) => {
                    group.images = err ? [] : imgs;
                    if (++completed === groupKeys.length) {
                        const groupedImages = Object.values(groups);
                        let ratingDone = 0;
                        groupedImages.forEach(g => {
                            if (g.images.length > 0) {
                                db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [g.images[0].id, req.user.id], (e, r) => {
                                    g.userRating = r ? r.stars : 0;
                                    if (++ratingDone === groupedImages.length) renderFinal();
                                });
                            } else {
                                g.userRating = 0;
                                if (++ratingDone === groupedImages.length) renderFinal();
                            }
                        });
                        function renderFinal() {
                            res.render('rejected', {
                                images: { length: totalRejected },
                                groupedImages: groupedImages,
                                success: req.flash('success')[0] || null,
                                error: null
                            });
                        }
                    }
                });
            });
        });
    });
});

app.get('/search', ensureAuth, (req, res) => {
    const query = (req.query.q || '').trim();
    const page = parseInt(req.query.page) || 1;
    const limit = 12;
    const offset = (page - 1) * limit;
    const date = req.query.date || null;
    const user = req.query.user || null;
    if (!query && !date && !user) {
        return res.render('search', {
            images: [],
            query: '',
            date: null,
            user: null,
            total: 0,
            success: req.flash('success')[0] || null
        });
    }
    let whereClauses = [];
    let params = [];
    if (query) {
        const searchTerm = `%${query}%`;
        whereClauses.push(`(species LIKE ? OR variety LIKE ? OR botanical_name LIKE ? OR origem LIKE ? OR caracteristicas LIKE ? OR conselhos_de_cultivo LIKE ? OR comentarios LIKE ?)`);
        params.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
    }
    if (date) {
        whereClauses.push(`DATE(uploaded_at) = ?`);
        params.push(date);
    }
    if (user) {
        whereClauses.push(`uploaded_by = ?`);
        params.push(user);
    }
    const whereSql = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';
    const countSql = `SELECT COUNT(*) as total FROM images ${whereSql}`;
    db.get(countSql, params, (err, countRow) => {
        if (err || !countRow) {
            req.flash('error', 'Erro na pesquisa');
            return res.redirect('/statistics');
        }
        const total = countRow.total || 0;
        const searchSql = `SELECT i.*, g.nome AS gama_nome
                           FROM images i
                           LEFT JOIN gamas g ON i.gama_id = g.id
                           ${whereSql} ORDER BY uploaded_at DESC LIMIT ? OFFSET ?`;
        db.all(searchSql, [...params, limit, offset], (err, images) => {
            if (err) {
                req.flash('error', 'Erro ao carregar resultados');
                return res.redirect('/statistics');
            }
            const imagesWithRating = [];
            let done = 0;
            if (images.length === 0) {
                return res.render('search', {
                    images: [],
                    query,
                    date,
                    user,
                    total,
                    success: req.flash('success')[0] || null
                });
            }
            images.forEach(img => {
                db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [img.id, req.user.id], (e, r) => {
                    img.userRating = r ? r.stars : 0;
                    imagesWithRating.push(img);
                    if (++done === images.length) {
                        res.render('search', {
                            images: imagesWithRating,
                            query,
                            date,
                            user,
                            total,
                            success: req.flash('success')[0] || null
                        });
                    }
                });
            });
        });
    });
});

app.get('/details/:id', ensureAuth, (req, res) => {
    const imageId = req.params.id;
    db.get(`
        SELECT
            i.*, m.nome AS marca_nome, g.nome AS gama_nome
        FROM images i
        LEFT JOIN marcas m ON i.marca_id = m.id
        LEFT JOIN gamas g ON i.gama_id = g.id
        WHERE i.id = ?
    `, [imageId], (err, mainImage) => {
        if (err || !mainImage) {
            req.flash('error', 'Imagem não encontrada');
            return res.redirect('/statistics');
        }
        const date = new Date(mainImage.uploaded_at);
        const timeKey = date.toISOString().slice(0, 10);
        db.all(`
            SELECT
                i.id, i.image_url, m.nome AS marca_nome, i.approvals, i.rejections, i.status
            FROM images i
            LEFT JOIN marcas m ON i.marca_id = m.id
            WHERE i.species = ?
              AND (i.variety = ? OR (i.variety IS NULL AND ? IS NULL))
              AND i.uploaded_by = ?
              AND strftime('%Y-%m-%d', i.uploaded_at) = ?
            ORDER BY i.approvals DESC, i.id ASC
        `, [
            mainImage.species,
            mainImage.variety, mainImage.variety,
            mainImage.uploaded_by,
            timeKey
        ], (err, relatedImages) => {
            if (err) {
                console.error('Erro ao carregar imagens relacionadas:', err);
                relatedImages = [];
            }
            if (relatedImages.length === 0) {
                relatedImages = [{
                    id: mainImage.id,
                    image_url: mainImage.image_url,
                    marca_nome: mainImage.marca_nome || 'Sem marca',
                    approvals: mainImage.approvals || 0,
                    rejections: mainImage.rejections || 0,
                    status: mainImage.status
                }];
            }

            // DETETAR SE VEMOS DA PÁGINA DE REJEITADAS
            const fromRejected = (req.headers.referer || '').includes('/rejected');

            res.render('details', {
                image: mainImage,
                relatedImages: relatedImages,
                success: req.flash('success')[0] || null,
                fromRejected: fromRejected
            });
        });
    });
});

app.get('/edit/:id', ensureAuth, (req, res) => {
    const imageId = req.params.id;
    db.get('SELECT * FROM images WHERE id = ?', [imageId], (err, image) => {
        if (err || !image) {
            req.flash('error', 'Imagem não encontrada');
            return res.redirect('/statistics');
        }
        const timeKey = new Date(image.uploaded_at).toISOString().slice(0, 10);
        db.all(`
            SELECT i.id, i.image_url, i.marca_id, m.nome AS marca_nome
            FROM images i
            LEFT JOIN marcas m ON i.marca_id = m.id
            WHERE i.species = ?
              AND (i.variety = ? OR (i.variety IS NULL AND ? IS NULL))
              AND i.uploaded_by = ?
              AND strftime('%Y-%m-%d', i.uploaded_at) = ?
            ORDER BY i.marca_id ASC
        `, [image.species, image.variety, image.variety, image.uploaded_by, timeKey], (err, relatedImages) => {
            if (err) relatedImages = [];
            if (!relatedImages || relatedImages.length === 0) {
                relatedImages = [{
                    id: image.id,
                    image_url: image.image_url,
                    marca_id: image.marca_id || 1
                }];
            }
            db.all('SELECT id, nome FROM gamas ORDER BY nome', [], (err, gamas) => {
                if (err) gamas = [];
                res.render('edit', {
                    image,
                    relatedImages,
                    gamas,
                    success: req.flash('success')[0] || null,
                    error: req.flash('error')[0] || null
                });
            });
        });
    });
});

app.post('/delete-image/:id', ensureAuth, (req, res) => {
    const imageId = req.params.id;
    db.get('SELECT image_url FROM images WHERE id = ?', [imageId], (err, row) => {
        if (err || !row) {
            req.flash('error', 'Imagem não encontrada para apagar.');
            return res.redirect('back');
        }
        const filePath = path.join(__dirname, 'public', 'uploads', row.image_url);
        db.run('DELETE FROM images WHERE id = ?', [imageId], function (err) {
            if (err) {
                console.error('Erro ao apagar imagem da DB:', err);
                req.flash('error', 'Erro ao apagar imagem da base de dados.');
                return res.redirect('back');
            }
            if (fs.existsSync(filePath)) {
                fs.unlink(filePath, (err) => {
                    if (err) console.error('Erro ao apagar ficheiro físico:', err);
                });
            }
            req.flash('success', 'Imagem apagada permanentemente da base de dados.');
            res.redirect('back');
        });
    });
});

app.post('/delete-plant', ensureAuth, (req, res) => {
    const sampleImageId = req.body.sampleImageId;
    if (!sampleImageId) {
        req.flash('error', 'Erro ao identificar a planta para apagar.');
        return res.redirect('/review');
    }
    db.get('SELECT * FROM images WHERE id = ?', [sampleImageId], (err, sampleImage) => {
        if (err || !sampleImage) {
            req.flash('error', 'Planta não encontrada.');
            return res.redirect('/review');
        }
        const timeKey = new Date(sampleImage.uploaded_at).toISOString().slice(0, 10);
        db.all(`
            SELECT id, image_url FROM images
            WHERE species = ?
              AND (variety = ? OR (variety IS NULL AND ? IS NULL))
              AND uploaded_by = ?
              AND strftime('%Y-%m-%d', uploaded_at) = ?
        `, [sampleImage.species, sampleImage.variety, sampleImage.variety, sampleImage.uploaded_by, timeKey], (err, plantImages) => {
            if (err || plantImages.length === 0) {
                req.flash('error', 'Nenhuma imagem encontrada para apagar.');
                return res.redirect('/review');
            }
            let deletedCount = 0;
            const totalImages = plantImages.length;
            plantImages.forEach(img => {
                const filePath = path.join(__dirname, 'public', 'uploads', img.image_url);
                db.run('DELETE FROM images WHERE id = ?', [img.id], function (err) {
                    if (err) {
                        console.error('Erro ao apagar imagem ID ' + img.id + ':', err);
                    } else {
                        deletedCount++;
                        if (fs.existsSync(filePath)) {
                            fs.unlink(filePath, (err) => {
                                if (err) console.error('Erro ao apagar ficheiro:', err);
                            });
                        }
                    }
                    if (deletedCount === totalImages) {
                        req.flash('success', `Planta apagada com sucesso! (${totalImages} imagem(ns) removida(s))`);
                        res.redirect('/review');
                    }
                });
            });
        });
    });
});

app.post('/edit', ensureAuth, upload.fields([
    { name: 'newImage0', maxCount: 1 },
    { name: 'newImage1', maxCount: 1 },
    { name: 'newImage2', maxCount: 1 }
]), async (req, res) => {
    console.log('=== INÍCIO DA EDIÇÃO RÁPIDA ===');
    console.log('Files recebidos:', req.files);
    try {
        const sampleImageId = req.body.originalId;
        if (!sampleImageId) {
            req.flash('error', 'Erro ao identificar a planta');
            return res.redirect('/statistics');
        }
        db.get('SELECT * FROM images WHERE id = ?', [sampleImageId], async (err, sampleImage) => {
            if (err || !sampleImage) {
                req.flash('error', 'Imagem não encontrada');
                return res.redirect('/statistics');
            }
            const commonData = {
                species: req.body.species,
                variety: req.body.variety ? req.body.variety.trim() : null,
                botanical_name: req.body.botanical_name || null,
                origem: req.body.origem || null,
                colheitaFloracao: req.body.colheitaFloracao || null,
                exposicaoSolar: req.body.exposicaoSolar || null,
                rega: req.body.rega || null,
                profundidadeSementeira: req.body.profundidadeSementeira || null,
                sementeiraDireta: req.body.sementeiraDireta ? 1 : 0,
                sementeiraAlfobre: req.body.sementeiraAlfobre ? 1 : 0,
                sementeira: req.body.sementeira || null,
                transplante: req.body.transplante || null,
                compasso: req.body.compasso || null,
                caracteristicas: req.body.caracteristicas || null,
                conselhos_de_cultivo: req.body.conselhos_de_cultivo || null,
                comentarios: req.body.comentarios || null,
                gama_id: req.body.gama_id || null
            };

            db.all(`
                SELECT id, image_url, marca_id FROM images
                WHERE species = ?
                  AND (variety = ? OR (variety IS NULL AND ? IS NULL))
                  AND uploaded_by = ?
                  AND strftime('%Y-%m-%d', uploaded_at) = strftime('%Y-%m-%d', ?)
                ORDER BY marca_id ASC
            `, [sampleImage.species, sampleImage.variety, sampleImage.variety, sampleImage.uploaded_by, sampleImage.uploaded_at], async (err, plantImages) => {
                if (err) plantImages = [];
                let updatedCount = 0;
                let createdCount = 0;
                const promises = [];
                for (let index = 0; index < 3; index++) {
                    const marcaId = index + 1;
                    const hasFile = req.files[`newImage${index}`] && req.files[`newImage${index}`].length;
                    const existingImage = plantImages.find(p => p.marca_id === marcaId);
                    let filename = null;
                    if (hasFile) {
                        filename = req.files[`newImage${index}`][0].filename;
                    }
                    if (existingImage) {
                        const updateFilename = filename || existingImage.image_url;
                        promises.push(new Promise((resolve, reject) => {
                            db.run(`
                                UPDATE images SET
                                    image_url = ?, species = ?, variety = ?, botanical_name = ?, origem = ?,
                                    colheitaFloracao = ?, exposicaoSolar = ?, rega = ?, profundidadeSementeira = ?,
                                    sementeiraDireta = ?, sementeiraAlfobre = ?, sementeira = ?, transplante = ?,
                                    compasso = ?, caracteristicas = ?, conselhos_de_cultivo = ?, comentarios = ?,
                                    gama_id = ?
                                WHERE id = ?
                            `, [
                                updateFilename, commonData.species, commonData.variety, commonData.botanical_name,
                                commonData.origem, commonData.colheitaFloracao, commonData.exposicaoSolar,
                                commonData.rega, commonData.profundidadeSementeira, commonData.sementeiraDireta,
                                commonData.sementeiraAlfobre, commonData.sementeira, commonData.transplante,
                                commonData.compasso, commonData.caracteristicas, commonData.conselhos_de_cultivo,
                                commonData.comentarios, commonData.gama_id, existingImage.id
                            ], function (err) {
                                if (err) reject(err);
                                else {
                                    updatedCount++;
                                    if (filename && existingImage.image_url !== filename) {
                                        const oldPath = path.join('public/uploads', existingImage.image_url);
                                        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
                                    }
                                    resolve();
                                }
                            });
                        }));
                    } else if (filename) {
                        promises.push(new Promise((resolve, reject) => {
                            db.run(`
                                INSERT INTO images (
                                    image_url, species, variety, botanical_name, origem, colheitaFloracao,
                                    exposicaoSolar, rega, profundidadeSementeira, sementeiraDireta, sementeiraAlfobre,
                                    sementeira, transplante, compasso, caracteristicas, conselhos_de_cultivo,
                                    comentarios, uploaded_by, uploaded_at, status, gama_id, marca_id
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            `, [
                                filename, commonData.species, commonData.variety, commonData.botanical_name,
                                commonData.origem, commonData.colheitaFloracao, commonData.exposicaoSolar,
                                commonData.rega, commonData.profundidadeSementeira, commonData.sementeiraDireta,
                                commonData.sementeiraAlfobre, commonData.sementeira, commonData.transplante,
                                commonData.compasso, commonData.caracteristicas, commonData.conselhos_de_cultivo,
                                commonData.comentarios, sampleImage.uploaded_by, sampleImage.uploaded_at,
                                sampleImage.status, commonData.gama_id, marcaId
                            ], function (err) {
                                if (err) reject(err);
                                else {
                                    createdCount++;
                                    resolve();
                                }
                            });
                        }));
                    }
                }
                await Promise.all(promises);
                req.flash('success', `Planta editada! ${updatedCount} atualizada(s), ${createdCount} criada(s)`);
                res.redirect('/details/' + sampleImageId);
            });
        });
    } catch (err) {
        console.error('Erro geral na edição:', err);
        req.flash('error', 'Erro ao editar planta');
        res.redirect('/statistics');
    }
});


app.get('/proxy', async (req, res) => {
    const url = req.query.url;
    if (!url) return res.status(400).send('URL missing');
    try {
        const response = await axios({
            url,
            method: 'GET',
            responseType: 'stream',
            timeout: 15000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; IVAAP Bot)'
            }
        });
        res.set({
            'Content-Type': response.headers['content-type'] || 'image/jpeg',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=3600'
        });
        response.data.pipe(res);
    } catch (err) {
        console.error('Erro no proxy:', err.message);
        res.status(500).send('Erro ao carregar imagem');
    }
});

app.post('/approve/:id', ensureAuth, (req, res) => {
    const imageId = req.params.id;
    db.run(`UPDATE images SET approvals = approvals + 1 WHERE id = ?`, [imageId], (err) => {
        if (err) {
            req.flash('error', 'Erro ao aprovar');
        } else {
            req.flash('success', 'Voto registado!');
        }
        res.redirect(req.get('referer') || '/details/' + imageId);
    });
});

app.post('/reject/:id', ensureAuth, (req, res) => {
    const imageId = req.params.id;
    db.run(`UPDATE images SET rejections = rejections + 1 WHERE id = ?`, [imageId], (err) => {
        if (err) {
            req.flash('error', 'Erro ao rejeitar');
        } else {
            req.flash('success', 'Voto registado!');
        }
        res.redirect(req.get('referer') || '/details/' + imageId);
    });
});

app.post('/validate-winner/:id', ensureAuth, (req, res) => {
    const imageId = req.params.id;
    const reviewedBy = req.user.username;
    const reviewedAt = new Date().toISOString();
    db.get('SELECT * FROM images WHERE id = ?', [imageId], (err, winnerImage) => {
        if (err || !winnerImage) {
            req.flash('error', 'Imagem não encontrada');
            return res.redirect('/review');
        }
        const timeKey = new Date(winnerImage.uploaded_at).toISOString().slice(0, 10);
        db.run(
            `UPDATE images
             SET status = 'approved',
                 reviewed_by = ?,
                 reviewed_at = ?
             WHERE id = ?`,
            [reviewedBy, reviewedAt, imageId],
            function (err) {
                if (err) {
                    req.flash('error', 'Erro ao validar imagem');
                    return res.redirect('/details/' + imageId);
                }
                db.run(
                    `UPDATE images
                     SET status = 'rejected',
                         reviewed_by = ?,
                         reviewed_at = ?
                     WHERE species = ?
                       AND (variety = ? OR (variety IS NULL AND ? IS NULL))
                       AND uploaded_by = ?
                       AND strftime('%Y-%m-%d', uploaded_at) = ?
                       AND status = 'pending'
                       AND id != ?`,
                    [
                        reviewedBy,
                        reviewedAt,
                        winnerImage.species,
                        winnerImage.variety,
                        winnerImage.variety,
                        winnerImage.uploaded_by,
                        timeKey,
                        imageId
                    ],
                    function (err) {
                        if (err) {
                            console.error('Erro ao rejeitar outras imagens:', err);
                        }
                        req.flash('success', `Imagem mais votada aprovada! As restantes foram descartadas.`);
                        res.redirect('/review');
                    }
                );
            }
        );
    });
});

app.listen(PORT, () => {
    console.log(`IVAAP RODANDO EM http://localhost:${PORT}`);
    console.log(`LOGIN INSTANTÂNEO`);
    console.log(`EDIÇÃO RÁPIDA`);
    console.log(`DELETE-PLANT FUNCIONA`);
    console.log(`fromRejected PASSADO NA ROTA /details`);
    console.log(`FLORA LUSITANA 2025  AGORA SIM, ESTÁVEL`);
});