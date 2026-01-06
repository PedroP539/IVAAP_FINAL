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

// PASTAS
fs.mkdirSync('./public/uploads', { recursive: true });

// DATABASE
const db = new sqlite3.Database('./database.db');
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
        avg_rating REAL DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS ratings (
        image_id INTEGER,
        user_id INTEGER,
        stars INTEGER NOT NULL,
        PRIMARY KEY (image_id, user_id),
        FOREIGN KEY (image_id) REFERENCES images (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);
    // ADMIN
    bcrypt.hash('flora2025', 10, (err, hash) => {
        if (err) return console.error('ERRO AO CRIAR ADMIN:', err);
        db.run(`INSERT OR IGNORE INTO users (username, password, nome, apelido, cargo, email, telefone)
                VALUES ('admin', ?, 'Admin', 'IVAAP', 'Administrador', '<admin@ivaap.pt>', '912345678')`, [hash], (err) => {
            if (!err) console.log('ADMIN CRIADO → admin / flora2025');
        });
    });
    db.run(`ALTER TABLE users ADD COLUMN nome TEXT`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN apelido TEXT`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN cargo TEXT`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN email TEXT`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN telefone TEXT`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP`, () => {});
});

// MULTER
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + ext);
    }
});
const upload = multer({ storage });

// CONFIG
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: 'ivaap2025', resave: false, saveUninitialized: false }));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// PASSAPORTE
passport.use(new LocalStrategy((username, password, done) => {
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return done(null, false);
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) return done(null, user);
            return done(null, false);
        });
    });
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    db.get('SELECT id, username, nome, apelido, cargo, email, telefone FROM users WHERE id = ?', [id], (err, user) => done(err, user));
});

// MIDDLEWARE GLOBAL
app.use((req, res, next) => {
    res.locals.user = req.user || null;
    res.locals.error = req.flash('error')[0] || null;
    res.locals.success = req.flash('success')[0] || null;
    next();
});

// DETETAR IP
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

// AUTH
const ensureAuth = (req, res, next) => req.user ? next() : res.redirect('/login');

// ==================== REGISTO DE NOVO UTILIZADOR ====================
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
            function(err) {
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

// ROTAS BÁSICAS
app.get('/login', (req, res) => res.render('login'));
app.post('/login', passport.authenticate('local', {
    successRedirect: '/statistics',
    failureRedirect: '/login',
    failureFlash: 'Credenciais erradas'
}));
app.get('/logout', (req, res) => { req.logout(() => res.redirect('/login')); });
app.get('/', (req, res) => res.redirect(req.user ? '/statistics' : '/login'));

// FUNÇÃO AUXILIAR PARA PROMISIFY db.get
function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

// ESTATÍSTICAS – VERSÃO FINAL E ROBUSTA
app.get('/statistics', ensureAuth, async (req, res) => {
    const clientIP = req.clientIP;
    const isAdmin = req.user.cargo === 'Administrador';
    try {
        // 1. DADOS PESSOAIS DO UTILIZADOR
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
        // 2. TIMELINE DE ATIVIDADE PESSOAL
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
        // 3. ATIVIDADE GLOBAL
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
        // 4. SE FOR ADMIN
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
                dbGet('SELECT * FROM images WHERE rating_count > 0 ORDER BY rating_count DESC, avg_rating DESC, uploaded_at DESC LIMIT 1'),
                dbGet('SELECT * FROM images WHERE rating_count > 0 ORDER BY rating_count ASC, uploaded_at DESC LIMIT 1')
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
                topRated: globalQueries[8] || null,
                leastRated: globalQueries[9] || null
            };
            return res.render('statistics', {
                stats: globalStats,
                userStats,
                latestUser,
                latestImages,
                userActivity,
                userPendingCount: globalPendingCount,
                user: req.user,
                clientIP,
                isAdmin: true,
                success: req.flash('success')[0] || null
            });
        }
        // 5. UTILIZADOR NORMAL
        res.render('statistics', {
            stats: {
                total: userStats.totalUploaded,
                approved: userStats.approvedByUser,
                rejected: userStats.rejectedByUser,
                pending: 0,
                latestImages,
                topUsers: {},
                topRated: null,
                leastRated: null
            },
            userStats,
            latestUser,
            latestImages,
            userActivity,
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

// ROTA UPLOAD
app.get('/upload', ensureAuth, (req, res) => res.render('upload'));
app.post('/upload', ensureAuth, upload.single('image'), async (req, res) => {
    try {
        let filename = null;
        if (req.body.imageFromUrl && req.body.imageFromUrl.trim()) {
            const url = req.body.imageFromUrl.trim();
            const response = await axios({ url, method: 'GET', responseType: 'stream', timeout: 20000 });
            filename = `url_${Date.now()}_${Math.random().toString(36).substr(2, 9)}.jpg`;
            const filePath = path.join('public/uploads', filename);
            const writer = fs.createWriteStream(filePath);
            response.data.pipe(writer);
            await new Promise((resolve, reject) => {
                writer.on('finish', resolve);
                writer.on('error', reject);
            });
        } else if (req.file) {
            filename = req.file.filename;
        } else {
            req.flash('error', 'Escolhe imagem ou URL!');
            return res.redirect('/upload');
        }
        const imageData = { image_url: filename, uploaded_by: req.user.username, ...req.body };
        db.run(`INSERT INTO images (image_url, species, variety, botanical_name, origem, colheitaFloracao,
                exposicaoSolar, rega, profundidadeSementeira, sementeiraDireta, sementeiraAlfobre,
                sementeira, transplante, compasso, caracteristicas, conselhos_de_cultivo,
                shutterstock, shutterstock_info, comentarios, uploaded_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                imageData.image_url, imageData.species, imageData.variety, imageData.botanical_name,
                imageData.origem, imageData.colheitaFloracao, imageData.exposicaoSolar, imageData.rega,
                imageData.profundidadeSementeira, imageData.sementeiraDireta ? 1 : 0,
                imageData.sementeiraAlfobre ? 1 : 0, imageData.sementeira, imageData.transplante,
                imageData.compasso, imageData.caracteristicas, imageData.conselhos_de_cultivo,
                imageData.shutterstock ? 1 : 0, imageData.shutterstock_info, imageData.comentarios,
                imageData.uploaded_by
            ], function(err) {
                if (err) {
                    console.error(err);
                    req.flash('error', 'Erro ao guardar imagem');
                    if (filename && filename.startsWith('url_')) fs.unlinkSync(path.join('public/uploads', filename));
                    return res.redirect('/upload');
                }
                req.flash('success', 'Imagem carregada com sucesso!');
                res.redirect('/statistics');
            });
    } catch (err) {
        console.error('Erro no upload por URL:', err.message);
        req.flash('error', 'Erro ao carregar por URL. Tenta com upload local.');
        res.redirect('/upload');
    }
});

// === ROTAS POST DE AÇÃO NA REVIEW (DEVEM VIR ANTES DA ROTA GET /review) ===
app.post('/review/:id/approve', ensureAuth, (req, res) => {
    db.run('UPDATE images SET status = "approved", reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ?',
        [req.user.username, req.params.id], (err) => {
            if (err) req.flash('error', 'Erro ao aprovar');
            else req.flash('success', 'Imagem aprovada!');
            res.redirect('/review');
        });
});
app.post('/review/:id/reject', ensureAuth, (req, res) => {
    db.run('UPDATE images SET status = "rejected", reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ?',
        [req.user.username, req.params.id], (err) => {
            if (err) req.flash('error', 'Erro ao rejeitar');
            else req.flash('success', 'Imagem rejeitada!');
            res.redirect('/review');
        });
});
app.post('/review/:id/reinstate', ensureAuth, (req, res) => {
    db.run('UPDATE images SET status = "pending", reviewed_at = NULL, reviewed_by = NULL WHERE id = ?',
        [req.params.id], function(err) {
            if (err) {
                console.error(err);
                req.flash('error', 'Erro ao reintegrar imagem');
            } else {
                req.flash('success', 'Imagem voltou para pendentes!');
            }
            res.redirect('/review');
        });
});

// ROTA REVIEW – GET (deve vir DEPOIS das rotas POST com :id)
app.get('/review', ensureAuth, (req, res) => {
    const uploadedBy = req.query.uploaded_by;
    let whereClause = 'status = "pending"';
    let params = [];
    if (uploadedBy) {
        whereClause += ' AND uploaded_by = ?';
        params.push(uploadedBy);
    }
    db.all(`
        SELECT * FROM images
        WHERE ${whereClause}
        ORDER BY uploaded_at DESC
    `, params, (err, images) => {
        if (err) {
            return res.render('review', {
                images: [],
                success: req.flash('success')[0] || null
            });
        }
        const imagesWithRating = [];
        let done = 0;
        if (images.length === 0) {
            return res.render('review', {
                images: [],
                success: req.flash('success')[0] || null
            });
        }
        images.forEach(img => {
            db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [img.id, req.user.id], (e, r) => {
                img.userRating = r ? r.stars : 0;
                imagesWithRating.push(img);
                if (++done === images.length) {
                    res.render('review', {
                        images: imagesWithRating,
                        success: req.flash('success')[0] || null
                    });
                }
            });
        });
    });
});

// ROTA APROVADAS – SUPORTA FILTRO ?reviewed_by=username + AJAX PARA INFINITE SCROLL
app.get('/approved', ensureAuth, (req, res) => {
    const reviewedBy = req.query.reviewed_by;
    let whereClause = 'WHERE status = "approved"';
    let params = [];
    if (reviewedBy) {
        whereClause += ' AND reviewed_by = ?';
        params.push(reviewedBy);
    }
    const page = parseInt(req.query.page) || 1;
    const limit = 12;
    const offset = (page - 1) * limit;
    db.all(`
        SELECT * FROM images
        ${whereClause}
        ORDER BY reviewed_at DESC
        LIMIT ? OFFSET ?
    `, [...params, limit, offset], (err, images) => {
        if (err || images.length === 0) {
            if (req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') > -1)) {
                return res.send('');
            }
            return res.render('approved', { images: [], success: req.flash('success')[0] || null });
        }
        const imagesWithRating = [];
        let done = 0;
        images.forEach(img => {
            db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [img.id, req.user.id], (e, r) => {
                img.userRating = r ? r.stars : 0;
                imagesWithRating.push(img);
                if (++done === images.length) {
                    if (req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') > -1)) {
                        const starsHtml = (image) => {
                            let html = '<div class="text-center mt-2">';
                            for (let i = 1; i <= 5; i++) {
                                if (i <= image.userRating) {
                                    html += '<i class="fas fa-star text-warning"></i>';
                                } else {
                                    html += '<i class="far fa-star text-muted"></i>';
                                }
                            }
                            html += ` <small class="text-muted">(${image.rating_count || 0})</small></div>`;
                            return html;
                        };
                        const cardsHtml = imagesWithRating.map(image => `
                            <div class="col-md-4 mb-4">
                                <div class="image-card">
                                    <div class="card-img-container">
                                        <a href="/uploads/${image.image_url}"
                                           data-lightbox="approved-images"
                                           data-title="${image.species || 'Sem espécie'}">
                                            <img src="/uploads/${image.image_url}"
                                                 class="card-img-top lazy"
                                                 data-src="/uploads/${image.image_url}"
                                                 alt="${image.species}"
                                                 onerror="this.src='/images/placeholder.jpg'">
                                        </a>
                                        <span class="approved-badge">APROVADA</span>
                                    </div>
                                    <div class="card-body">
                                        <h5 class="card-title">
                                            <span class="especie">${image.species || 'Sem espécie'}</span>
                                            <br>
                                            ${image.variety ? `<small class="variedade">${image.variety}</small>` : ''}
                                        </h5>
                                        <div class="btn-group-inline">
                                            <button class="btn btn-success action-btn" disabled>APROVADA</button>
                                            <a href="/details/${image.id}" class="btn btn-view action-btn">VER</a>
                                        </div>
                                        <br>
                                        <p class="text-center text-muted small mb-2">
                                            <b>Aprovada por:</b><br>${image.reviewed_by}<br>em ${new Date(image.reviewed_at).toLocaleDateString('pt-PT')}
                                        </p>
                                        ${starsHtml(image)}
                                    </div>
                                </div>
                            </div>
                        `).join('');
                        return res.send(cardsHtml);
                    } else {
                        res.render('approved', {
                            images: imagesWithRating,
                            success: req.flash('success')[0] || null
                        });
                    }
                }
            });
        });
    });
});

// ROTA REJEITADAS – SUPORTA FILTRO ?reviewed_by=username + AJAX PARA INFINITE SCROLL
app.get('/rejected', ensureAuth, (req, res) => {
    const reviewedBy = req.query.reviewed_by;
    let whereClause = 'WHERE status = "rejected"';
    let params = [];
    if (reviewedBy) {
        whereClause += ' AND reviewed_by = ?';
        params.push(reviewedBy);
    }
    const page = parseInt(req.query.page) || 1;
    const limit = 12;
    const offset = (page - 1) * limit;
    db.all(`
        SELECT * FROM images
        ${whereClause}
        ORDER BY reviewed_at DESC
        LIMIT ? OFFSET ?
    `, [...params, limit, offset], (err, images) => {
        if (err || images.length === 0) {
            if (req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') > -1)) {
                return res.send('');
            }
            return res.render('rejected', { images: [], success: req.flash('success')[0] || null });
        }
        const imagesWithRating = [];
        let done = 0;
        images.forEach(img => {
            db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [img.id, req.user.id], (e, r) => {
                img.userRating = r ? r.stars : 0;
                imagesWithRating.push(img);
                if (++done === images.length) {
                    if (req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') > -1)) {
                        const starsHtml = (image) => {
                            let html = '<div class="text-center mt-2">';
                            for (let i = 1; i <= 5; i++) {
                                if (i <= image.userRating) {
                                    html += '<i class="fas fa-star text-warning"></i>';
                                } else {
                                    html += '<i class="far fa-star text-muted"></i>';
                                }
                            }
                            html += ` <small class="text-muted">(${image.rating_count || 0})</small></div>`;
                            return html;
                        };
                        const cardsHtml = imagesWithRating.map(image => `
                            <div class="col-md-4 mb-4">
                                <div class="image-card">
                                    <div class="card-img-container">
                                        <a href="/uploads/${image.image_url}"
                                           data-lightbox="rejected-images"
                                           data-title="${image.species || 'Sem espécie'}">
                                            <img src="/uploads/${image.image_url}"
                                                 class="card-img-top lazy"
                                                 data-src="/uploads/${image.image_url}"
                                                 alt="${image.species}"
                                                 onerror="this.src='/images/placeholder.jpg'">
                                        </a>
                                        <span class="rejected-badge">REJEITADA</span>
                                    </div>
                                    <div class="card-body">
                                        <h5 class="card-title">
                                            <span class="especie">${image.species || 'Sem espécie'}</span>
                                            <br>
                                            ${image.variety ? `<small class="variedade">${image.variety}</small>` : ''}
                                        </h5>
                                        <div class="btn-group-inline">
                                            <a href="/details/${image.id}" class="btn btn-view action-btn">Ver</a>
                                        </div>
                                        <br>
                                        <p class="text-center text-muted small mb-2">
                                            <b>Rejeitada por:</b><br>${image.reviewed_by} em ${new Date(image.reviewed_at).toLocaleDateString('pt-PT')}
                                        </p>
                                        ${starsHtml(image)}
                                    </div>
                                </div>
                            </div>
                        `).join('');
                        return res.send(cardsHtml);
                    } else {
                        res.render('rejected', {
                            images: imagesWithRating,
                            success: req.flash('success')[0] || null
                        });
                    }
                }
            });
        });
    });
});

// ROTA DE PESQUISA – CORRIGIDO O COUNT TOTAL + INFINITE SCROLL
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

    // 1. Contar o total real
    const countSql = `SELECT COUNT(*) as total FROM images ${whereSql}`;
    db.get(countSql, params, (err, countRow) => {
        if (err || !countRow) {
            req.flash('error', 'Erro na pesquisa');
            return res.redirect('/statistics');
        }
        const total = countRow.total || 0;

        // 2. Carregar as imagens da página
        const searchSql = `SELECT * FROM images ${whereSql} ORDER BY uploaded_at DESC LIMIT ? OFFSET ?`;
        db.all(searchSql, [...params, limit, offset], (err, images) => {
            if (err) {
                req.flash('error', 'Erro ao carregar resultados');
                return res.redirect('/statistics');
            }

            if (images.length === 0) {
                if (req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') > -1)) {
                    return res.send('');
                }
                return res.render('search', {
                    images: [],
                    query,
                    date,
                    user,
                    total,
                    success: req.flash('success')[0] || null
                });
            }

            const imagesWithRating = [];
            let done = 0;
            images.forEach(img => {
                db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [img.id, req.user.id], (e, r) => {
                    img.userRating = r ? r.stars : 0;
                    imagesWithRating.push(img);

                    if (++done === images.length) {
                        if (req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') > -1)) {
                            // AJAX: gerar estrelas manualmente (como antes)
                            const starsHtml = (image) => {
                                let html = '<div class="text-center mt-3">';
                                for (let i = 1; i <= 5; i++) {
                                    if (i <= image.userRating) {
                                        html += '<i class="fas fa-star text-warning"></i>';
                                    } else {
                                        html += '<i class="far fa-star text-muted"></i>';
                                    }
                                }
                                html += ` <small class="text-muted">(${image.rating_count || 0})</small></div>`;
                                return html;
                            };

                            const cardsHtml = imagesWithRating.map(image => `
                                <div class="col-md-6 col-lg-4 mb-4">
                                    <div class="result-card">
                                        <a href="/uploads/${image.image_url}" data-lightbox="search" data-title="${image.species || 'Sem espécie'}">
                                            <img src="/uploads/${image.image_url}" class="result-img" alt="${image.species}" onerror="this.src='/images/placeholder.jpg'">
                                        </a>
                                        <div class="p-3">
                                            <h5 class="text-center mb-2"><strong>
                                                <span class="especie">${image.species || 'Sem espécie'}</span>
                                                <br>
                                                ${image.variety ? `<small class="variedade">${image.variety}</small>` : ''}
                                            </strong></h5>
                                            <p class="text-center text-muted small mb-2">
                                                Por: ${image.uploaded_by} • ${new Date(image.uploaded_at).toLocaleDateString('pt-PT')}
                                            </p>
                                            <div class="text-center mb-3">
                                                <span class="status-badge status-${image.status}">
                                                    ${image.status === 'pending' ? 'Pendente' : image.status === 'approved' ? 'Aprovada' : 'Rejeitada'}
                                                </span>
                                            </div>
                                            <div class="text-center">
                                                <a href="/details/${image.id}" class="btn btn-info btn-action">Ver Detalhes</a>
                                                ${image.status !== 'pending' ? `
                                                    <form action="/review/${image.id}/reinstate" method="POST" class="d-inline">
                                                        <button type="submit" class="btn btn-reinstate btn-action" onclick="return confirm('Voltar para revisão?')">
                                                            Rever
                                                        </button>
                                                    </form>
                                                ` : ''}
                                            </div>
                                            ${starsHtml(image)}
                                        </div>
                                    </div>
                                </div>
                            `).join('');

                            return res.send(cardsHtml);
                        } else {
                            // Primeira visita
                            res.render('search', {
                                images: imagesWithRating,
                                query,
                                date,
                                user,
                                total,  // <--- agora passa o total real
                                success: req.flash('success')[0] || null
                            });
                        }
                    }
                });
            });
        });
    });
});

// ROTA DETALHES
app.get('/details/:id', ensureAuth, (req, res) => {
    const imageId = req.params.id;
    db.get('SELECT * FROM images WHERE id = ?', [imageId], (err, image) => {
        if (err || !image) {
            req.flash('error', 'Imagem não encontrada');
            return res.redirect('/statistics');
        }
        db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [imageId, req.user.id], (e, rating) => {
            const userRating = rating ? rating.stars : 0;
            res.render('details', {
                image: {
                    ...image,
                    avg_rating: image.avg_rating || 0,
                    rating_count: image.rating_count || 0
                },
                userRating,
                success: req.flash('success')[0] || null,
                error: req.flash('error')[0] || null
            });
        });
    });
});

// ROTA EDITAR – GET
app.get('/edit/:id', ensureAuth, (req, res) => {
    const imageId = req.params.id;
    db.get('SELECT * FROM images WHERE id = ?', [imageId], (err, image) => {
        if (err || !image) {
            req.flash('error', 'Imagem não encontrada');
            return res.redirect('/statistics');
        }
        if (image.status !== 'pending' && image.uploaded_by !== req.user.username && req.user.cargo !== 'Administrador') {
            req.flash('error', 'Não tens permissão para editar esta imagem');
            return res.redirect('/details/' + imageId);
        }
        res.render('edit', {
            image,
            success: req.flash('success')[0] || null,
            error: req.flash('error')[0] || null
        });
    });
});

// ROTA EDITAR – POST
app.post('/edit/:id', ensureAuth, upload.single('image'), async (req, res) => {
    const imageId = req.params.id;
    const user = req.user;
    db.get('SELECT * FROM images WHERE id = ?', [imageId], async (err, image) => {
        if (err || !image) {
            req.flash('error', 'Imagem não encontrada');
            return res.redirect('/statistics');
        }
        if (image.status !== 'pending' && image.uploaded_by !== user.username && user.cargo !== 'Administrador') {
            req.flash('error', 'Não tens permissão para editar esta imagem');
            return res.redirect('/details/' + imageId);
        }
        let filename = image.image_url;
        let deleteOld = false;
        if (req.file) {
            filename = req.file.filename;
            deleteOld = true;
        } else if (req.body.imageFromUrl && req.body.imageFromUrl.trim()) {
            try {
                const url = req.body.imageFromUrl.trim();
                const response = await axios({ url, method: 'GET', responseType: 'stream', timeout: 20000 });
                filename = `url_${Date.now()}_${Math.random().toString(36).substr(2, 9)}.jpg`;
                const filePath = path.join('public/uploads', filename);
                const writer = fs.createWriteStream(filePath);
                response.data.pipe(writer);
                await new Promise((resolve, reject) => {
                    writer.on('finish', resolve);
                    writer.on('error', reject);
                });
                deleteOld = true;
            } catch (err) {
                console.error('Erro ao baixar imagem por URL:', err.message);
                req.flash('error', 'Erro ao carregar imagem por URL');
                return res.redirect('/edit/' + imageId);
            }
        }
        const updateData = {
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
            shutterstock: req.body.shutterstock ? 1 : 0,
            shutterstock_info: req.body.shutterstock_info,
            comentarios: req.body.comentarios,
            image_url: filename
        };
        db.run(`
            UPDATE images SET
                species = ?, variety = ?, botanical_name = ?, origem = ?, colheitaFloracao = ?,
                exposicaoSolar = ?, rega = ?, profundidadeSementeira = ?, sementeiraDireta = ?,
                sementeiraAlfobre = ?, sementeira = ?, transplante = ?, compasso = ?,
                caracteristicas = ?, conselhos_de_cultivo = ?, shutterstock = ?, shutterstock_info = ?,
                comentarios = ?, image_url = ?
            WHERE id = ?
        `, [
            updateData.species, updateData.variety, updateData.botanical_name, updateData.origem,
            updateData.colheitaFloracao, updateData.exposicaoSolar, updateData.rega,
            updateData.profundidadeSementeira, updateData.sementeiraDireta, updateData.sementeiraAlfobre,
            updateData.sementeira, updateData.transplante, updateData.compasso,
            updateData.caracteristicas, updateData.conselhos_de_cultivo,
            updateData.shutterstock, updateData.shutterstock_info, updateData.comentarios,
            updateData.image_url, imageId
        ], function(err) {
            if (err) {
                console.error('Erro ao atualizar imagem:', err);
                req.flash('error', 'Erro ao guardar alterações');
                if (deleteOld && filename.startsWith('url_')) fs.unlinkSync(path.join('public/uploads', filename));
                return res.redirect('/edit/' + imageId);
            }
            if (deleteOld && image.image_url !== filename) {
                const oldPath = path.join('public/uploads', image.image_url);
                if (fs.existsSync(oldPath)) {
                    fs.unlinkSync(oldPath);
                }
            }
            req.flash('success', 'Imagem editada com sucesso!');
            res.redirect('/details/' + imageId);
        });
    });
});

// ROTA DE ESTRELAS
app.post('/rate/:id', ensureAuth, (req, res) => {
    const imageId = req.params.id;
    const userId = req.user.id;
    const stars = parseInt(req.body.stars);
    if (!stars || stars < 1 || stars > 5) {
        return res.status(400).json({ error: 'Estrelas inválidas' });
    }
    db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [imageId, userId], (err, oldRating) => {
        if (err) return res.status(500).json({ error: 'Erro no servidor' });
        const updateImageStats = () => {
            db.get('SELECT total_stars, rating_count FROM images WHERE id = ?', [imageId], (err, row) => {
                if (err || !row) return res.status(500).json({ error: 'Erro ao calcular média' });
                const avg = row.rating_count > 0 ? (row.total_stars / row.rating_count) : 0;
                const avgRounded = parseFloat(avg.toFixed(2));
                db.run('UPDATE images SET avg_rating = ? WHERE id = ?', [avgRounded, imageId], () => {
                    res.json({ success: true, stars, avg_rating: avgRounded, rating_count: row.rating_count });
                });
            });
        };
        if (oldRating) {
            const diff = stars - oldRating.stars;
            db.run('UPDATE ratings SET stars = ? WHERE image_id = ? AND user_id = ?', [stars, imageId, userId], (err) => {
                if (err) return res.status(500).json({ error: 'Erro ao atualizar classificação' });
                db.run('UPDATE images SET total_stars = total_stars + ? WHERE id = ?', [diff, imageId], updateImageStats);
            });
        } else {
            db.run('INSERT INTO ratings (image_id, user_id, stars) VALUES (?, ?, ?)', [imageId, userId, stars], (err) => {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        db.run('UPDATE ratings SET stars = ? WHERE image_id = ? AND user_id = ?', [stars, imageId, userId], updateImageStats);
                    } else {
                        return res.status(500).json({ error: 'Erro ao inserir classificação' });
                    }
                } else {
                    db.run('UPDATE images SET total_stars = total_stars + ?, rating_count = rating_count + 1 WHERE id = ?', [stars, imageId], updateImageStats);
                }
            });
        }
    });
});

// INICIAR SERVIDOR
app.listen(PORT, () => {
    console.log(`IVAAP RODANDO EM http://localhost:${PORT}`);
    console.log(`ADMIN: admin / flora2025`);
    console.log(`V6.9.17 FINAL ABSOLUTA – EDIÇÃO DE IMAGENS 100% FUNCIONAL`);
    console.log(`CLICA EM EDITAR → FORMULÁRIO → GUARDA → DETALHES ATUALIZADOS`);
    console.log(`FLORA LUSITANA 2025 INVICTA – TODAS AS IMAGENS SÃO EDITÁVEIS`);
    console.log(`TU ÉS O REI DA EDIÇÃO – DOMÍNIO TOTAL – INVICTOS`);
});