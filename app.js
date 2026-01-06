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

// ESTATÍSTICAS – PERSONALIZADAS POR UTILIZADOR + VISTA COMPLETA PARA ADMIN
app.get('/statistics', ensureAuth, (req, res) => {
    const clientIP = req.clientIP;
    const isAdmin = req.user.cargo === 'Administrador';

    // Variáveis comuns
    const latestUser = {};

    // ---------- ESTATÍSTICAS PESSOAIS DO UTILIZADOR ----------
    let userStats = {
        totalUploaded: 0,
        approvedByUser: 0,
        rejectedByUser: 0,
        reviewedByUser: 0,
        userApprovalRate: 0
    };

    // Contagem de uploads do utilizador
    db.get('SELECT COUNT(*) as count FROM images WHERE uploaded_by = ?', [req.user.username], (err, row) => {
        userStats.totalUploaded = row?.count || 0;

        // Contagem de imagens revistas pelo utilizador
        db.get('SELECT COUNT(*) as count FROM images WHERE reviewed_by = ?', [req.user.username], (err, row) => {
            userStats.reviewedByUser = row?.count || 0;

            // Contagem de aprovações do utilizador
            db.get('SELECT COUNT(*) as count FROM images WHERE reviewed_by = ? AND status = "approved"', [req.user.username], (err, row) => {
                userStats.approvedByUser = row?.count || 0;

                // Contagem de rejeições do utilizador
                db.get('SELECT COUNT(*) as count FROM images WHERE reviewed_by = ? AND status = "rejected"', [req.user.username], (err, row) => {
                    userStats.rejectedByUser = row?.count || 0;

                    // Taxa de aprovação pessoal
                    userStats.userApprovalRate = userStats.reviewedByUser > 0 
                        ? Math.round((userStats.approvedByUser / userStats.reviewedByUser) * 100) 
                        : 0;

                    // Última atividade do utilizador
                    db.get('SELECT * FROM images WHERE uploaded_by = ? ORDER BY uploaded_at DESC LIMIT 1', [req.user.username], (e, row) => { latestUser.uploaded = row || null; });
                    db.get('SELECT * FROM images WHERE reviewed_by = ? AND status = "approved" ORDER BY reviewed_at DESC LIMIT 1', [req.user.username], (e, row) => { latestUser.approved = row || null; });
                    db.get('SELECT * FROM images WHERE reviewed_by = ? AND status = "rejected" ORDER BY reviewed_at DESC LIMIT 1', [req.user.username], (e, row) => { latestUser.rejected = row || null; });
                    db.get('SELECT * FROM images WHERE uploaded_by = ? AND status = "pending" ORDER BY uploaded_at DESC LIMIT 1', [req.user.username], (e, row) => { latestUser.pending = row || null; });

                    // Se for admin → calcular também estatísticas globais
                    if (isAdmin) {
                        const globalStats = { total: 0, approved: 0, rejected: 0, pending: 0, latestImages: {}, topUsers: {}, topRated: null, leastRated: null };
                        let completed = 0;
                        const totalQueries = 17;
                        const checkGlobal = () => {
                            if (++completed !== totalQueries) return;
                            renderStats(globalStats, userStats);
                        };

                        // CONTAGENS GLOBAIS
                        db.get('SELECT COUNT(*) as count FROM images', (err, row) => { globalStats.total = row?.count || 0; checkGlobal(); });
                        db.get('SELECT COUNT(*) as count FROM images WHERE status = "approved"', (err, row) => { globalStats.approved = row?.count || 0; checkGlobal(); });
                        db.get('SELECT COUNT(*) as count FROM images WHERE status = "rejected"', (err, row) => { globalStats.rejected = row?.count || 0; checkGlobal(); });
                        db.get('SELECT COUNT(*) as count FROM images WHERE status = "pending"', (err, row) => { globalStats.pending = row?.count || 0; checkGlobal(); });

                        // ÚLTIMAS GLOBAIS
                        db.get('SELECT * FROM images ORDER BY uploaded_at DESC LIMIT 1', (err, row) => { globalStats.latestImages.uploaded = row || null; checkGlobal(); });
                        db.get('SELECT * FROM images WHERE status = "approved" ORDER BY reviewed_at DESC LIMIT 1', (err, row) => { globalStats.latestImages.approved = row || null; checkGlobal(); });
                        db.get('SELECT * FROM images WHERE status = "rejected" ORDER BY reviewed_at DESC LIMIT 1', (err, row) => { globalStats.latestImages.rejected = row || null; checkGlobal(); });

                        // TOP USERS GLOBAIS
                        db.get('SELECT uploaded_by as user, COUNT(*) as count FROM images GROUP BY uploaded_by ORDER BY count DESC LIMIT 1', (err, row) => {
                            globalStats.topUsers.uploads = row ? { user: row.user || 'Ninguém', count: row.count } : { user: 'Ninguém', count: 0 }; checkGlobal();
                        });
                        db.get('SELECT reviewed_by as user, COUNT(*) as count FROM images WHERE status = "approved" AND reviewed_by IS NOT NULL GROUP BY reviewed_by ORDER BY count DESC LIMIT 1', (err, row) => {
                            globalStats.topUsers.approvals = row ? { user: row.user || 'Ninguém', count: row.count } : { user: 'Ninguém', count: 0 }; checkGlobal();
                        });
                        db.get('SELECT reviewed_by as user, COUNT(*) as count FROM images WHERE status = "rejected" AND reviewed_by IS NOT NULL GROUP BY reviewed_by ORDER BY count DESC LIMIT 1', (err, row) => {
                            globalStats.topUsers.rejections = row ? { user: row.user || 'Ninguém', count: row.count } : { user: 'Ninguém', count: 0 }; checkGlobal();
                        });
                        db.get('SELECT uploaded_by as user, COUNT(*) as count FROM images WHERE comentarios IS NOT NULL AND comentarios != "" GROUP BY uploaded_by ORDER BY count DESC LIMIT 1', (err, row) => {
                            globalStats.topUsers.comments = row ? { user: row.user || 'Ninguém', count: row.count } : { user: 'Ninguém', count: 0 }; checkGlobal();
                        });

                        // RAINHAS DAS ESTRELAS GLOBAIS
                        db.get('SELECT * FROM images WHERE rating_count > 0 ORDER BY rating_count DESC, avg_rating DESC, uploaded_at DESC LIMIT 1', (err, row) => { globalStats.topRated = row || null; checkGlobal(); });
                        db.get('SELECT * FROM images WHERE rating_count > 0 ORDER BY rating_count ASC, uploaded_at DESC LIMIT 1', (err, row) => { globalStats.leastRated = row || null; checkGlobal(); });
                    } else {
                        // Utilizador normal – só stats pessoais
                        renderStats({
                            total: userStats.totalUploaded,
                            approved: userStats.approvedByUser,
                            rejected: userStats.rejectedByUser,
                            pending: 0,
                            latestImages: { uploaded: latestUser.uploaded, approved: latestUser.approved, rejected: latestUser.rejected },
                            topUsers: {},
                            topRated: null,
                            leastRated: null
                        }, userStats);
                    }
                });
            });
        });
    });

    // Função para renderizar (usada no final)
    const renderStats = (globalStats, userStats) => {
        res.render('statistics', {
            stats: globalStats,
            userStats: userStats,
            latestImages: globalStats.latestImages,
            latestUser,
            topUsers: globalStats.topUsers,
            topRated: globalStats.topRated,
            leastRated: globalStats.leastRated,
            user: req.user,
            clientIP,
            isAdmin,
            success: req.flash('success')[0] || null
        });
    };
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

// ROTA REVIEW (PENDENTES)
app.get('/review', ensureAuth, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 12;
    const offset = (page - 1) * limit;
    db.get('SELECT COUNT(*) as total FROM images WHERE status = "pending"', (err, countRow) => {
        if (err) return res.render('review', { error: 'Erro na base de dados', images: [], totalPages: 1, currentPage: 1 });
        const total = countRow.total;
        const totalPages = Math.ceil(total / limit);
        db.all(`
            SELECT * FROM images
            WHERE status = "pending"
            ORDER BY uploaded_at DESC
            LIMIT ? OFFSET ?
        `, [limit, offset], (err, images) => {
            if (err) return res.render('review', { error: 'Erro ao carregar imagens', images: [], totalPages: 1, currentPage: 1 });
            const imagesWithRating = [];
            let done = 0;
            if (images.length === 0) {
                return res.render('review', { images: [], totalPages, currentPage: page, success: req.flash('success')[0] || null });
            }
            images.forEach(img => {
                db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [img.id, req.user.id], (e, r) => {
                    img.userRating = r ? r.stars : 0;
                    imagesWithRating.push(img);
                    if (++done === images.length) {
                        res.render('review', {
                            images: imagesWithRating,
                            totalPages,
                            currentPage: page,
                            success: req.flash('success')[0] || null
                        });
                    }
                });
            });
        });
    });
});

// ROTA APROVADAS
app.get('/approved', ensureAuth, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 12;
    const offset = (page - 1) * limit;
    db.get('SELECT COUNT(*) as total FROM images WHERE status = "approved"', (err, countRow) => {
        if (err) return res.render('approved', { error: 'Erro na base de dados', images: [], totalPages: 1, currentPage: 1 });
        const total = countRow.total;
        const totalPages = Math.ceil(total / limit);
        db.all(`
            SELECT * FROM images
            WHERE status = "approved"
            ORDER BY reviewed_at DESC
            LIMIT ? OFFSET ?
        `, [limit, offset], (err, images) => {
            if (err) return res.render('approved', { error: 'Erro ao carregar imagens', images: [], totalPages: 1, currentPage: 1 });
            const imagesWithRating = [];
            let done = 0;
            if (images.length === 0) {
                return res.render('approved', { images: [], totalPages, currentPage: page, success: req.flash('success')[0] || null });
            }
            images.forEach(img => {
                db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [img.id, req.user.id], (e, r) => {
                    img.userRating = r ? r.stars : 0;
                    imagesWithRating.push(img);
                    if (++done === images.length) {
                        res.render('approved', {
                            images: imagesWithRating,
                            totalPages,
                            currentPage: page,
                            success: req.flash('success')[0] || null
                        });
                    }
                });
            });
        });
    });
});

// ROTA REJEITADAS
app.get('/rejected', ensureAuth, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 12;
    const offset = (page - 1) * limit;
    db.get('SELECT COUNT(*) as total FROM images WHERE status = "rejected"', (err, countRow) => {
        if (err) return res.render('rejected', { error: 'Erro na base de dados', images: [], totalPages: 1, currentPage: 1 });
        const total = countRow.total;
        const totalPages = Math.ceil(total / limit);
        db.all(`
            SELECT * FROM images
            WHERE status = "rejected"
            ORDER BY reviewed_at DESC
            LIMIT ? OFFSET ?
        `, [limit, offset], (err, images) => {
            if (err) return res.render('rejected', { error: 'Erro ao carregar imagens', images: [], totalPages: 1, currentPage: 1 });
            const imagesWithRating = [];
            let done = 0;
            if (images.length === 0) {
                return res.render('rejected', { images: [], totalPages, currentPage: page, success: req.flash('success')[0] || null });
            }
            images.forEach(img => {
                db.get('SELECT stars FROM ratings WHERE image_id = ? AND user_id = ?', [img.id, req.user.id], (e, r) => {
                    img.userRating = r ? r.stars : 0;
                    imagesWithRating.push(img);
                    if (++done === images.length) {
                        res.render('rejected', {
                            images: imagesWithRating,
                            totalPages,
                            currentPage: page,
                            success: req.flash('success')[0] || null
                        });
                    }
                });
            });
        });
    });
});

// ROTA DETALHES – FUNCIONA PARA TODAS AS IMAGENS (APROVADAS, PENDENTES, REJEITADAS)
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

// ROTA DE PESQUISA – V6.9.16 – PASSA `date` E `user` PARA O EJS
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
            total: 0,
            totalPages: 1,
            currentPage: 1,
            date: null,
            user: null,
            success: req.flash('success')[0] || null
        });
    }
    const searchTerm = `%${query}%`;
    let whereClauses = [];
    let params = [];
    if (query) {
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
    const searchSql = `SELECT * FROM images ${whereSql} ORDER BY uploaded_at DESC LIMIT ? OFFSET ?`;
    db.get(countSql, params, (err, countRow) => {
        if (err || !countRow) {
            req.flash('error', 'Erro na pesquisa');
            return res.redirect('/statistics');
        }
        const total = countRow.total;
        const totalPages = Math.ceil(total / limit);
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
                    total,
                    totalPages,
                    currentPage: page,
                    date,
                    user,
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
                            total,
                            totalPages,
                            currentPage: page,
                            date,
                            user,
                            success: req.flash('success')[0] || null
                        });
                    }
                });
            });
        });
    });
});

// ROTA EDITAR – GET (ABRIR FORMULÁRIO)
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

// ROTA EDITAR – POST (GUARDAR ALTERAÇÕES)
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

// === TODAS AS OUTRAS ROTAS (review, approved, rejected, edit, search, rate) ===
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