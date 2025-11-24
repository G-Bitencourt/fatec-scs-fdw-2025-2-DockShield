require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();

// --- Conexão ao Banco de Dados ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Conectado ao MongoDB (Banco: login)!'))
    .catch(err => console.error('Erro ao conectar no Mongo:', err));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- Modelo Único ---
const credencialSchema = new mongoose.Schema({
    nome: String,
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});

const User = mongoose.model('Credencial', credencialSchema, 'credenciais');

// --- ROTAS ---

// 1. CADASTRO
app.post('/cadastro', async (req, res) => {
    try {
        const { nome, username, password } = req.body;
        if (await User.findOne({ username })) {
            return res.send('Erro: Usuário já existe! <a href="cadastro.html">Tentar de novo</a>');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ nome, username, password: hashedPassword });
        res.redirect('/login.html');
    } catch (error) {
        res.send('Erro ao cadastrar: ' + error.message);
    }
});

// 2. LOGIN
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.send('Usuário ou senha incorretos! <a href="login.html">Voltar</a>');
    }

    const token = jwt.sign(
        { userId: user._id, username: user.username, nome: user.nome },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    res.cookie('auth_token', token, { httpOnly: true, maxAge: 3600000 });


    // Pega a URL do arquivo .env. Se não tiver, usa localhost como fallback.
    const flaskUrl = process.env.FLASK_EXTERNAL_URL || 'http://localhost:5000/';
    res.redirect(flaskUrl);
});

// 3. LOGOUT
app.get('/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.redirect('/login.html');
});

// 4. EDITAR SENHA
app.post('/editar_senha', async (req, res) => {
    const { username, old_password, new_password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(old_password, user.password))) {
        return res.send('Senha atual incorreta. <a href="editar_senha.html">Voltar</a>');
    }

    user.password = await bcrypt.hash(new_password, 10);
    await user.save();
    res.send('Senha alterada com sucesso! <a href="login.html">Fazer Login</a>');
});

// 5. EXCLUIR CONTA
app.post('/excluir', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.send('Senha incorreta. <a href="excluir.html">Voltar</a>');
    }

    await User.deleteOne({ username });
    res.clearCookie('auth_token');
    res.send('Conta excluída. <a href="cadastro.html">Novo Cadastro</a>');
});

app.listen(3000, () => {
    console.log('Servidor Node rodando em: http://localhost:3000/login.html');
});