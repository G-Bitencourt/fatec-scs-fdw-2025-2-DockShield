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

// --- Middlewares (Configurações) ---
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser()); // Necessário para criar o cookie de login

// Define a pasta 'public' como local dos arquivos HTML/CSS
app.use(express.static(path.join(__dirname, 'public')));

// --- Modelo Único (Schema) ---
// Salva tudo na coleção 'credenciais' do banco 'login'
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

        // Verifica se usuário já existe
        if (await User.findOne({ username })) {
            return res.send('Erro: Usuário já existe! <a href="cadastro.html">Tentar de novo</a>');
        }

        // Criptografa a senha
        const hashedPassword = await bcrypt.hash(password, 10);

        // Salva no banco
        await User.create({ 
            nome, 
            username, 
            password: hashedPassword 
        });

        res.redirect('/login.html');
    } catch (error) {
        res.send('Erro ao cadastrar: ' + error.message);
    }
});

// 2. LOGIN (Com integração para o Flask)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    // Validação de segurança
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.send('Usuário ou senha incorretos! <a href="login.html">Voltar</a>');
    }

    // --- Integração JWT ---
    // Cria o token com os dados do usuário
    const token = jwt.sign(
        { userId: user._id, username: user.username, nome: user.nome },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    // Grava o cookie 'auth_token' que o Flask vai ler
    res.cookie('auth_token', token, { httpOnly: true, maxAge: 3600000 });

    // Redireciona para o painel do Flask (assumindo porta 5000)
    res.redirect('http://localhost:5000/');
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
    
    // Limpa o cookie se a conta foi excluída
    res.clearCookie('auth_token');
    res.send('Conta excluída. <a href="cadastro.html">Novo Cadastro</a>');
});

// Inicia o servidor na porta 3000
app.listen(3000, () => {
    console.log('Servidor Node rodando em: http://localhost:3000/login.html');
});