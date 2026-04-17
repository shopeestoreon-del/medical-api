const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ==========================================
// 🛡️ MIDDLEWARES DE SEGURANÇA
// ==========================================

// 1. Verifica se o usuário está logado (Token Válido)
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Acesso negado. Token não fornecido." });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(401).json({ error: "Token inválido ou expirado." });
  }
};

// 2. Verifica se o usuário é ADMIN 
const isAdmin = async (req, res, next) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id = $1', [req.userId]);
    if (user.rows.length > 0 && user.rows[0].role === 'admin') {
      next();
    } else {
      res.status(403).json({ error: "Acesso restrito apenas para administradores." });
    }
  } catch (err) {
    res.status(500).json({ error: "Erro ao verificar permissão." });
  }
};

// ==========================================
// 🔑 ROTAS DE AUTENTICAÇÃO
// ==========================================

app.post('/auth/register', async (req, res) => {
  const { name, email, password, clinic_id } = req.body;
  try {
    const password_hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (full_name, email, password_hash, role, clinic_id) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [name, email, password_hash, 'admin', clinic_id]
    );
    res.status(201).json({ message: "Admin criado com sucesso!", id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: "Usuário não encontrado" });

    const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!validPassword) return res.status(401).json({ error: "Senha incorreta" });

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ 
      token, 
      user: { 
        id: user.rows[0].id,
        name: user.rows[0].full_name, 
        email: user.rows[0].email,
        role: user.rows[0].role,
        clinic_id: user.rows[0].clinic_id 
      } 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 🏥 ROTA DE CONFIGURAÇÃO DA CLÍNICA (White-Label) [cite: 119-122]
// ==========================================

app.post('/clinica/config', verifyToken, isAdmin, async (req, res) => {
  const { nome_fantasia, razao_social, cnpj, logo_url, cor_primaria, cor_secundaria, telefone, email } = req.body;

  try {
    const result = await pool.query(
      `INSERT INTO clinicas (nome_fantasia, razao_social, cnpj, logo_url, cor_primaria, cor_secundaria, telefone, email)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (cnpj) DO UPDATE SET
       nome_fantasia = EXCLUDED.nome_fantasia,
       razao_social = EXCLUDED.razao_social,
       logo_url = EXCLUDED.logo_url,
       cor_primaria = EXCLUDED.cor_primaria,
       cor_secundaria = EXCLUDED.cor_secundaria,
       telefone = EXCLUDED.telefone,
       email = EXCLUDED.email
       RETURNING id`,
      [nome_fantasia, razao_social, cnpj, logo_url, cor_primaria, cor_secundaria, telefone, email]
    );

    res.json({ message: "Configurações da clínica salvas!", id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log("📡 API Pronta!"));