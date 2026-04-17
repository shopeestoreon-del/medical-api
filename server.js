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
// 🏥 CONFIGURAÇÃO DA CLÍNICA (White-Label)
// ==========================================

// 1. SALVAR configurações (POST)
app.post('/clinica/config', verifyToken, isAdmin, async (req, res) => {
  const { 
    nome_fantasia, razao_social, cnpj, logo_url, 
    cor_primaria, cor_secundaria, telefone, email 
  } = req.body;

  try {
    // 1. Pegamos o ID da clínica que já está no cadastro do usuário
    const userResult = await pool.query('SELECT clinic_id FROM users WHERE id = $1', [req.userId]);
    const clinicId = userResult.rows[0].clinic_id;

    if (!clinicId) {
      return res.status(404).json({ error: "Usuário não possui uma clínica vinculada." });
    }

    // 2. Lógica "UPSERT": Insere se não existir, atualiza se existir. Tudo pelo ID.
    const result = await pool.query(
      `INSERT INTO clinicas (id, nome_fantasia, razao_social, cnpj, logo_url, cor_primaria, cor_secundaria, telefone, email)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (id) DO UPDATE SET
         nome_fantasia = EXCLUDED.nome_fantasia,
         razao_social = EXCLUDED.razao_social,
         cnpj = EXCLUDED.cnpj,
         logo_url = EXCLUDED.logo_url,
         cor_primaria = EXCLUDED.cor_primaria,
         cor_secundaria = EXCLUDED.cor_secundaria,
         telefone = EXCLUDED.telefone,
         email = EXCLUDED.email
       RETURNING id`,
      [clinicId, nome_fantasia, razao_social, cnpj, logo_url, cor_primaria, cor_secundaria, telefone, email]
    );

    res.json({ message: "Configurações salvas com sucesso!", id: result.rows[0].id });
  } catch (err) {
    console.error("Erro ao salvar:", err);
    res.status(500).json({ error: "Erro interno no servidor." });
  }
});

// 2. LER configurações (GET) - ESSENCIAL PARA O FRONTEND
app.get('/clinica/config', verifyToken, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT clinic_id FROM users WHERE id = $1', [req.userId]);
    const clinicId = userResult.rows[0].clinic_id;

    if (!clinicId) return res.status(404).json({ error: "Clínica não associada." });

    const result = await pool.query('SELECT * FROM clinicas WHERE id = $1', [clinicId]);

    if (result.rows.length === 0) {
      return res.json({ nome_fantasia: "MedicalPlus", cor_primaria: "#3b82f6", cor_secundaria: "#1e40af" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar configurações." });
  }
});

// ==========================================
// 📋 MÓDULO DE PACIENTES
// ==========================================

app.get('/pacientes', verifyToken, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT clinic_id FROM users WHERE id = $1', [req.userId]);
    const clinicId = userResult.rows[0].clinic_id;

    const pacientes = await pool.query(
      'SELECT * FROM pacientes WHERE clinic_id = $1 ORDER BY nome_completo ASC',
      [clinicId]
    );

    res.json(pacientes.rows);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar pacientes." });
  }
});

app.post('/pacientes', verifyToken, async (req, res) => {
  const { nome_completo, cpf, rg, data_nascimento, telefone, endereco, alergias } = req.body;

  try {
    const userResult = await pool.query('SELECT clinic_id FROM users WHERE id = $1', [req.userId]);
    const clinicId = userResult.rows[0].clinic_id;

    const result = await pool.query(
      `INSERT INTO pacientes (nome_completo, cpf, rg, data_nascimento, telefone, endereco, alergias, clinic_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [nome_completo, cpf, rg, data_nascimento, telefone, endereco, alergias, clinicId]
    );

    res.status(201).json({ message: "Paciente cadastrado!", paciente: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: "CPF já cadastrado." });
    res.status(500).json({ error: "Erro ao cadastrar paciente." });
  }
});

// Mensagem de boas-vindas na raiz para teste de conexão
app.get('/', (req, res) => res.send('🚀 Medical-API está online!'));

app.listen(process.env.PORT || 3000, () => console.log("📡 API Pronta!"));