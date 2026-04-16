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

// ROTA DE CADASTRO DE ADMIN (Você vai usar isso primeiro)
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

// ROTA DE LOGIN
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: "Usuário não encontrado" });

    const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!validPassword) return res.status(401).json({ error: "Senha incorreta" });

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { name: user.rows[0].full_name, email: user.rows[0].email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log("📡 API Pronta!"));