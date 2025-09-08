// index.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const users = []; // Simulación de base de datos en memoria
const tokensInvalidated = new Set(); // Para manejar logout

// 🔐 Middleware para verificar token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token || tokensInvalidated.has(token)) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// 📝 Registro de usuario
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) return res.status(400).json({ error: 'Datos incompletos' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { username, email, password: hashedPassword };
  users.push(user);

  res.status(201).json({ message: 'Usuario registrado con éxito', user: { username, email } });
});

// 🔓 Inicio de sesión
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: 'Usuario no encontrado' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });

  const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.status(200).json({ message: 'Inicio de sesión exitoso', token });
});

// 🔒 Recurso protegido
app.get('/api/protected-resource', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'Acceso autorizado', data: `Contenido secreto para ${req.user.username}` });
});

// 🚪 Cierre de sesión
app.post('/api/logout', authenticateToken, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  tokensInvalidated.add(token);
  res.status(200).json({ message: 'Sesión cerrada correctamente' });
});

// 🚀 Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
