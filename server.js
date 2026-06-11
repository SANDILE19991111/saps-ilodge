// ============================================================================
// SAPS iLodge - Backend API Server (PostgreSQL Edition)
// ============================================================================

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Serve frontend static files
app.use(express.static(path.join(__dirname)));

// ----------------------------------------------------------------------------
// Database Connection Pool (PostgreSQL)
// ----------------------------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET = process.env.JWT_SECRET || 'saps-ilodge-secret-key-2026';
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';

// ----------------------------------------------------------------------------
// Authentication Middleware
// ----------------------------------------------------------------------------
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const requireRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
  next();
};

// ----------------------------------------------------------------------------
// AI Routing Engine (Groq + fallback)
// ----------------------------------------------------------------------------
async function routeWithAI(description) {
  const textHash = crypto.createHash('sha256').update(description.toLowerCase()).digest('hex');

  const cached = await pool.query(
    'SELECT department_code, reason, confidence FROM ai_routing_cache WHERE text_hash = $1',
    [textHash]
  );
  if (cached.rows.length > 0) {
    return {
      department: cached.rows[0].department_code,
      reason: cached.rows[0].reason,
      confidence: cached.rows[0].confidence,
      cached: true,
    };
  }

  try {
    const Groq = require('groq-sdk');
    const groq = new Groq({ apiKey: GROQ_API_KEY });
    const completion = await groq.chat.completions.create({
      model: 'llama3-8b-8192',
      messages: [
        {
          role: 'system',
          content: `You are a SAPS ticket routing assistant. Route complaints to the correct department.
Departments: IT (computers,systems,software,login,network,email,printer), FIN (salary,pay,payment,allowance,claim,money,overtime), HR (leave,discipline,grievance,training,transfer,promotion,uniform), OPS (vehicle,patrol,equipment,crime,arrest,maintenance,facility)
Reply ONLY with valid JSON: {"department":"FIN","reason":"brief explanation","confidence":0.95}`,
        },
        { role: 'user', content: `Route this SAPS complaint: "${description}"` },
      ],
      temperature: 0.1,
      max_tokens: 150,
    });
    const text = completion.choices[0].message.content.trim();
    const clean = text.replace(/```json|```/g, '').trim();
    const result = JSON.parse(clean);
    result.cached = false;

    await pool.query(
      `INSERT INTO ai_routing_cache (text_hash, description_sample, department_code, reason, confidence)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (text_hash) DO UPDATE SET
         department_code = EXCLUDED.department_code,
         reason = EXCLUDED.reason,
         confidence = EXCLUDED.confidence`,
      [textHash, description.substring(0, 500), result.department, result.reason, result.confidence || 0.90]
    );
    return result;
  } catch (err) {
    console.error('Groq API error:', err.message);
    return fallbackRouting(description);
  }
}

function fallbackRouting(description) {
  const text = description.toLowerCase();
  const patterns = {
    IT:  /computer|laptop|system|software|login|network|internet|vpn|printer|email|server|crashed|technical|hardware|screen|frozen|device|keyboard|mouse|wifi|password|access|not working/,
    FIN: /salary|salaries|paid|not paid|payment|pay slip|payslip|budget|finance|invoice|allowance|claim|overtime|reimbursement|money|deduction|bonus|pension|compensation|stipend|short paid|underpaid|wages/,
    HR:  /\bhr\b|leave|annual leave|sick leave|recruitment|personnel|employee|discipline|grievance|training|transfer|holiday|resign|contract|promotion|uniform|conduct|suspension/,
    OPS: /vehicle|patrol|equipment|operation|crime|case|report|arrest|firearm|ammo|shift|duty|resource|maintenance|generator|building|facility/,
  };
  for (const [dept, pattern] of Object.entries(patterns)) {
    if (pattern.test(text)) {
      const names = { IT: 'Information Technology', FIN: 'Finance', HR: 'Human Resources', OPS: 'Operations' };
      return { department: dept, reason: `Routed to ${names[dept]} based on complaint content`, confidence: 0.80 };
    }
  }
  return { department: 'OPS', reason: 'General operational matter — routed to Operations', confidence: 0.65 };
}

// ----------------------------------------------------------------------------
// Health Check
// ----------------------------------------------------------------------------
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ status: 'error', database: 'disconnected', error: err.message });
  }
});

// ----------------------------------------------------------------------------
// Authentication
// ----------------------------------------------------------------------------
app.post('/api/auth/login', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const result = await pool.query(
      'SELECT id, email, full_name, role, password_hash, is_active FROM users WHERE email = $1 AND role = $2',
      [email, role]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials or role mismatch' });
    const user = result.rows[0];
    if (!user.is_active) return res.status(401).json({ error: 'Account is deactivated' });
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    await pool.query(
      `INSERT INTO activity_logs (user_id, action, entity_type, ip_address, details) VALUES ($1, 'login', 'user', $2, $3)`,
      [user.id, req.ip, JSON.stringify({ role: user.role })]
    );

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.full_name, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token, user: { id: user.id, email: user.email, name: user.full_name, role: user.role } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, password, role, idNumber, phoneNumber, stationId } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required' });
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'Email already registered' });

    const userId = `${role}_${Date.now()}`;
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO users (id, email, password_hash, full_name, role, id_number, phone_number, station_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [userId, email, hashedPassword, fullName, role, idNumber || null, phoneNumber || null, stationId || null]
    );
    res.status(201).json({ message: 'User created successfully', userId });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ----------------------------------------------------------------------------
// Tickets
// ----------------------------------------------------------------------------
app.get('/api/tickets', authenticateToken, async (req, res) => {
  try {
    let query = `
      SELECT t.*, ps.station_name, d.dept_name as department_name,
             EXTRACT(EPOCH FROM (NOW() - t.opened_at))/3600 as hours_open,
             u.full_name, tr.response_text as admin_response,
             tr.created_at as admin_response_at, ru.full_name as admin_response_by
      FROM tickets t
      JOIN police_stations ps ON t.station_id = ps.id
      JOIN departments d ON t.department_id = d.id
      JOIN users u ON t.user_id = u.id
      LEFT JOIN ticket_responses tr ON t.id = tr.ticket_id
      LEFT JOIN users ru ON tr.responder_id = ru.id
    `;
    const params = [];
    if (req.user.role === 'external') {
      query += ' WHERE t.user_id = $1';
      params.push(req.user.id);
    } else if (req.user.role === 'staff') {
      query += ' WHERE t.user_id = $1 OR t.assigned_to = $2';
      params.push(req.user.id, req.user.id);
    }
    query += ' ORDER BY t.opened_at DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Get tickets error:', err);
    res.status(500).json({ error: 'Failed to fetch tickets' });
  }
});

app.post('/api/tickets', authenticateToken, async (req, res) => {
  const { stationId, description, priority } = req.body;
  if (!description || !stationId) return res.status(400).json({ error: 'Station and description are required' });
  try {
    const aiResult = await routeWithAI(description);
    const dept = await pool.query('SELECT id FROM departments WHERE dept_code = $1', [aiResult.department]);
    if (dept.rows.length === 0) return res.status(500).json({ error: 'Invalid department routing' });

    const lastTicket = await pool.query(
      "SELECT ticket_number FROM tickets WHERE ticket_number LIKE 'SAPS-%' ORDER BY id DESC LIMIT 1"
    );
    let lastNum = 2400;
    if (lastTicket.rows.length > 0) {
      const match = lastTicket.rows[0].ticket_number.match(/SAPS-(\d+)/);
      if (match) lastNum = parseInt(match[1]);
    }
    const ticketNumber = `SAPS-${lastNum + 1}`;

    await pool.query(
      `INSERT INTO tickets (ticket_number, user_id, station_id, department_id, description, priority, ai_reason, source, ai_confidence)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [ticketNumber, req.user.id, stationId, dept.rows[0].id, description, priority || 'Medium',
       aiResult.reason, req.user.role === 'external' ? 'citizen_portal' : 'staff_portal', aiResult.confidence]
    );
    await pool.query(
      `INSERT INTO activity_logs (user_id, action, entity_type, entity_id, details) VALUES ($1, 'create_ticket', 'ticket', $2, $3)`,
      [req.user.id, ticketNumber, JSON.stringify({ department: aiResult.department, priority })]
    );

    res.status(201).json({
      ticketNumber,
      department: aiResult.department,
      departmentName: { IT: 'Information Technology', FIN: 'Finance', HR: 'Human Resources', OPS: 'Operations' }[aiResult.department],
      aiReason: aiResult.reason,
      confidence: aiResult.confidence,
      status: 'Pending',
    });
  } catch (err) {
    console.error('Create ticket error:', err);
    res.status(500).json({ error: 'Failed to create ticket' });
  }
});

app.patch('/api/tickets/:ticketNumber/status', authenticateToken, requireRole(['admin', 'staff']), async (req, res) => {
  const { ticketNumber } = req.params;
  const { status } = req.body;
  const validStatuses = ['Pending', 'In Progress', 'Resolved', 'Closed'];
  if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const result = await pool.query(
      `UPDATE tickets SET
         status = $1,
         resolved_at = CASE WHEN $2 = 'Resolved' AND resolved_at IS NULL THEN NOW() ELSE resolved_at END,
         closed_at   = CASE WHEN $3 = 'Closed'   AND closed_at   IS NULL THEN NOW() ELSE closed_at   END
       WHERE ticket_number = $4`,
      [status, status, status, ticketNumber]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Ticket not found' });
    await pool.query(
      `INSERT INTO activity_logs (user_id, action, entity_type, entity_id, details) VALUES ($1, 'update_status', 'ticket', $2, $3)`,
      [req.user.id, ticketNumber, JSON.stringify({ newStatus: status })]
    );
    res.json({ message: 'Ticket status updated', status });
  } catch (err) {
    console.error('Update status error:', err);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

app.post('/api/tickets/:ticketNumber/respond', authenticateToken, requireRole(['admin']), async (req, res) => {
  const { ticketNumber } = req.params;
  const { response } = req.body;
  if (!response || !response.trim()) return res.status(400).json({ error: 'Response text is required' });
  try {
    const ticket = await pool.query('SELECT id FROM tickets WHERE ticket_number = $1', [ticketNumber]);
    if (ticket.rows.length === 0) return res.status(404).json({ error: 'Ticket not found' });

    await pool.query(
      `INSERT INTO ticket_responses (ticket_id, responder_id, response_text)
       VALUES ($1, $2, $3)
       ON CONFLICT (ticket_id) DO UPDATE SET response_text = EXCLUDED.response_text, updated_at = NOW()`,
      [ticket.rows[0].id, req.user.id, response.trim()]
    );
    await pool.query(
      `INSERT INTO activity_logs (user_id, action, entity_type, entity_id, details) VALUES ($1, 'admin_response', 'ticket', $2, $3)`,
      [req.user.id, ticketNumber, JSON.stringify({ responseLength: response.length })]
    );
    res.json({ message: 'Response saved successfully' });
  } catch (err) {
    console.error('Admin response error:', err);
    res.status(500).json({ error: 'Failed to save response' });
  }
});

app.post('/api/tickets/:ticketNumber/comments', authenticateToken, async (req, res) => {
  const { ticketNumber } = req.params;
  const { comment, isInternal } = req.body;
  if (!comment) return res.status(400).json({ error: 'Comment is required' });
  try {
    const ticket = await pool.query('SELECT id FROM tickets WHERE ticket_number = $1', [ticketNumber]);
    if (ticket.rows.length === 0) return res.status(404).json({ error: 'Ticket not found' });
    await pool.query(
      `INSERT INTO ticket_comments (ticket_id, user_id, comment, is_internal) VALUES ($1, $2, $3, $4)`,
      [ticket.rows[0].id, req.user.id, comment, isInternal || false]
    );
    res.status(201).json({ message: 'Comment added' });
  } catch (err) {
    console.error('Add comment error:', err);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

app.get('/api/tickets/:ticketNumber/comments', authenticateToken, async (req, res) => {
  const { ticketNumber } = req.params;
  try {
    const ticket = await pool.query('SELECT id FROM tickets WHERE ticket_number = $1', [ticketNumber]);
    if (ticket.rows.length === 0) return res.status(404).json({ error: 'Ticket not found' });

    let query = `SELECT tc.*, u.full_name, u.role FROM ticket_comments tc JOIN users u ON tc.user_id = u.id WHERE tc.ticket_id = $1`;
    const params = [ticket.rows[0].id];
    if (!['admin', 'staff'].includes(req.user.role)) query += ' AND tc.is_internal = FALSE';
    query += ' ORDER BY tc.created_at ASC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Get comments error:', err);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

// ----------------------------------------------------------------------------
// AI Chatbot
// ----------------------------------------------------------------------------
app.post('/api/chatbot', authenticateToken, async (req, res) => {
  const { message, history } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });
  try {
    const ticketsResult = await pool.query(
      `SELECT t.ticket_number, t.status, t.description, d.dept_name as department_name,
              tr.response_text as admin_response
       FROM tickets t
       JOIN departments d ON t.department_id = d.id
       LEFT JOIN ticket_responses tr ON t.id = tr.ticket_id
       WHERE t.user_id = $1 ORDER BY t.opened_at DESC LIMIT 10`,
      [req.user.id]
    );
    const tickets = ticketsResult.rows;

    if (!GROQ_API_KEY) {
      return res.json({ reply: generateRuleBasedResponse(message, tickets) });
    }

    let ticketContext = '';
    if (tickets.length > 0) {
      ticketContext = '\nUser tickets:\n' + tickets.map(t =>
        `- ${t.ticket_number}: [${t.status}] ${t.department_name} — "${t.description.substring(0,60)}"${t.admin_response ? ` | Admin: "${t.admin_response.substring(0,60)}"` : ''}`
      ).join('\n');
    }

    const systemPrompt = `You are the SAPS iLodge AI Support Assistant for the South African Police Service ticket management system.
Help users with ticket tracking, department info (IT, Finance, HR, Operations), lodging complaints, priorities (High:24h, Medium:48h, Low:72h), and escalation.
Current user: ${req.user.name} (Role: ${req.user.role})${ticketContext}
Be concise, professional, and helpful. Speak in English appropriate for South African government service.`;

    const Groq = require('groq-sdk');
    const groq = new Groq({ apiKey: GROQ_API_KEY });
    const completion = await groq.chat.completions.create({
      model: 'llama3-8b-8192',
      max_tokens: 1000,
      messages: [{ role: 'system', content: systemPrompt }, ...(history || []), { role: 'user', content: message }],
    });

    res.json({ reply: completion.choices[0]?.message?.content || 'Could not process your request.' });
  } catch (err) {
    console.error('Chatbot error:', err);
    res.status(500).json({ reply: 'AI service temporarily unavailable. Please try again shortly.' });
  }
});

function generateRuleBasedResponse(message, tickets) {
  const text = message.toLowerCase();
  if (/status|track|where|progress/.test(text)) {
    if (tickets.length === 0) return 'You have no tickets yet. Lodge a new complaint from your dashboard.';
    const t = tickets[0];
    return `Your latest ticket is ${t.ticket_number} — Status: ${t.status} (${t.department_name}). ${t.admin_response ? 'Admin: ' + t.admin_response : 'Awaiting admin response.'}`;
  }
  if (/time|how long|sla|resolve/.test(text)) return 'Resolution times: High Priority: 24h | Medium: 48h | Low: 72h';
  if (/department|it|finance|hr|operations/.test(text)) return 'Departments: IT (computers), Finance (salary), HR (leave/discipline), Operations (vehicles/patrol). AI auto-routes your complaint.';
  if (/escalat|urgent/.test(text)) return 'To escalate: set priority to High, or use "Chat with Admin" in the chatbot to reach an admin directly.';
  if (/lodge|submit|new/.test(text)) return 'To lodge: click "Lodge Complaint", select your station, describe your issue, choose priority and submit. You get a ticket number immediately.';
  return 'I can help with ticket tracking, department info, lodging complaints, and escalation. Ask a specific question or use "Chat with Admin" for human support.';
}

// ----------------------------------------------------------------------------
// Chat Messages
// ----------------------------------------------------------------------------
app.post('/api/chat/messages', authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });
  try {
    await pool.query(
      `INSERT INTO chat_messages (user_id, message, is_admin_reply) VALUES ($1, $2, FALSE)`,
      [req.user.id, message]
    );
    res.status(201).json({ message: 'Message sent' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/chat/messages', authenticateToken, async (req, res) => {
  try {
    let query, params = [];
    if (req.user.role === 'admin') {
      query = `SELECT cm.*, u.full_name, u.role FROM chat_messages cm JOIN users u ON cm.user_id = u.id ORDER BY cm.created_at DESC`;
    } else {
      query = `SELECT cm.*, u.full_name, u.role FROM chat_messages cm JOIN users u ON cm.user_id = u.id WHERE cm.user_id = $1 OR cm.target_user_id = $2 ORDER BY cm.created_at ASC`;
      params = [req.user.id, req.user.id];
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.post('/api/chat/reply', authenticateToken, requireRole(['admin']), async (req, res) => {
  const { targetUserId, message } = req.body;
  if (!message || !targetUserId) return res.status(400).json({ error: 'Target user and message required' });
  try {
    await pool.query(
      `INSERT INTO chat_messages (user_id, target_user_id, message, is_admin_reply) VALUES ($1, $2, $3, TRUE)`,
      [req.user.id, targetUserId, message]
    );
    res.status(201).json({ message: 'Reply sent' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send reply' });
  }
});

// ----------------------------------------------------------------------------
// Admin: Users
// ----------------------------------------------------------------------------
app.get('/api/admin/users', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, full_name, role, is_active, last_login, created_at,
       (SELECT COUNT(*) FROM tickets WHERE tickets.user_id = users.id) as ticket_count
       FROM users ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.delete('/api/admin/users/:userId', authenticateToken, requireRole(['admin']), async (req, res) => {
  const { userId } = req.params;
  if (userId === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ----------------------------------------------------------------------------
// Dashboard Stats
// ----------------------------------------------------------------------------
app.get('/api/dashboard/stats', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT COUNT(*) as total_tickets,
             SUM(CASE WHEN status = 'Pending'     THEN 1 ELSE 0 END) as pending,
             SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) as in_progress,
             SUM(CASE WHEN status = 'Resolved'    THEN 1 ELSE 0 END) as resolved,
             SUM(CASE WHEN status = 'Closed'      THEN 1 ELSE 0 END) as closed,
             ROUND(AVG(CASE WHEN closed_at IS NOT NULL
               THEN EXTRACT(EPOCH FROM (closed_at - opened_at))/3600
               ELSE NULL END)::numeric, 1) as avg_resolution_hours
      FROM tickets`
    );
    const deptStats = await pool.query('SELECT * FROM department_performance_view');
    const unresponded = await pool.query(
      `SELECT COUNT(*) as count FROM tickets t LEFT JOIN ticket_responses tr ON t.id = tr.ticket_id WHERE tr.id IS NULL AND t.status != 'Closed'`
    );
    const pendingChat = await pool.query(
      `SELECT COUNT(*) as count FROM chat_messages WHERE is_admin_reply = FALSE`
    );
    res.json({
      stats: stats.rows[0],
      departmentStats: deptStats.rows,
      unrespondedTickets: unresponded.rows[0].count,
      pendingChatMessages: pendingChat.rows[0].count,
    });
  } catch (err) {
    console.error('Dashboard stats error:', err);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// ----------------------------------------------------------------------------
// Police Stations
// ----------------------------------------------------------------------------
app.get('/api/stations', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, station_code, station_name, province FROM police_stations WHERE is_active = TRUE ORDER BY station_name'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch stations' });
  }
});

// ----------------------------------------------------------------------------
// Serve frontend for all non-API routes (SPA fallback)
// ----------------------------------------------------------------------------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ----------------------------------------------------------------------------
// Start Server
// ----------------------------------------------------------------------------
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 SAPS iLodge API running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
});