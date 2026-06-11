// ============================================================================
// SAPS iLodge - Backend API Server (Week 2 Enhanced)
// Technology: Node.js + Express + MySQL2 + bcrypt + JWT + Claude AI Chatbot
// ============================================================================

require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// ----------------------------------------------------------------------------
// Database Connection Pool
// ----------------------------------------------------------------------------
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'saps_user',
  password: process.env.DB_PASSWORD || 'YourSecurePassword123!',
  database: process.env.DB_NAME || 'saps_ilodge',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
});

// JWT Secret
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
  const [cached] = await pool.execute(
    'SELECT department_code, reason, confidence FROM ai_routing_cache WHERE text_hash = ?',
    [textHash]
  );
  if (cached.length > 0) {
    return { department: cached[0].department_code, reason: cached[0].reason, confidence: cached[0].confidence, cached: true };
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
Reply ONLY with valid JSON: {"department":"FIN","reason":"brief explanation","confidence":0.95}`
        },
        { role: 'user', content: `Route this SAPS complaint: "${description}"` }
      ],
      temperature: 0.1,
      max_tokens: 150,
    });
    const text = completion.choices[0].message.content.trim();
    const clean = text.replace(/```json|```/g, '').trim();
    const result = JSON.parse(clean);
    result.cached = false;
    await pool.execute(
      `INSERT INTO ai_routing_cache (text_hash, description_sample, department_code, reason, confidence)
       VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE department_code=VALUES(department_code), reason=VALUES(reason), confidence=VALUES(confidence)`,
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
    const [users] = await pool.execute(
      'SELECT id, email, full_name, role, password_hash, is_active FROM users WHERE email = ? AND role = ?',
      [email, role]
    );
    if (users.length === 0) return res.status(401).json({ error: 'Invalid credentials or role mismatch' });
    const user = users[0];
    if (!user.is_active) return res.status(401).json({ error: 'Account is deactivated' });
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    await pool.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
    await pool.execute(
      `INSERT INTO activity_logs (user_id, action, entity_type, ip_address, details) VALUES (?, 'login', 'user', ?, ?)`,
      [user.id, req.ip, JSON.stringify({ role: user.role })]
    );
    const token = jwt.sign({ id: user.id, email: user.email, name: user.full_name, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
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
    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) return res.status(409).json({ error: 'Email already registered' });
    const userId = `${role}_${Date.now()}`;
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.execute(
      `INSERT INTO users (id, email, password_hash, full_name, role, id_number, phone_number, station_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
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
             TIMESTAMPDIFF(HOUR, t.opened_at, NOW()) as hours_open,
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
    if (req.user.role === 'external') { query += ' WHERE t.user_id = ?'; params.push(req.user.id); }
    else if (req.user.role === 'staff') { query += ' WHERE t.user_id = ? OR t.assigned_to = ?'; params.push(req.user.id, req.user.id); }
    query += ' ORDER BY t.opened_at DESC';
    const [tickets] = await pool.execute(query, params);
    res.json(tickets);
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
    const [dept] = await pool.execute('SELECT id FROM departments WHERE dept_code = ?', [aiResult.department]);
    if (dept.length === 0) return res.status(500).json({ error: 'Invalid department routing' });
    const [lastTicket] = await pool.execute("SELECT ticket_number FROM tickets WHERE ticket_number LIKE 'SAPS-%' ORDER BY id DESC LIMIT 1");
    let lastNum = 2400;
    if (lastTicket.length > 0) { const match = lastTicket[0].ticket_number.match(/SAPS-(\d+)/); if (match) lastNum = parseInt(match[1]); }
    const ticketNumber = `SAPS-${lastNum + 1}`;
    await pool.execute(
      `INSERT INTO tickets (ticket_number, user_id, station_id, department_id, description, priority, ai_reason, source, ai_confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [ticketNumber, req.user.id, stationId, dept[0].id, description, priority || 'Medium', aiResult.reason, req.user.role === 'external' ? 'citizen_portal' : 'staff_portal', aiResult.confidence]
    );
    await pool.execute(
      `INSERT INTO activity_logs (user_id, action, entity_type, entity_id, details) VALUES (?, 'create_ticket', 'ticket', ?, ?)`,
      [req.user.id, ticketNumber, JSON.stringify({ department: aiResult.department, priority })]
    );
    res.status(201).json({ ticketNumber, department: aiResult.department, aiReason: aiResult.reason, confidence: aiResult.confidence, status: 'Pending' });
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
    const [result] = await pool.execute(
      `UPDATE tickets SET status = ?,
       opened_at = COALESCE(opened_at, ?),
       resolved_at = CASE WHEN ? = 'Resolved' AND resolved_at IS NULL THEN NOW() ELSE resolved_at END,
       closed_at = CASE WHEN ? = 'Closed' AND closed_at IS NULL THEN NOW() ELSE closed_at END
       WHERE ticket_number = ?`,
      [status, new Date(), status, status, ticketNumber]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Ticket not found' });
    await pool.execute(
      `INSERT INTO activity_logs (user_id, action, entity_type, entity_id, details) VALUES (?, 'update_status', 'ticket', ?, ?)`,
      [req.user.id, ticketNumber, JSON.stringify({ newStatus: status })]
    );
    res.json({ message: 'Ticket status updated', status });
  } catch (err) {
    console.error('Update status error:', err);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Admin responds to a ticket (visible to citizen/staff)
app.post('/api/tickets/:ticketNumber/respond', authenticateToken, requireRole(['admin']), async (req, res) => {
  const { ticketNumber } = req.params;
  const { response } = req.body;
  if (!response || !response.trim()) return res.status(400).json({ error: 'Response text is required' });
  try {
    const [ticket] = await pool.execute('SELECT id FROM tickets WHERE ticket_number = ?', [ticketNumber]);
    if (ticket.length === 0) return res.status(404).json({ error: 'Ticket not found' });
    // Upsert response (one official response per ticket, admin can update)
    await pool.execute(
      `INSERT INTO ticket_responses (ticket_id, responder_id, response_text)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE response_text = VALUES(response_text), updated_at = NOW()`,
      [ticket[0].id, req.user.id, response.trim()]
    );
    await pool.execute(
      `INSERT INTO activity_logs (user_id, action, entity_type, entity_id, details) VALUES (?, 'admin_response', 'ticket', ?, ?)`,
      [req.user.id, ticketNumber, JSON.stringify({ responseLength: response.length })]
    );
    res.json({ message: 'Response saved successfully' });
  } catch (err) {
    console.error('Admin response error:', err);
    res.status(500).json({ error: 'Failed to save response' });
  }
});

// Add comment to ticket
app.post('/api/tickets/:ticketNumber/comments', authenticateToken, async (req, res) => {
  const { ticketNumber } = req.params;
  const { comment, isInternal } = req.body;
  if (!comment) return res.status(400).json({ error: 'Comment is required' });
  try {
    const [ticket] = await pool.execute('SELECT id FROM tickets WHERE ticket_number = ?', [ticketNumber]);
    if (ticket.length === 0) return res.status(404).json({ error: 'Ticket not found' });
    await pool.execute(
      `INSERT INTO ticket_comments (ticket_id, user_id, comment, is_internal) VALUES (?, ?, ?, ?)`,
      [ticket[0].id, req.user.id, comment, isInternal || false]
    );
    res.status(201).json({ message: 'Comment added' });
  } catch (err) {
    console.error('Add comment error:', err);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// Get comments for a ticket
app.get('/api/tickets/:ticketNumber/comments', authenticateToken, async (req, res) => {
  const { ticketNumber } = req.params;
  try {
    const [ticket] = await pool.execute('SELECT id FROM tickets WHERE ticket_number = ?', [ticketNumber]);
    if (ticket.length === 0) return res.status(404).json({ error: 'Ticket not found' });
    let query = `SELECT tc.*, u.full_name, u.role FROM ticket_comments tc JOIN users u ON tc.user_id = u.id WHERE tc.ticket_id = ?`;
    const params = [ticket[0].id];
    if (!['admin', 'staff'].includes(req.user.role)) { query += ' AND tc.is_internal = FALSE'; }
    query += ' ORDER BY tc.created_at ASC';
    const [comments] = await pool.execute(query, params);
    res.json(comments);
  } catch (err) {
    console.error('Get comments error:', err);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

// ----------------------------------------------------------------------------
// AI Chatbot Endpoint (Week 2 Feature)
// Uses Claude AI via Anthropic API to answer questions about the SAPS system
// ----------------------------------------------------------------------------
app.post('/api/chatbot', authenticateToken, async (req, res) => {
  const { message, history } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });

  try {
    // Fetch user's tickets for context
    let ticketContext = '';
    const params = [];
    let query = `SELECT t.ticket_number, t.status, t.description, d.dept_name as department_name,
                        tr.response_text as admin_response
                 FROM tickets t
                 JOIN departments d ON t.department_id = d.id
                 LEFT JOIN ticket_responses tr ON t.id = tr.ticket_id
                 WHERE t.user_id = ? ORDER BY t.opened_at DESC LIMIT 10`;
    params.push(req.user.id);
    const [tickets] = await pool.execute(query, params);
    if (tickets.length > 0) {
      ticketContext = '\nUser tickets:\n' + tickets.map(t =>
        `- ${t.ticket_number}: [${t.status}] ${t.department_name} — "${t.description.substring(0,60)}"${t.admin_response ? ` | Admin: "${t.admin_response.substring(0,60)}"` : ''}`
      ).join('\n');
    }

    // Call Groq API for chatbot
    if (!GROQ_API_KEY) {
      // Fallback: rule-based responses if no API key
      const reply = generateRuleBasedResponse(message, tickets);
      return res.json({ reply });
    }

    const systemPrompt = `You are the SAPS iLodge AI Support Assistant for the South African Police Service ticket management system.

Help users with:
- Ticket status and tracking
- Department information (IT, Finance, HR, Operations)
- How to lodge complaints
- Ticket priorities and resolution times (High: 24h, Medium: 48h, Low: 72h)
- Escalation procedures
- AI routing explanation
- Understanding ticket statuses (Pending → In Progress → Resolved → Closed)

Current user: ${req.user.name} (Role: ${req.user.role})${ticketContext}

Be concise, professional, and helpful. Use the ticket data above to give specific answers. Speak in English appropriate for South African government service.`;

    const messages = [...(history || []), { role: 'user', content: message }];

    const Groq = require('groq-sdk');
    const groq = new Groq({ apiKey: GROQ_API_KEY });
    const completion = await groq.chat.completions.create({
      model: 'llama3-8b-8192',
      max_tokens: 1000,
      messages: [
        { role: 'system', content: systemPrompt },
        ...messages,
      ],
    });

    const reply = completion.choices[0]?.message?.content || 'I could not process your request. Please try again.';
    res.json({ reply });
  } catch (err) {
    console.error('Chatbot error:', err);
    res.status(500).json({ error: 'Chatbot service unavailable', reply: 'I apologise — the AI service is temporarily unavailable. Please try again shortly or contact admin directly.' });
  }
});

// Rule-based chatbot fallback (no API key required)
function generateRuleBasedResponse(message, tickets) {
  const text = message.toLowerCase();
  if (/status|track|where|progress/.test(text)) {
    if (tickets.length === 0) return 'You have no tickets in the system yet. You can lodge a new complaint from the dashboard.';
    const latest = tickets[0];
    return `Your most recent ticket is ${latest.ticket_number} with status: ${latest.status} (${latest.department_name}). ${latest.admin_response ? 'Admin response: ' + latest.admin_response : 'Awaiting admin response.'}`;
  }
  if (/department|it|finance|hr|operations/.test(text)) {
    return 'SAPS iLodge has 4 departments:\n• IT: Computer & system issues\n• Finance: Salary & payment issues\n• HR: Leave, discipline & personnel matters\n• Operations: Vehicles, patrol & facilities\n\nOur AI automatically routes your complaint to the correct department.';
  }
  if (/escalat|urgent|priority/.test(text)) {
    return 'To escalate an unresolved complaint: (1) Set priority to High when lodging. (2) Use the "Chat with Admin" tab in this chatbot. (3) If no response within SLA time, contact your station commander. High priority tickets are addressed within 24 hours.';
  }
  if (/time|how long|sla|resolve/.test(text)) {
    return 'Expected resolution times:\n• High Priority: 24 hours\n• Medium Priority: 48 hours\n• Low Priority: 72 hours\n\nThese are SLA targets. Complex issues may take longer. You will receive an admin response on your ticket when it is reviewed.';
  }
  if (/lodge|submit|new|create/.test(text)) {
    return 'To lodge a new complaint: (1) Click "Lodge Complaint" from your dashboard. (2) Select your police station. (3) Describe your issue in detail — the more detail you provide, the better our AI can route it. (4) Select priority and submit. You will receive a ticket number immediately.';
  }
  if (/ai|routing|automatic/.test(text)) {
    return 'Our AI Routing Engine analyses your complaint description and automatically routes it to the correct department (IT, Finance, HR, or Operations). It uses keyword analysis with 80–95% confidence. The routing reason and confidence score are shown on each ticket.';
  }
  return 'I can help you with ticket tracking, department information, lodging complaints, escalation, and understanding the SAPS iLodge system. Please ask a specific question or use the "Chat with Admin" tab to reach a human administrator.';
}

// ----------------------------------------------------------------------------
// Chat Messages (Live chat with admin)
// ----------------------------------------------------------------------------
app.post('/api/chat/messages', authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });
  try {
    await pool.execute(
      `INSERT INTO chat_messages (user_id, message, is_admin_reply) VALUES (?, ?, FALSE)`,
      [req.user.id, message]
    );
    res.status(201).json({ message: 'Message sent' });
  } catch (err) {
    console.error('Send chat message error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/chat/messages', authenticateToken, async (req, res) => {
  try {
    let query, params = [];
    if (req.user.role === 'admin') {
      query = `SELECT cm.*, u.full_name, u.role FROM chat_messages cm JOIN users u ON cm.user_id = u.id ORDER BY cm.created_at DESC`;
    } else {
      query = `SELECT cm.*, u.full_name, u.role FROM chat_messages cm JOIN users u ON cm.user_id = u.id WHERE cm.user_id = ? OR cm.target_user_id = ? ORDER BY cm.created_at ASC`;
      params = [req.user.id, req.user.id];
    }
    const [messages] = await pool.execute(query, params);
    res.json(messages);
  } catch (err) {
    console.error('Get chat messages error:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.post('/api/chat/reply', authenticateToken, requireRole(['admin']), async (req, res) => {
  const { targetUserId, message } = req.body;
  if (!message || !targetUserId) return res.status(400).json({ error: 'Target user and message required' });
  try {
    await pool.execute(
      `INSERT INTO chat_messages (user_id, target_user_id, message, is_admin_reply) VALUES (?, ?, ?, TRUE)`,
      [req.user.id, targetUserId, message]
    );
    res.status(201).json({ message: 'Reply sent' });
  } catch (err) {
    console.error('Admin reply error:', err);
    res.status(500).json({ error: 'Failed to send reply' });
  }
});

// ----------------------------------------------------------------------------
// Admin: Users
// ----------------------------------------------------------------------------
app.get('/api/admin/users', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [users] = await pool.execute(
      `SELECT id, email, full_name, role, is_active, last_login, created_at,
       (SELECT COUNT(*) FROM tickets WHERE tickets.user_id = users.id) as ticket_count
       FROM users ORDER BY created_at DESC`
    );
    res.json(users);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.delete('/api/admin/users/:userId', authenticateToken, requireRole(['admin']), async (req, res) => {
  const { userId } = req.params;
  if (userId === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
  try {
    await pool.execute('DELETE FROM users WHERE id = ?', [userId]);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ----------------------------------------------------------------------------
// Dashboard statistics
// ----------------------------------------------------------------------------
app.get('/api/dashboard/stats', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [stats] = await pool.execute(`
      SELECT COUNT(*) as total_tickets,
             SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) as pending,
             SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) as in_progress,
             SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) as resolved,
             SUM(CASE WHEN status = 'Closed' THEN 1 ELSE 0 END) as closed,
             ROUND(AVG(CASE WHEN closed_at IS NOT NULL THEN TIMESTAMPDIFF(HOUR, opened_at, closed_at) ELSE NULL END), 1) as avg_resolution_hours
      FROM tickets`
    );
    const [deptStats] = await pool.execute('SELECT * FROM department_performance_view');
    const [unrespondedTickets] = await pool.execute(
      `SELECT COUNT(*) as count FROM tickets t LEFT JOIN ticket_responses tr ON t.id = tr.ticket_id WHERE tr.id IS NULL AND t.status != 'Closed'`
    );
    const [pendingChatMessages] = await pool.execute(
      `SELECT COUNT(*) as count FROM chat_messages WHERE is_admin_reply = FALSE`
    );
    res.json({ stats: stats[0], departmentStats: deptStats, unrespondedTickets: unrespondedTickets[0].count, pendingChatMessages: pendingChatMessages[0].count });
  } catch (err) {
    console.error('Dashboard stats error:', err);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// Police stations
app.get('/api/stations', async (req, res) => {
  try {
    const [stations] = await pool.execute('SELECT id, station_code, station_name, province FROM police_stations WHERE is_active = TRUE ORDER BY station_name');
    res.json(stations);
  } catch (err) {
    console.error('Get stations error:', err);
    res.status(500).json({ error: 'Failed to fetch stations' });
  }
});

// ----------------------------------------------------------------------------
// Start Server
// ----------------------------------------------------------------------------
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 SAPS iLodge API Server running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔐 Auth: http://localhost:${PORT}/api/auth/login`);
  console.log(`🎫 Tickets: http://localhost:${PORT}/api/tickets`);
  console.log(`🤖 Chatbot: http://localhost:${PORT}/api/chatbot`);
  console.log(`💬 Chat: http://localhost:${PORT}/api/chat/messages`);
});

module.exports = { pool, routeWithAI };
