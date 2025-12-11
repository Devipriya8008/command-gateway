const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database(':memory:');

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,
    credits INTEGER NOT NULL DEFAULT 100,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL,
    priority INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    command_text TEXT NOT NULL,
    status TEXT NOT NULL,
    matched_rule_id INTEGER,
    credits_deducted INTEGER DEFAULT 0,
    result TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Seed default admin
  const adminKey = crypto.randomBytes(16).toString('hex');
  db.run('INSERT INTO users (api_key, role, credits) VALUES (?, ?, ?)', 
    [adminKey, 'admin', 100], function(err) {
      if (!err) console.log('🔑 Admin API Key:', adminKey);
    });

  // Seed default rules
  const defaultRules = [
    [':(){ :|:& };:', 'AUTO_REJECT', 1],
    ['rm\\s+-rf\\s+/', 'AUTO_REJECT', 2],
    ['mkfs\\.', 'AUTO_REJECT', 3],
    ['git\\s+(status|log|diff)', 'AUTO_ACCEPT', 4],
    ['^(ls|cat|pwd|echo)', 'AUTO_ACCEPT', 5]
  ];

  const stmt = db.prepare('INSERT INTO rules (pattern, action, priority) VALUES (?, ?, ?)');
  defaultRules.forEach(rule => stmt.run(rule));
  stmt.finalize();
});

// Auth middleware
const authenticate = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  db.get('SELECT * FROM users WHERE api_key = ?', [apiKey], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Audit logging
const logAudit = (userId, action, details) => {
  db.run('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)',
    [userId, action, JSON.stringify(details)]);
};

// Routes

// Get current user info
app.get('/api/me', authenticate, (req, res) => {
  res.json({
    id: req.user.id,
    role: req.user.role,
    credits: req.user.credits
  });
});

// Submit command
app.post('/api/commands', authenticate, (req, res) => {
  const { command_text } = req.body;

  if (!command_text || command_text.trim() === '') {
    return res.status(400).json({ error: 'Command text required' });
  }

  // Check credits
  if (req.user.credits <= 0) {
    return res.status(400).json({ error: 'Insufficient credits' });
  }

  // Match against rules
  db.all('SELECT * FROM rules ORDER BY priority', [], (err, rules) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    let matchedRule = null;
    for (const rule of rules) {
      try {
        const regex = new RegExp(rule.pattern);
        if (regex.test(command_text)) {
          matchedRule = rule;
          break;
        }
      } catch (e) {
        console.error('Invalid regex in rule:', rule.id);
      }
    }

    if (!matchedRule) {
      // No match - reject by default
      db.run(
        'INSERT INTO commands (user_id, command_text, status) VALUES (?, ?, ?)',
        [req.user.id, command_text, 'rejected'],
        function(err) {
          if (err) return res.status(500).json({ error: 'Database error' });
          logAudit(req.user.id, 'COMMAND_REJECTED', { command_text, reason: 'No matching rule' });
          res.json({ 
            id: this.lastID,
            status: 'rejected', 
            message: 'No matching rule found',
            credits: req.user.credits
          });
        }
      );
      return;
    }

    if (matchedRule.action === 'AUTO_REJECT') {
      db.run(
        'INSERT INTO commands (user_id, command_text, status, matched_rule_id) VALUES (?, ?, ?, ?)',
        [req.user.id, command_text, 'rejected', matchedRule.id],
        function(err) {
          if (err) return res.status(500).json({ error: 'Database error' });
          logAudit(req.user.id, 'COMMAND_REJECTED', { command_text, rule: matchedRule.pattern });
          res.json({ 
            id: this.lastID,
            status: 'rejected', 
            message: 'Command blocked by security rule',
            credits: req.user.credits
          });
        }
      );
    } else if (matchedRule.action === 'AUTO_ACCEPT') {
      // Execute command (mocked)
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        
        db.run(
          'INSERT INTO commands (user_id, command_text, status, matched_rule_id, credits_deducted, result) VALUES (?, ?, ?, ?, ?, ?)',
          [req.user.id, command_text, 'executed', matchedRule.id, 1, `[MOCKED] Command "${command_text}" executed successfully`],
          function(err) {
            if (err) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: 'Database error' });
            }

            const commandId = this.lastID;

            db.run('UPDATE users SET credits = credits - 1 WHERE id = ?', [req.user.id], (err) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: 'Failed to deduct credits' });
              }

              db.run('COMMIT');
              logAudit(req.user.id, 'COMMAND_EXECUTED', { command_text, rule: matchedRule.pattern });
              
              res.json({ 
                id: commandId,
                status: 'executed', 
                message: 'Command executed successfully',
                credits: req.user.credits - 1,
                result: `[MOCKED] Command "${command_text}" executed successfully`
              });
            });
          }
        );
      });
    }
  });
});

// Get command history
app.get('/api/commands', authenticate, (req, res) => {
  const query = req.user.role === 'admin' 
    ? 'SELECT c.*, u.api_key as user_key FROM commands c JOIN users u ON c.user_id = u.id ORDER BY c.created_at DESC LIMIT 50'
    : 'SELECT * FROM commands WHERE user_id = ? ORDER BY created_at DESC LIMIT 50';
  
  const params = req.user.role === 'admin' ? [] : [req.user.id];

  db.all(query, params, (err, commands) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(commands);
  });
});

// Get rules (all users can view)
app.get('/api/rules', authenticate, (req, res) => {
  db.all('SELECT * FROM rules ORDER BY priority', [], (err, rules) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rules);
  });
});

// Create rule (admin only)
app.post('/api/rules', authenticate, requireAdmin, (req, res) => {
  const { pattern, action } = req.body;

  if (!pattern || !action) {
    return res.status(400).json({ error: 'Pattern and action required' });
  }

  if (!['AUTO_ACCEPT', 'AUTO_REJECT'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action' });
  }

  // Validate regex
  try {
    new RegExp(pattern);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid regex pattern: ' + e.message });
  }

  db.get('SELECT MAX(priority) as max_priority FROM rules', [], (err, row) => {
    const priority = (row.max_priority || 0) + 1;
    
    db.run(
      'INSERT INTO rules (pattern, action, priority) VALUES (?, ?, ?)',
      [pattern, action, priority],
      function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        logAudit(req.user.id, 'RULE_CREATED', { pattern, action });
        res.json({ id: this.lastID, pattern, action, priority });
      }
    );
  });
});

// Delete rule (admin only)
app.delete('/api/rules/:id', authenticate, requireAdmin, (req, res) => {
  db.run('DELETE FROM rules WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    logAudit(req.user.id, 'RULE_DELETED', { rule_id: req.params.id });
    res.json({ deleted: this.changes });
  });
});

// Get all users (admin only)
app.get('/api/users', authenticate, requireAdmin, (req, res) => {
  db.all('SELECT id, api_key, role, credits, created_at FROM users', [], (err, users) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(users);
  });
});

// Create user (admin only)
app.post('/api/users', authenticate, requireAdmin, (req, res) => {
  const { role } = req.body;

  if (!role || !['admin', 'member'].includes(role)) {
    return res.status(400).json({ error: 'Valid role required (admin or member)' });
  }

  const apiKey = crypto.randomBytes(16).toString('hex');

  db.run(
    'INSERT INTO users (api_key, role, credits) VALUES (?, ?, ?)',
    [apiKey, role, 100],
    function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      logAudit(req.user.id, 'USER_CREATED', { role, new_user_id: this.lastID });
      res.json({ 
        id: this.lastID, 
        api_key: apiKey, 
        role, 
        credits: 100,
        message: 'Save this API key - it will not be shown again!' 
      });
    }
  );
});

// Update user credits (admin only)
app.patch('/api/users/:id/credits', authenticate, requireAdmin, (req, res) => {
  const { credits } = req.body;

  if (typeof credits !== 'number' || credits < 0) {
    return res.status(400).json({ error: 'Valid credits amount required' });
  }

  db.run('UPDATE users SET credits = ? WHERE id = ?', [credits, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    logAudit(req.user.id, 'CREDITS_UPDATED', { user_id: req.params.id, new_credits: credits });
    res.json({ updated: this.changes });
  });
});

// Get audit logs (admin only)
app.get('/api/audit', authenticate, requireAdmin, (req, res) => {
  db.all(
    'SELECT a.*, u.api_key as user_key FROM audit_logs a JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 100',
    [],
    (err, logs) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(logs);
    }
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Command Gateway Backend running on port ${PORT}`);
});