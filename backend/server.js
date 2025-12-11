const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());

// CORS Configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'file://',
  // Add your Vercel URL after deployment:
  process.env.FRONTEND_URL || ''
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (origin.startsWith('file://')) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || origin.endsWith('.vercel.app')) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all for now
    }
  },
  credentials: true
}));

// Database Configuration
// In production (Render), use in-memory but with better admin key handling
const isProduction = process.env.NODE_ENV === 'production';
const useInMemory = isProduction; // Use in-memory in production (Render free tier)

let db;
if (useInMemory) {
  db = new sqlite3.Database(':memory:', (err) => {
    if (err) {
      console.error('❌ Database connection error:', err);
    } else {
      console.log('✅ Database connected (in-memory)');
    }
  });
} else {
  const DB_PATH = path.join(__dirname, 'database.db');
  db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
      console.error('❌ Database connection error:', err);
    } else {
      console.log('✅ Database connected (file-based)');
      console.log('💾 Database path:', DB_PATH);
    }
  });
}

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,
    credits INTEGER NOT NULL DEFAULT 100,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL,
    priority INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    command_text TEXT NOT NULL,
    status TEXT NOT NULL,
    matched_rule_id INTEGER,
    credits_deducted INTEGER DEFAULT 0,
    result TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS approval_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    command_text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approved_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    FOREIGN KEY(command_id) REFERENCES commands(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(approved_by) REFERENCES users(id)
  )`);

  // Admin key handling - use environment variable if set, otherwise generate
  const adminKey = process.env.ADMIN_API_KEY || crypto.randomBytes(16).toString('hex');
  
  db.get('SELECT * FROM users WHERE role = ?', ['admin'], (err, row) => {
    if (!row) {
      db.run('INSERT INTO users (api_key, role, credits) VALUES (?, ?, ?)', 
        [adminKey, 'admin', 1000], function(err) {
          if (!err) {
            console.log('');
            console.log('═══════════════════════════════════════════');
            console.log('🔑 ADMIN API KEY:');
            console.log(adminKey);
            if (!process.env.ADMIN_API_KEY) {
              console.log('');
              console.log('⚠️  IMPORTANT: Set this as ADMIN_API_KEY');
              console.log('   environment variable in Render to keep');
              console.log('   it consistent across restarts!');
            }
            console.log('═══════════════════════════════════════════');
            console.log('');
          }
        });
    } else {
      console.log('✅ Admin user exists - API Key:', row.api_key);
    }
  });

  // Seed default rules
  db.get('SELECT COUNT(*) as count FROM rules', [], (err, row) => {
    if (row && row.count === 0) {
      const defaultRules = [
        [':(){ :|:& };:', 'AUTO_REJECT', 1],
        ['rm\\s+-rf\\s+/', 'AUTO_REJECT', 2],
        ['mkfs\\.', 'AUTO_REJECT', 3],
        ['sudo\\s+', 'REQUIRE_APPROVAL', 4],
        ['git\\s+(status|log|diff)', 'AUTO_ACCEPT', 5],
        ['^(ls|cat|pwd|echo)', 'AUTO_ACCEPT', 6]
      ];

      const stmt = db.prepare('INSERT INTO rules (pattern, action, priority) VALUES (?, ?, ?)');
      defaultRules.forEach(rule => stmt.run(rule));
      stmt.finalize();
      console.log('✅ Default security rules created');
    }
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: isProduction ? 'production' : 'development',
    storage: useInMemory ? 'in-memory' : 'file-based'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Command Gateway API',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      health: '/health',
      api: '/api/*'
    }
  });
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

  if (req.user.credits <= 0) {
    return res.status(400).json({ error: 'Insufficient credits' });
  }

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
    } else if (matchedRule.action === 'REQUIRE_APPROVAL') {
      db.get(
        'SELECT * FROM approval_requests WHERE user_id = ? AND command_text = ? AND status = "approved" ORDER BY created_at DESC LIMIT 1',
        [req.user.id, command_text],
        (err, approval) => {
          if (approval) {
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
                      message: 'Command executed successfully (was pre-approved)',
                      credits: req.user.credits - 1,
                      result: `[MOCKED] Command "${command_text}" executed successfully`
                    });
                  });
                }
              );
            });
          } else {
            db.run(
              'INSERT INTO commands (user_id, command_text, status, matched_rule_id) VALUES (?, ?, ?, ?)',
              [req.user.id, command_text, 'pending_approval', matchedRule.id],
              function(err) {
                if (err) return res.status(500).json({ error: 'Database error' });

                const commandId = this.lastID;

                db.run(
                  'INSERT INTO approval_requests (command_id, user_id, command_text) VALUES (?, ?, ?)',
                  [commandId, req.user.id, command_text],
                  function(err) {
                    if (err) return res.status(500).json({ error: 'Database error' });
                    
                    logAudit(req.user.id, 'APPROVAL_REQUESTED', { command_text, rule: matchedRule.pattern });
                    
                    res.json({
                      id: commandId,
                      status: 'pending_approval',
                      message: 'Command requires approval from admin. Submit again after approval.',
                      credits: req.user.credits
                    });
                  }
                );
              }
            );
          }
        }
      );
    } else if (matchedRule.action === 'AUTO_ACCEPT') {
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

// Get approval requests
app.get('/api/approvals', authenticate, requireAdmin, (req, res) => {
  db.all(
    `SELECT ar.*, u.api_key as user_key 
     FROM approval_requests ar 
     JOIN users u ON ar.user_id = u.id 
     WHERE ar.status = 'pending'
     ORDER BY ar.created_at DESC`,
    [],
    (err, requests) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(requests);
    }
  );
});

// Approve/reject request
app.post('/api/approvals/:id/:action', authenticate, requireAdmin, (req, res) => {
  const { id, action } = req.params;

  if (!['approve', 'reject'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action' });
  }

  const newStatus = action === 'approve' ? 'approved' : 'rejected';

  db.run(
    'UPDATE approval_requests SET status = ?, approved_by = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND status = "pending"',
    [newStatus, req.user.id, id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Request not found or already processed' });
      }

      logAudit(req.user.id, `APPROVAL_${action.toUpperCase()}D`, { request_id: id });
      
      res.json({ 
        success: true, 
        message: `Request ${action}d successfully`,
        status: newStatus
      });
    }
  );
});

// Get rules
app.get('/api/rules', authenticate, (req, res) => {
  db.all('SELECT * FROM rules ORDER BY priority', [], (err, rules) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rules);
  });
});

// Create rule
app.post('/api/rules', authenticate, requireAdmin, (req, res) => {
  const { pattern, action } = req.body;

  if (!pattern || !action) {
    return res.status(400).json({ error: 'Pattern and action required' });
  }

  if (!['AUTO_ACCEPT', 'AUTO_REJECT', 'REQUIRE_APPROVAL'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action' });
  }

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

// Delete rule
app.delete('/api/rules/:id', authenticate, requireAdmin, (req, res) => {
  db.run('DELETE FROM rules WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    logAudit(req.user.id, 'RULE_DELETED', { rule_id: req.params.id });
    res.json({ deleted: this.changes });
  });
});

// Get all users
app.get('/api/users', authenticate, requireAdmin, (req, res) => {
  db.all('SELECT id, api_key, role, credits, created_at FROM users', [], (err, users) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(users);
  });
});

// Create user
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

// Update user credits
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

// Get audit logs
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
app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('═══════════════════════════════════════════');
  console.log('🚀 Command Gateway Backend');
  console.log('═══════════════════════════════════════════');
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌍 Environment: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
  console.log(`💾 Storage: ${useInMemory ? 'In-Memory' : 'File-Based'}`);
  console.log(`🔗 Health Check: http://localhost:${PORT}/health`);
  console.log('═══════════════════════════════════════════');
  console.log('');
});