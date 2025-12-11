# command-gateway
Command Gateway
A secure command execution system with role-based access control, approval workflows, and comprehensive audit logging.

Features
Role-Based Access Control with admin and member roles
Rule Engine with regex-based command filtering
Credit System for usage tracking
Approval Workflow for sensitive commands
Comprehensive Audit Logging
Modern React-based UI
Built-in security protections
Architecture
Backend
Node.js and Express server
SQLite database for data persistence
RESTful API with API key authentication
Transaction support for critical operations
Comprehensive logging system
Frontend
Single-page application built with React
Real-time updates for approval requests
Responsive design
Admin dashboard for system management
Prerequisites
Node.js v14 or higher
npm or yarn package manager
Installation and Setup
Clone the Repository
bash
git clone <repository-url>
cd command-gateway
Backend Setup
bash
cd backend
npm install
Create a .env file in the backend directory:

env
NODE_ENV=development
PORT=3000
ADMIN_API_KEY=your-admin-key-here
FRONTEND_URL=http://localhost:8080
Start the backend server:

bash
npm start
The backend will start on http://localhost:3000 and display the Admin API Key in the console. Save this key as you'll need it to log in.

Frontend Setup
Open frontend/index.html in your browser, or serve it with a local server:

bash
cd frontend
python -m http.server 8080
Or using npx:

bash
npx serve .
Login
Use the Admin API Key displayed in the backend console to log in to the frontend.

Project Structure
command-gateway/
├── backend/
│   ├── server.js           # Main backend application
│   ├── package.json        # Backend dependencies
│   ├── database.db         # SQLite database (auto-generated)
│   └── .env               # Environment configuration
├── frontend/
│   ├── index.html         # Single-page application
│   └── vercel.json        # Vercel deployment config
└── README.md
Usage Guide
For Members
Login
Use your API key to access the system.

Submit Commands
Enter commands in the command submission form. Each command execution costs 1 credit.

View History
Check your command execution history in the History tab.

Monitor Credits
Track your remaining credits displayed in the header.

For Admins
Admins have access to all member features plus additional management capabilities:

Manage Rules
Create regex patterns to control command behavior:

AUTO_ACCEPT: Commands matching this pattern execute immediately
AUTO_REJECT: Commands are blocked
REQUIRE_APPROVAL: Commands need admin approval before execution
Handle Approvals
Review and approve or reject pending command requests from the Approvals tab.

User Management
Create new users with specified roles
Assign and modify user credits
View all system users
Audit Logs
View complete system activity logs including all actions performed by users.

Security Features
Default Security Rules
The system includes built-in protection against dangerous commands:

Pattern	Action	Description
:(){ :|:& };:	AUTO_REJECT	Fork bomb protection
rm\s+-rf\s+/	AUTO_REJECT	Filesystem destruction prevention
mkfs\.	AUTO_REJECT	Format command blocking
sudo\s+	REQUIRE_APPROVAL	Elevated privilege commands
git\s+(status|log|diff)	AUTO_ACCEPT	Safe git commands
^(ls|cat|pwd|echo)	AUTO_ACCEPT	Basic safe commands
Rule Priority
Rules are evaluated in priority order (lower priority number = higher precedence). The first matching rule determines the action taken.

Command Execution Flow
User submits a command
System checks user's credit balance
Command is matched against rules in priority order
Based on matched rule:
AUTO_ACCEPT: Executes immediately, deducts 1 credit
AUTO_REJECT: Rejected, no credit deducted
REQUIRE_APPROVAL: Queued for admin review, no credit deducted until approved
Result is logged and returned to user
API Documentation
Authentication
All API endpoints require the X-API-Key header. Admin-only endpoints return 403 for non-admin users.

Public Endpoints
Health Check
GET /health
Returns server status and configuration.

Get Current User
GET /api/me
Headers: X-API-Key: <your-api-key>
Returns current user information including role and credits.

User Endpoints
Submit Command
POST /api/commands
Headers: X-API-Key: <your-api-key>
Body: { "command_text": "ls -la" }
Submits a command for execution.

Get Command History
GET /api/commands
Headers: X-API-Key: <your-api-key>
Returns command history. Members see only their commands, admins see all commands.

List Rules
GET /api/rules
Headers: X-API-Key: <your-api-key>
Returns all configured rules.

Admin Endpoints
List Users
GET /api/users
Headers: X-API-Key: <admin-api-key>
Returns all system users.

Create User
POST /api/users
Headers: X-API-Key: <admin-api-key>
Body: { "role": "member" }
Creates a new user and returns their API key.

Update User Credits
PATCH /api/users/:id/credits
Headers: X-API-Key: <admin-api-key>
Body: { "credits": 100 }
Updates the credit balance for a user.

Create Rule
POST /api/rules
Headers: X-API-Key: <admin-api-key>
Body: { "pattern": "^git", "action": "AUTO_ACCEPT" }
Creates a new command rule.

Delete Rule
DELETE /api/rules/:id
Headers: X-API-Key: <admin-api-key>
Deletes an existing rule.

Get Pending Approvals
GET /api/approvals
Headers: X-API-Key: <admin-api-key>
Returns all pending approval requests.

Approve Request
POST /api/approvals/:id/approve
Headers: X-API-Key: <admin-api-key>
Approves a pending command request.

Reject Request
POST /api/approvals/:id/reject
Headers: X-API-Key: <admin-api-key>
Rejects a pending command request.

View Audit Logs
GET /api/audit
Headers: X-API-Key: <admin-api-key>
Returns system audit logs.

Database Schema
users
Column	Type	Description
id	INTEGER	Primary key
api_key	TEXT	Unique API key for authentication
role	TEXT	User role (admin or member)
credits	INTEGER	Available credits (default: 100)
created_at	DATETIME	Account creation timestamp
rules
Column	Type	Description
id	INTEGER	Primary key
pattern	TEXT	Regex pattern for command matching
action	TEXT	Action to take (AUTO_ACCEPT, AUTO_REJECT, REQUIRE_APPROVAL)
priority	INTEGER	Rule evaluation priority (lower = higher precedence)
created_at	DATETIME	Rule creation timestamp
commands
Column	Type	Description
id	INTEGER	Primary key
user_id	INTEGER	Foreign key to users table
command_text	TEXT	The command that was submitted
status	TEXT	Command status (executed, rejected, pending_approval)
matched_rule_id	INTEGER	Foreign key to rules table
credits_deducted	INTEGER	Number of credits deducted (0 or 1)
result	TEXT	Command execution result
created_at	DATETIME	Command submission timestamp
approval_requests
Column	Type	Description
id	INTEGER	Primary key
command_id	INTEGER	Foreign key to commands table
user_id	INTEGER	User who submitted the command
command_text	TEXT	The command text
status	TEXT	Request status (pending, approved, rejected)
approved_by	INTEGER	Admin who processed the request
created_at	DATETIME	Request creation timestamp
resolved_at	DATETIME	Request resolution timestamp
audit_logs
Column	Type	Description
id	INTEGER	Primary key
user_id	INTEGER	User who performed the action
action	TEXT	Action type
details	TEXT	JSON string with action details
created_at	DATETIME	Action timestamp
Deployment
Backend Deployment (Render)
Create a new Web Service on Render
Connect your Git repository
Configure environment variables:
NODE_ENV=production
ADMIN_API_KEY=your-secure-random-key
FRONTEND_URL=https://your-frontend-url.vercel.app
Set build command: cd backend && npm install
Set start command: cd backend && npm start
Deploy the service
Frontend Deployment (Vercel)
Update the API_URL in frontend/index.html to point to your deployed backend
Push changes to your Git repository
Import the project in Vercel
Deploy
Alternatively, use Vercel CLI:

bash
cd frontend
vercel
Environment Variables
Backend
NODE_ENV: Set to "production" for production deployment
PORT: Server port (default: 3000)
ADMIN_API_KEY: Static admin API key (recommended for production)
FRONTEND_URL: Frontend URL for CORS configuration
Testing
Test Commands
Try these commands to test system functionality:

Safe commands (auto-accepted):

bash
ls -la
pwd
echo "Hello World"
git status
Commands requiring approval:

bash
sudo apt update
sudo systemctl restart nginx
Dangerous commands (auto-rejected):

bash
rm -rf /
:(){ :|:& };:
mkfs.ext4 /dev/sda1
Testing Workflow
Login with a member account
Submit various commands to test rule matching
Observe credit deduction for executed commands
Submit a command requiring approval
Login with admin account
Review and process the approval request
Check audit logs for all activities
Contributing
Contributions are welcome. Please follow these guidelines:

Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add some amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request
Coding Standards
Use meaningful variable and function names
Add comments for complex logic
Follow existing code style and formatting
Write clear commit messages
Update documentation as needed
Known Issues
Backend uses in-memory SQLite database in production on Render free tier (data is lost on restart)
Admin API key regenerates on backend restart if not set via environment variable
Command execution is currently mocked (returns simulated output)
Future Enhancements
Persistent storage solution for production environments
Real command execution capability with sandboxing
Per-user rate limiting
Email notifications for approval requests
Real-time command output streaming
Multi-level approval workflows
Integration with external notification systems (Slack, Microsoft Teams)
Command templating and parameterization
Scheduled and recurring command execution
Command output history and search
Export audit logs to external systems
Two-factor authentication support
API key rotation and expiration
Webhook support for external integrations
License
This project is licensed under the MIT License. See the LICENSE file for details.

Support
For bug reports and feature requests, please open an issue on GitHub.

For security vulnerabilities, please email security@example.com instead of opening a public issue.

