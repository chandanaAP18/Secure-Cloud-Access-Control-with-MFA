-- SQLite
-- List all important application tables
SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'accounts_%' OR name LIKE 'auditlog_%');

-- View all Users (Admin and Standard Users)
SELECT id, email, role, is_active, date_joined FROM accounts_user ORDER BY date_joined DESC;

-- View Login Logs / Audit Trail
SELECT id, email, status, ip_address, is_unusual, detail 
FROM auditlog_loginactivity 
ORDER BY id DESC LIMIT 20;
