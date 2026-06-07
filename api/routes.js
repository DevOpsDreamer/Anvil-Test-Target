/**
 * Express API routes
 * VULNERABLE: Multiple injection issues for AEGIS JS scanner testing
 */

const express = require('express');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const db = require('./database');

const router = express.Router();

// VULNERABLE: SQL Injection in Node.js (CWE-89)
// Exploit: GET /users?id=1 OR 1=1
router.get('/users', async (req, res) => {
    const userId = req.query.id;
    // VULNERABLE: template literal in SQL query with req.query
    const query = `SELECT * FROM users WHERE id = ${req.query.id}`;
    try {
        const results = await db.query(query);
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// VULNERABLE: Command Injection (CWE-78)
// Exploit: GET /run?cmd=ls;cat /etc/passwd
router.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    // VULNERABLE: exec() with user-controlled input
    exec(req.query.cmd, (error, stdout, stderr) => {
        res.json({ output: stdout, error: stderr });
    });
});

// VULNERABLE: XSS (CWE-79)
// Exploit: GET /display?msg=<script>alert(document.cookie)</script>
router.get('/display', (req, res) => {
    const message = req.query.msg;
    // VULNERABLE: res.send with unsanitized request data
    res.send(`<html><body><h1>${req.query.msg}</h1></body></html>`);
});

// VULNERABLE: Path Traversal (CWE-22)
// Exploit: GET /read?file=../../etc/passwd
router.get('/read', (req, res) => {
    const filename = req.query.file;
    // VULNERABLE: fs.readFileSync with req.query directly
    try {
        const content = fs.readFileSync(req.query.file, 'utf8');
        res.json({ content });
    } catch (err) {
        res.status(404).json({ error: 'File not found' });
    }
});

// VULNERABLE: Path Traversal via path.join (CWE-22)
router.get('/static', (req, res) => {
    // VULNERABLE: path.join with __dirname and req.query
    const filePath = path.join(__dirname, 'public', req.query.name);
    res.sendFile(filePath);
});

module.exports = router;
