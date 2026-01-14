const express = require('express')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')
require('dotenv').config()
const app = express()
const port = 3001
const JWT_SECRET = process.env.JWT_SECRET

app.use(cors())
app.use(express.json())

const db = new sqlite3.Database('./database.db', (err) =>{
    if(err){
        console.error(err.message)
    }
    console.log('connected to the SQLite Database.')
})

db.run(`CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT unique,
    password TEXT
    )`)

//API ENDPOINT
app.post('/register',async(req,res) =>{
    const {username,password} = req.body;
    if(!username || !password){
        return res.status(400).json({message : 'Username and password are required'})
    }
    const hashedPassword = await bcrypt.hash(password,10)
    const sql = `INSERT INTO user (username,password) VALUES(?,?)`

    db.run(sql, [username,hashedPassword],function(err){
        if(err){
            if(err.errno === 19){
                return res.status(409).json({message : 'Username already exists'})
            }
            return res.status(500).json({ message : 'Database error'})
        }
        res.status(201).json({message : 'User registered successfully',userId: this.lastID})
    })
})

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    // 1. ค้นหา User ในฐานข้อมูลจาก Username
    const sql = `SELECT * FROM user WHERE username = ?`;
    
    db.get(sql, [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        
        // 2. ถ้าไม่เจอ User
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        try {
            // 3. เปรียบเทียบรหัสผ่านที่ส่งมา กับรหัสผ่านที่ Hash ไว้ใน DB
            const isMatch = await bcrypt.compare(password, user.password);
            
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid username or password' });
            }

            // 4. ถ้าผ่านหมด ให้ตอบกลับ (ในอนาคตคุณอาจจะส่ง JWT Token ตรงนี้)
            res.status(200).json({ 
                message: 'Login successful', 
                user: { id: user.id, username: user.username } 
            });

        } catch (error) {
            res.status(500).json({ message: 'Error during password verification' });
        }
    });
});


app.listen(port,()=>{
    console.log(`Server running on port ${port}`);
});