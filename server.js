const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = 3000;

const JWT_SECRET = "CHANGE_THIS_TO_A_LONG_SECRET_KEY";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

const db = new sqlite3.Database("./workers.db");

// --------------------
// DATABASE
// --------------------

db.serialize(() => {

    db.run(`
        CREATE TABLE IF NOT EXISTS workers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            worker_id TEXT UNIQUE,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            work TEXT NOT NULL,
            city TEXT NOT NULL,
            experience INTEGER DEFAULT 0,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS contractors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            company TEXT,
            city TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
});

// --------------------
// AUTH MIDDLEWARE
// --------------------

function authenticate(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            message: "Login required"
        });
    }

    const token = authHeader.split(" ")[1];

    try {

        const user = jwt.verify(token, JWT_SECRET);

        req.user = user;

        next();

    } catch (error) {

        return res.status(401).json({
            message: "Invalid or expired login"
        });

    }
}

// --------------------
// WORKER REGISTER
// --------------------

app.post("/api/workers/register", async (req, res) => {

    const {
        name,
        phone,
        password,
        work,
        city,
        experience,
        description
    } = req.body;

    if (!name || !phone || !password || !work || !city) {

        return res.status(400).json({
            message: "Please fill all required fields"
        });

    }

    try {

        const hashedPassword = await bcrypt.hash(password, 10);

        const workerId =
            "WRK" +
            Date.now().toString().slice(-8);

        const sql = `
            INSERT INTO workers
            (
                worker_id,
                name,
                phone,
                password,
                work,
                city,
                experience,
                description
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;

        db.run(
            sql,
            [
                workerId,
                name,
                phone,
                hashedPassword,
                work,
                city,
                experience || 0,
                description || ""
            ],
            function (err) {

                if (err) {

                    return res.status(500).json({
                        message: "Registration failed"
                    });

                }

                res.json({
                    success: true,
                    message: "Worker registered successfully",
                    worker_id: workerId
                });

            }
        );

    } catch (error) {

        res.status(500).json({
            message: "Server error"
        });

    }
});

// --------------------
// WORKER LOGIN
// --------------------

app.post("/api/workers/login", (req, res) => {

    const {
        worker_id,
        password
    } = req.body;

    db.get(
        "SELECT * FROM workers WHERE worker_id = ?",
        [worker_id],
        async (err, worker) => {

            if (err || !worker) {

                return res.status(401).json({
                    message: "Worker ID not found"
                });

            }

            const valid = await bcrypt.compare(
                password,
                worker.password
            );

            if (!valid) {

                return res.status(401).json({
                    message: "Wrong password"
                });

            }

            const token = jwt.sign(
                {
                    id: worker.id,
                    role: "worker"
                },
                JWT_SECRET,
                {
                    expiresIn: "7d"
                }
            );

            res.json({
                success: true,
                token,
                worker: {
                    id: worker.worker_id,
                    name: worker.name,
                    phone: worker.phone,
                    work: worker.work,
                    city: worker.city,
                    experience: worker.experience,
                    description: worker.description
                }
            });

        }
    );

});

// --------------------
// CONTRACTOR REGISTER
// --------------------

app.post("/api/contractors/register", async (req, res) => {

    const {
        name,
        phone,
        password,
        company,
        city
    } = req.body;

    if (!name || !phone || !password) {

        return res.status(400).json({
            message: "Required fields missing"
        });

    }

    const hashedPassword =
        await bcrypt.hash(password, 10);

    db.run(
        `
        INSERT INTO contractors
        (
            name,
            phone,
            password,
            company,
            city
        )
        VALUES (?, ?, ?, ?, ?)
        `,
        [
            name,
            phone,
            hashedPassword,
            company || "",
            city || ""
        ],
        function (err) {

            if (err) {

                return res.status(500).json({
                    message: "Registration failed"
                });

            }

            res.json({
                success: true,
                message: "Contractor registered"
            });

        }
    );

});

// --------------------
// CONTRACTOR LOGIN
// --------------------

app.post("/api/contractors/login", (req, res) => {

    const {
        phone,
        password
    } = req.body;

    db.get(
        "SELECT * FROM contractors WHERE phone = ?",
        [phone],
        async (err, contractor) => {

            if (err || !contractor) {

                return res.status(401).json({
                    message: "Account not found"
                });

            }

            const valid = await bcrypt.compare(
                password,
                contractor.password
            );

            if (!valid) {

                return res.status(401).json({
                    message: "Wrong password"
                });

            }

            const token = jwt.sign(
                {
                    id: contractor.id,
                    role: "contractor"
                },
                JWT_SECRET,
                {
                    expiresIn: "7d"
                }
            );

            res.json({
                success: true,
                token
            });

        }
    );

});

// --------------------
// SEARCH WORKERS
// --------------------

app.get("/api/workers", authenticate, (req, res) => {

    if (req.user.role !== "contractor") {

        return res.status(403).json({
            message: "Only contractors can search workers"
        });

    }

    const {
        work,
        city
    } = req.query;

    let sql = `
        SELECT
            worker_id,
            name,
            phone,
            work,
            city,
            experience,
            description
        FROM workers
        WHERE 1=1
    `;

    const params = [];

    if (work) {

        sql += " AND work LIKE ?";

        params.push(`%${work}%`);

    }

    if (city) {

        sql += " AND city LIKE ?";

        params.push(`%${city}%`);

    }

    db.all(
        sql,
        params,
        (err, workers) => {

            if (err) {

                return res.status(500).json({
                    message: "Search failed"
                });

            }

            res.json(workers);

        }
    );

});

// --------------------
// WORKER PROFILE
// --------------------

app.get("/api/worker/profile", authenticate, (req, res) => {

    if (req.user.role !== "worker") {

        return res.status(403).json({
            message: "Worker access only"
        });

    }

    db.get(
        `
        SELECT
            worker_id,
            name,
            phone,
            work,
            city,
            experience,
            description
        FROM workers
        WHERE id = ?
        `,
        [req.user.id],
        (err, worker) => {

            if (err || !worker) {

                return res.status(404).json({
                    message: "Worker not found"
                });

            }

            res.json(worker);

        }
    );

});

// --------------------
// START SERVER
// --------------------

app.listen(PORT, () => {

    console.log(
        `Server running at http://localhost:${PORT}`
    );

});
