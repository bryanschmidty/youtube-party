require('dotenv').config();
const express = require('express');
const app = express();
const server = require('http').createServer(app);
const io = require('socket.io')(server);
const sqlite3 = require('sqlite3').verbose();
const { google } = require('googleapis');
const ngrok = require('ngrok');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const ejs = require('ejs');
const bodyParser = require('body-parser');
const axios = require('axios');
const expressSession = require('express-session');
const sharedSession = require('express-socket.io-session');


// Set up SQLite database
const db = new sqlite3.Database('youtube-party.db');

// set up YouTube API
const API_KEY = process.env.YOUTUBE_API_KEY;
const youtube = google.youtube({ version: 'v3', auth: API_KEY });

// Set up Database
db.serialize(() => {
    migrateRoomsTable();
    migrateUsersTable();
    db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, google_id TEXT, name TEXT, email TEXT, avatar BLOB)');
    db.run('CREATE TABLE IF NOT EXISTS rooms (id INTEGER PRIMARY KEY, uuid TEXT, host_id INTEGER, name TEXT, private INTEGER, invite_code TEXT, allow_anon INTEGER)');
    db.run('CREATE TABLE IF NOT EXISTS user_rooms (user_id INTEGER, room_id INTEGER)');
    db.run('CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY, room_id INTEGER, timestamp TEXT, user_id INTEGER, message TEXT)');
    db.run('CREATE TABLE IF NOT EXISTS queues (id INTEGER PRIMARY KEY, room_id INTEGER, user_id INTEGER, video_id TEXT, title TEXT, thumbnail TEXT)');
});

function migrateRoomsTable() {
    db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='rooms' AND sql LIKE '%uuid%'", (err, row) => {
        if (!row) {
            db.run('ALTER TABLE rooms ADD COLUMN uuid TEXT');
            console.info('adding uuid column to rooms table');
        }
    });
}
function migrateUsersTable() {
    db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users' AND sql LIKE '%name%'", (err, row) => {
        if (!row) {
            db.run('ALTER TABLE users ADD COLUMN name TEXT');
            console.info('adding name column to users table');
        }
    });
    db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users' AND sql LIKE '%avatar%'", (err, row) => {
        if (!row) {
            db.run('ALTER TABLE users ADD COLUMN avatar BLOB');
            console.info('adding avatar column to users table');
        }
    });
}

async function findUserById(id) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
}

async function getUpdatedVideoQueue(roomId) {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM queues WHERE room_id = ?', [roomId], (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
}


// Configure Google OAuth
passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback"
    },
    (accessToken, refreshToken, profile, cb) => {
        const email = profile.emails[0].value;
        const name = profile.displayName;
        db.get('SELECT * FROM users WHERE google_id = ?', [profile.id], async (err, row) => {
            if (err) return cb(err);
            if (!row) {
                // get user avatar
                const response = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
                    headers: {Authorization: `Bearer ${accessToken}`}
                });
                const avatarData = Buffer.from(response.data.picture.replace(/^data:image\/\w+;base64,/, ''), 'base64');

                // User doesn't exist in database, insert them
                db.run('INSERT INTO users (google_id, email, name, avatar) VALUES (?, ?, ?, ?)', [profile.id, email, name, avatarData], () => {
                    // Fetch newly inserted user from database
                    db.get('SELECT * FROM users WHERE google_id = ?', [profile.id], (err, row) => {
                        if (err) return cb(err);
                        cb(null, row);
                    });
                });
            } else {
                // User already exists in database, return their record
                cb(null, row);
            }
        });
    }
));


// Configure Express
const session = expressSession({
    secret: 'e72bde9a924ebf6e2c83127652fb0f1d',
    resave: false,
    saveUninitialized: false,
});
app.use(session);

app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');
app.use(express.static('public'));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
    const user = await findUserById(id);

    if (user) {
        done(null, user);
    } else {
        done(new Error('User not found.'));
    }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/');
    }
);


// Configure ngrok
// (async () => {
//     const url = await ngrok.connect({
//         addr: process.env.PORT,
//         authtoken: process.env.NGROK_AUTH_TOKEN,
//     });
//     console.log(`Server running at ${url}`);
// })();


// Your routes and socket.io logic here

app.use(bodyParser.urlencoded({ extended: false }));

app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/');
    });
});


app.get('/', (req, res) => {
    const loggedIn = isAuthenticated(req);

    let query = 'SELECT rooms.*, user_rooms.user_id FROM rooms LEFT JOIN user_rooms ON rooms.id = user_rooms.room_id WHERE (private = 0 OR host_id = ? OR user_id = ?)';
    let userId = req.user ? req.user.id : null;
    let params = [userId, userId]
    if (!loggedIn) {
        query += ' AND allow_anon = 1';
    }
    query += ' ORDER BY id DESC';

    db.all(query, params, (err, rows) => {
        if (err) {
            throw err;
        }
        res.render('index', { loggedIn, rooms: rows });
    });
});

app.get('/host', (req, res) => {
    res.render('host');
});


app.post('/join-private-room', (req, res) => {
    const inviteCode = req.body.invite_code;
    db.get('SELECT * FROM rooms WHERE invite_code = ?', [inviteCode], (err, row) => {
        if (err || !row) {
            res.redirect('/');
        } else {
            res.redirect(`/room/${row.uuid}`);
        }
    });
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/auth/google');
}

app.post('/create-room', ensureAuthenticated, (req, res) => {
    const { v4: uuidv4 } = require('uuid');
    const crypto = require('crypto');
    const uuid = uuidv4();

    const roomName = req.body.room_name;
    const isPrivate = req.body.private ? 1 : 0;
    const allowAnon = req.body.allow_anon ? 1 : 0;
    const hostId = req.user.id;
    let inviteCode = '';


    if (isPrivate) {
        inviteCode = crypto.randomBytes(5).toString('hex');
    }

    db.run(
        'INSERT INTO rooms (host_id, name, private, allow_anon, uuid, invite_code) VALUES (?, ?, ?, ?, ?, ?)',
        [hostId, roomName, isPrivate, allowAnon, uuid, inviteCode]
        , function (err) {
            if (err) {
                throw err;
            }
            res.redirect(`/room/${uuid}`);
        });
});

app.get('/room/:uuid', (req, res) => {
    const uuid = req.params.uuid;

    db.get('SELECT * FROM rooms WHERE uuid = ?', [uuid], (err, room) => {
        if (err || !room) {
            return res.status(404).send('Room not found');
        }

        res.render('room', {
            room,
            user: req.user
        });
    });
});

app.get('/room/:uuid/messages', (req, res) => {
    let sql = 'SELECT chats.timestamp, chats.message, users.name ' +
        'FROM chats ' +
        'JOIN users ON chats.user_id = users.id ' +
        'JOIN rooms ON chats.room_id = rooms.id ' +
        'WHERE rooms.uuid = ? ' +
        'ORDER BY timestamp';
    db.all(sql, [req.params.uuid], (err, rows) => {
        if (err) throw err;
        res.send(rows);
    });
});

app.get('/search', ensureAuthenticated, async (req, res) => {
    const query = req.query.q;
    try {
        const response = await youtube.search.list({
            part: 'snippet',
            type: 'video',
            maxResults: 5,
            q: query
        });
        res.json(response.data);
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

function isAuthenticated(req) {
    return req.isAuthenticated();
}

io.use(sharedSession(session, {
    autoSave: true,
}));

io.on('connection', async (socket) => {
    const user = socket.handshake.session.passport ? await findUserById(socket.handshake.session.passport.user) : false;

    // Join a room
    socket.on('join-room', (roomId) => {
        let log = `joining room ${roomId}`;
        if (user) {
            log += `:  ${user.email} ${user.name}`;
        } else {
            log += ': anonymous';
        }
        console.log(log);
        socket.join(roomId);

        // Add user to user_rooms table
        if (socket.request.user) {
            db.run('INSERT OR IGNORE INTO user_rooms (user_id, room_id) VALUES (?, ?)', [socket.request.user.id, roomId], (err) => {
                if (err) {
                    throw err;
                }
            });
        }
    });

    // Leave a room
    socket.on('leave-room', (roomId) => {
        console.log(`leaving room ${roomId}`);
        socket.leave(roomId);
    });

    // Chat message
    socket.on('chat-message', (roomId, googleId, message) => {
        const timestamp = new Date().toISOString();

        db.get('SELECT id, name, avatar FROM users WHERE google_id = ?', [googleId], (err, row) => {
            if (err) {
                console.error(err);
            } else {
                db.run('INSERT INTO chats (room_id, timestamp, user_id, message) VALUES (?, ?, ?, ?)', [roomId, timestamp, row.id, message], (err) => {
                    if (err) {
                        console.error(err);
                    } else {
                        const name = row.name;
                        const avatar = row.avatar;
                        io.to(roomId).emit('chat-message', { message, name, avatar, timestamp });
                    }
                });
            }
        });
    });

    socket.on('player-state-change', (roomId, userId, state, time) => {
        console.log(roomId, state, time);
        io.to(roomId).emit('player-state-change', { userId, state, time })
    });

    socket.on('add-to-queue', async (roomId, userId, videoId, title, thumbnail) => {
        db.run('INSERT INTO queues (room_id, user_id, video_id, title, thumbnail) VALUES (?, ?, ?, ?, ?)', [roomId, userId, videoId, title, thumbnail], async (err) => {
            if (err) throw err;
            const updatedQueue = await getUpdatedVideoQueue(roomId);
            io.to(roomId).emit('update-queue', updatedQueue);
        });
    });

    socket.on('remove-from-queue', async (roomId, userId, videoId) => {
        db.run('DELETE FROM queues WHERE room_id = ? AND video_id = ?', [roomId, videoId], async (err) => {
            if (err) throw err;
            const updatedQueue = await getUpdatedVideoQueue(roomId);
            io.to(roomId).emit('update-queue', updatedQueue);
        });
    });
});

server.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});
