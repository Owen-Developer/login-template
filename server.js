const express = require('express');
const app = express();
const bcrypt = require('bcryptjs');
app.use(express.json());
const mysql = require('mysql2');
const port = process.env.PORT || 3000;
const session = require('express-session');
app.use(express.urlencoded({ extended: true }));
const crypto = require('crypto'); // verification token generator
const nodemailer = require('nodemailer');
require('dotenv').config();

function generateToken() {
  return crypto.randomBytes(20).toString('hex'); 
}

app.use(session({
	secret: 'your-secret-key', // Replace with a strong secret
	resave: false,
	saveUninitialized: false,
}));

const db = mysql.createConnection({
	host: process.env.DB_HOST,
	user: process.env.DB_USER,
	password: process.env.DB_PASSWORD,
	database: process.env.DB_NAME,
	port: 24642
});
db.connect((err) => {
	if (err) {
		console.error('Database connection failed:', err.stack);
		return;
	}
	console.log('Connected to MySQL database.');
});

app.use(express.static('public'));

function requireUser(req, res, next){
	if(!req.session.user){
		return res.redirect("/login.html");
	}
	next();
}

const transporter = nodemailer.createTransport({
	service: 'gmail',
	auth: {
		user: process.env.EMAIL_USER, 
		pass: process.env.EMAIL_PASS 
	}
  });
function sendVerificationEmail(userEmail, token) {
	const verificationLink = `https://login-template-wyxd.onrender.com/verify.html?token=${token}`;
  
	const mailOptions = {
		from: 'marceauowen@gmail.com',  // Sender address
		to: userEmail,                 // Receiver's email
		subject: 'Email Verification', // Subject line
		text: `Please verify your email by clicking the following link: ${verificationLink}`,
		html: `<p>Please verify your email by clicking the following link: <a href="${verificationLink}">${verificationLink}</a></p>`
	};
  
	// Send mail
	transporter.sendMail(mailOptions, (error, info) => {
	if (error) {
		console.log('Error sending email:', error);
	} else {
		console.log('Verification email sent:', info.response);
	}
});
}
function isValidEmail(email) {
	const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	return emailRegex.test(email);
}


app.post("/signup", (req, res) => {
	const email = req.body.email;
	const username = req.body.username;
	const password = req.body.password;

	const checkUsernameQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';
	db.query(checkUsernameQuery, [username, email], (err, result) => {
		if (err) {
			console.error('Error querying the database:', err);
			return res.status(500).send('Database error');
		}

		// If a user with the same username exists, return an error
		if(result.length > 0 && result[0].email_verified == 0){
			const deleteQuery = "delete from users where id = ?";
			db.query(deleteQuery, [result[0].id], (err, result) => {
				if(err){
					console.error("Error deleting unverified user: " + err);
				}
			});
		} else if(result.length > 0) {
			return res.status(400).send('Username or Email already taken');
		}

		const valid = isValidEmail(email);
		if(!valid){
			return res.send("Email format is invalid");
		}


		bcrypt.hash(password, 10, (err, hashedPassword) => {
			if (err) {
				console.error('Error hashing password:', err);
				return res.status(500).send('Error hashing password');
			}

			const token = generateToken();
			const query = 'INSERT INTO users (username, email, password_hash, email_verified, verification_token) VALUES (?, ?, ?, ?, ?)';
			db.query(query, [username, email, hashedPassword, false, token], (err, result) => {
				if (err) {
					console.error('Error inserting data:', err);
					return res.status(500).send(`Error in database query: ${err.message}`);
				}

				// User is authenticated and session is created
				req.session.user = username;
				const idQuery = "select id from users where username = ?";
				db.query(idQuery, [username], (err, result) => {
					if(err){
						console.error("error fetching user ID: ", err);
						return res.status(500).send('Database error: ' + err.message);
					}
		
					if(result.length === 0){
						return res.status(404).send('User not found');
					}
		
					req.session.userId = result[0].id;
				});

				// Redirect to index page after a short delay
				setTimeout(() => {
					sendVerificationEmail(email, token);
					res.redirect("/check.html");
				}, 500);
			});
		});
	});
});

app.post("/login", (req, res) => {
	const username = req.body.username;
	const password = req.body.password;

	const query = 'SELECT * FROM users WHERE username = ? and email_verified = true';
	db.query(query, [username], (err, result) => {
	if (err) {
		console.error('Error checking user:', err);
		return res.status(500).send('Database error: ' + err.message);
	}
	if (result.length < 1) {
		return res.status(404).send('User not found');
	}
	// Proceed to password comparison

	bcrypt.compare(password, result[0].password_hash, (err, isMatch) => {
		if (err) {
		  console.error('Error comparing password:', err);
		  return res.status(500).send('Error comparing password');
		}
		if (!isMatch) {
			return res.status(401).send('Invalid password');
		}
		// User is authenticated
		req.session.user = username;
		const idQuery = "select id from users where username = ?";
		db.query(idQuery, [username], (err, result) => {
			if(err){
				console.error("error fetching user ID: ", err);
				return res.status(500).send('Database error: ' + err.message);
			}

			if(result.length === 0){
				return res.status(404).send('User not found');
			}

			req.session.userId = result[0].id;
		});

		setTimeout(() => {
			res.redirect("/index.html");
		}, 500);
	  });
	});
});

// MANUALLY SERVE PAGES NOT IN /PUBLIC //
app.get("/book.html", requireUser, (req, res) => {
	res.sendFile(__dirname + '/private/book.html');
});
app.get("/choose.html", requireUser, (req, res) => {
	db.query("select * from slots", (err, result) => {
		const month = Number(req.query.month); // 1 = 2
		const day = Number(req.query.day); // 2 = 2
		const formalDate = req.query.date; // 2025-02-02
	
		let formalMonth;
		if((month + 1) < 10){
			formalMonth = "0" + String(month + 1);
		} else {
			formalMonth = String(month + 1);
		}
	
		let formalDay;
		if((day) < 10){
			formalDay = "0" + String(day);
		} else {
			formalDay = String(day);
		}

		if(err){
			console.error("Error fetching slots: ", + err);
		}

		let matchDate = false;
		let matchMonth = false;
		let matchDay = false;
		let resultIdx;
		result.forEach((obj, idx) => {
			if(obj.date.toISOString().split("T")[0] == formalDate){
				resultIdx = idx;
				matchDate = true;
			}
		});
		if(matchDate){
			if(result[resultIdx].date.toISOString().split("T")[0].slice(5, 7) == formalMonth){
				matchMonth = true;
			}
			if(result[resultIdx].date.toISOString().split("T")[0].slice(8) == formalDay){
				matchDay = true;
			}
		}

		if(!matchMonth || !matchDate || !matchDay){
			console.log("mtmonth: " + matchMonth);
			console.log("mtday: " + matchDay);
			console.log("mtdate: " + matchDate);
	
			return res.redirect("/");
		} else {
			console.log("success");
		}
	
		res.sendFile(__dirname + '/private/choose.html');
	});
});
app.get("/view.html", requireUser, (req, res) => {
	res.sendFile(__dirname + '/private/view.html');
});
app.get("/thanks.html", requireUser, (req, res) => {
	res.sendFile(__dirname + '/private/thanks.html');
});
app.get("/check.html", requireUser, (req, res) => {
	res.sendFile(__dirname + '/private/check.html');
});
app.get("/verify.html", requireUser, (req, res) => {
	res.sendFile(__dirname + '/private/verify.html');
});
////////////////////////////////////////

app.get('/check-session', (req, res) => {
	if (req.session.user) {
	  res.json({ loggedIn: true, user: req.session.user });
	} else {
	  res.json({ loggedIn: false });
    }
});

app.post("/book", (req, res) => {
	const date = req.body.date;
	const time = req.body.time;

	const query = "select id from slots where date = ? and time = ?";
	db.query(query, [date, time], (err, result) => {
        if (err) {
            console.error('Error fetching slot:', err);
            return res.status(500).json({ success: false, message: 'Error fetching slot' });
        }

        if (result.length === 0) {
			console.log("date: " + date);
			console.log("time: " + time);
            return res.status(400).json({ success: false, message: 'Slot not available' });
        }

        const slotId = result[0].id;
        const userId = req.session.userId;
		const status = "taken";
		const updateQuery = "update slots set status = ? where id = ?";
		db.query(updateQuery, [status, slotId], (err, result) => {
			if (err) {
                console.error('Error updating DB:', err);
            }
		});

        const bookingQuery = 'INSERT INTO bookings (slot_id, user_id, booking_time) VALUES (?, ?, NOW())';
        db.query(bookingQuery, [slotId, userId], (err, result) => {
            if (err) {
                console.error('Error inserting booking:', err);
                return res.status(500).json({ success: false, message: 'Error booking the slot' });
            }

            // Successfully booked
            res.json({ success: true, message: 'Booking successful' });
        });
    });
});

app.get("/logout", (req, res) => {
	req.session.destroy(err => {
		if (err) {
		console.error("Logout error:", err);
		return res.status(500).send("Logout failed");
		}
		res.sendStatus(200);
	});
});

app.get("/slots", (req, res) => {
	db.query("SELECT * FROM slots", (err, results) => {
		if (err) {
			console.error(err);
			return res.status(500).send("Database error");
		}
		res.json(results); // Send array of rows as JSON
	});
});

app.post("/bookings", (req, res) => {
	const date = req.body.queryDate;
	const times = ["13:00:00", "14:00:00", "15:00:00", "16:00:00"];
	const availability = [];

	const checkQuery = "select status from slots where date = ? and time = ?";
	for(let i = 0; i < 4; i++){
		setTimeout(() => {
			db.query(checkQuery, [date, times[i]], (err, result) => {
				if(err){
					console.error("error fetching status: " + err);
				}

				if(result[0].status == "taken"){
					availability.push(false);
				} else {
					availability.push(true);
				}
			});
		}, 100 * i);
	}
	setTimeout(() => {
		res.json({ array: availability });
	}, 50);

});

app.get("/appointments", (req, res) => {
	const userId = req.session.userId;

	const query = "select * from bookings where user_id = ?";
	db.query(query, [userId], (err, result) => {
		if(err){
			console.error("Error fetching bookings: " + err);
		}

		let bookingIds = [];
		let isResult = false;
		if(result.length > 0){
			isResult = true;
			result.forEach(obj => {
				bookingIds.push(obj.slot_id);
			});
		}

		let slotsBooked = [];
		const slotQuery = "select * from slots where id = ?";
		for(let i = 0; i < bookingIds.length; i++){
			db.query(slotQuery, [bookingIds[i]], (err, result) => {
				if(err){
					console.error("Error fetching slots table: " + err);
				}

				if(result){
					slotsBooked.push(result[0]);
				}
			});
		}

		setTimeout(() => {
			res.json({ isBooking: isResult, bookings: slotsBooked });
		}, 50);
	});
});

app.post("/cancel", (req, res) => {
	const date = req.body.date;
	const time = req.body.time;

	const idQuery = "select * from slots where date = ? and time = ?";
	db.query(idQuery, [date, time], (err, result) => {
		if(err){
			console.error("Error fetching slot ID: " + err);
		}

		const slotId = result[0].id;

		const statusQuery = "update slots set status = ? where id = ?";
		db.query(statusQuery, ["available", slotId], (err, result) => {
			if(err){
				console.error("Error updating status in slots: " + err);
			}
		});

		const deleteQuery = "delete from bookings where slot_id = ?";
		db.query(deleteQuery, [slotId], (err, result) => {
			if(err){
				console.error("Error deleting booking: " + err);
			}
		});
	});

	setTimeout(() => {
		res.json({ message: "Booking  has been deleted." })
	}, 50);
});

app.get("/auth-user", (req, res) => {
	const authQuery = "update users set email_verified = ?, verification_token = ?";
	db.query(authQuery, [1, null], (err, result) => {
		if(err){
			console.error("Error authenticating user: " + err);
		}

		res.json({ message: "Your account has been verified. Now you can log in." });
	});
});


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});