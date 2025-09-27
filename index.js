import express from "express"
import bodyParser from "body-parser";
import { dirname } from "path"
import { fileURLToPath } from "url";
import pg from "pg"
import dotenv from "dotenv"
import session from "express-session"; 
import passport from "passport"; 
import { Strategy as GoogleStrategy } from "passport-google-oauth2"; 

dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express()
const port = 3000;

// 1. Initialize DB Connection
const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME, 
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

db.connect(); 

// 2. Set up Middleware
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs'); 

// 3. Setup Session Middleware (REQUIRED FOR PASSPORT)
app.use(session({
    secret: process.env.SESSION_SECRET || "A-SECURE-SECRET-KEY", 
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // 24 hours
    }
}));

// 4. Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// 5. Google OAuth Strategy Configuration
passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    // CRITICAL: Must match the redirect URI in Google Cloud Console
    callbackURL: HOST_URL + "/auth/google/secrets", 
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
},
async (accessToken, refreshToken, profile, cb) => {
    try {
        // Check if user exists in our 'users' table
        const result = await db.query("SELECT * FROM users WHERE google_id = $1", [profile.id]);

        if (result.rows.length === 0) {
            // New user - Register them
            const newUser = await db.query(
                "INSERT INTO users (google_id, username, email) VALUES ($1, $2, $3) RETURNING *",
                [profile.id, profile.displayName, profile.email]
            );
            cb(null, newUser.rows[0]); 
        } else {
            // Existing user - Log them in
            cb(null, result.rows[0]); 
        }
    } catch (err) {
        cb(err);
    }
}));

// 6. Serialize and Deserialize User
passport.serializeUser((user, cb) => {
    cb(null, user.id); 
});

passport.deserializeUser(async (id, cb) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
        if (result.rows.length > 0) {
            cb(null, result.rows[0]); 
        } else {
            cb(new Error("User not found"));
        }
    } catch (err) {
        cb(err);
    }
});

// Middleware to check if user is logged in
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

// 7. --- AUTHENTICATION ROUTES ---

// Login panel
app.get("/login", (req, res) => {
    res.render("login.ejs");
});

// Initiate Google Auth
app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"]
}));

// Google Auth Callback Route
app.get("/auth/google/secrets", passport.authenticate("google", {
    successRedirect: "/",
    failureRedirect: "/login"
}));

// LOGOUT ROUTE (The Sign-Out Feature)
app.get("/logout", (req, res, next) => {
    // req.logout() is provided by Passport.js to terminate the login session
    req.logout((err) => {
        if (err) {
            console.error("Logout error:", err);
            return next(err);
        }
        // Redirect to the login page after successfully logging out
        res.redirect("/login");
    });
});

// 8. --- BLOG CRUD ROUTES (Protected and DB-Driven) ---

// Home/Dashboard - Only show current user's blogs
app.get("/", isAuthenticated, async (req, res) => {
    try {
        // Fetch ONLY blogs belonging to the logged-in user (req.user.id)
        const result = await db.query("SELECT * FROM blogs WHERE user_id = $1 ORDER BY created_at DESC", [req.user.id]);
        res.render("index.ejs", {
            blogs: result.rows,
            user: req.user // Pass user info for the welcome message
        });
    } catch (err) {
        console.error("Error fetching blogs:", err);
        res.render("index.ejs", { blogs: [], user: req.user });
    }
});

// Create Blog Form
app.get("/create", isAuthenticated, (req, res) => {
    res.sendFile(__dirname + "/public/create.html");
});

// Post/Save the created blog
app.post("/post", isAuthenticated, async (req, res) => {
    const { title, subtitle, content } = req.body;
    const userId = req.user.id; // GETS THE LOGGED-IN USER ID

    try {
        await db.query(
            "INSERT INTO blogs (user_id, title, subtitle, content) VALUES ($1, $2, $3, $4)",
            [userId, title, subtitle, content]
        );
        res.redirect("/");
    } catch (err) {
        console.error("Error posting blog:", err);
        res.status(500).send("Error creating blog post.");
    }
});

// Viewing the blog post
app.get("/view/:id", isAuthenticated, async (req, res) => {
    const blogId = req.params.id;
    try {
        const result = await db.query(
            "SELECT * FROM blogs WHERE id = $1 AND user_id = $2",
            [blogId, req.user.id]
        );
        if (result.rows.length > 0) {
            res.render("views.ejs", { blog: result.rows[0] });
        } else {
            res.status(404).send("Blog not found or unauthorized.");
        }
    } catch (err) {
        console.error("Error viewing blog:", err);
        res.status(500).send("Error viewing blog post.");
    }
});

// Editing the blog post (Form)
app.get("/edit/:id", isAuthenticated, async (req, res) => {
    const blogId = req.params.id;
    try {
        const result = await db.query(
            "SELECT * FROM blogs WHERE id = $1 AND user_id = $2",
            [blogId, req.user.id]
        );
        if (result.rows.length > 0) {
            // Note: The blog object passed uses the DB 'id'
            res.render("edit.ejs", { blog: result.rows[0] });
        } else {
            res.status(404).send("Blog not found or unauthorized.");
        }
    } catch (err) {
        console.error("Error fetching blog for edit:", err);
        res.status(500).send("Error fetching blog for edit.");
    }
});

// Updating the blog post after editing it.
app.post("/update/:id", isAuthenticated, async (req, res) => {
    const blogId = req.params.id;
    const { title, subtitle, content } = req.body;

    try {
        // Update ONLY if the blog ID and user ID match
        const result = await db.query(
            "UPDATE blogs SET title = $1, subtitle = $2, content = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4 AND user_id = $5 RETURNING *",
            [title, subtitle, content, blogId, req.user.id]
        );
        if (result.rows.length === 0) {
             res.status(404).send("Blog not found or unauthorized to update.");
        } else {
            res.redirect("/");
        }

    } catch (err) {
        console.error("Error updating blog:", err);
        res.status(500).send("Error updating blog post.");
    }
});

// Deleting the blog post
app.get("/delete/:id", isAuthenticated, async (req, res) => {
    const blogId = req.params.id;
    try {
        // Delete ONLY if the blog ID and user ID match
        const result = await db.query(
            "DELETE FROM blogs WHERE id = $1 AND user_id = $2 RETURNING *",
            [blogId, req.user.id]
        );
        if (result.rows.length === 0) {
            res.status(404).send("Blog not found or unauthorized to delete.");
        } else {
            res.redirect("/");
        }
    } catch (err) {
        console.error("Error deleting blog:", err);
        res.status(500).send("Error deleting blog post.");
    }
});


// app.listen(port, () => {
//   console.log(`Server running on port ${port}.`);
// });

// for deployment using export default app
export default app;
