export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // REGISTER
    // =========================
    if (request.method === "POST" && url.pathname === "/api/register") {
      try {
        const { username, email, password } = await request.json();

        if (!username || !email || !password) {
          return Response.json(
            { success: false, error: "All fields are required" },
            { status: 400 }
          );
        }

        if (password.length < 6) {
          return Response.json(
            {
              success: false,
              error: "Password must be at least 6 characters"
            },
            { status: 400 }
          );
        }

        const existing = await env.DB
          .prepare(
            "SELECT id FROM users WHERE username = ? OR email = ?"
          )
          .bind(username, email)
          .first();

        if (existing) {
          return Response.json(
            {
              success: false,
              error: "Username or email already exists"
            },
            { status: 409 }
          );
        }

        const passwordHash = await hashPassword(password);

        const result = await env.DB
          .prepare(
            `INSERT INTO users
            (username, email, password_hash)
            VALUES (?, ?, ?)`
          )
          .bind(username, email, passwordHash)
          .run();

        return Response.json({
          success: true,
          user_id: result.meta.last_row_id
        });

      } catch (error) {
        return Response.json(
          { success: false, error: "Registration failed" },
          { status: 500 }
        );
      }
    }

    // =========================
    // LOGIN
    // =========================
    if (request.method === "POST" && url.pathname === "/api/login") {
      try {
        const { email, password } = await request.json();

        if (!email || !password) {
          return Response.json(
            {
              success: false,
              error: "Email and password are required"
            },
            { status: 400 }
          );
        }

        const user = await env.DB
          .prepare(
            `SELECT
              id,
              username,
              email,
              password_hash,
              balance,
              views,
              earned,
              plan
            FROM users
            WHERE email = ?`
          )
          .bind(email)
          .first();

        if (!user) {
          return Response.json(
            {
              success: false,
              error: "Invalid email or password"
            },
            { status: 401 }
          );
        }

        const valid = await verifyPassword(
          password,
          user.password_hash
        );

        if (!valid) {
          return Response.json(
            {
              success: false,
              error: "Invalid email or password"
            },
            { status: 401 }
          );
        }

        const token =
          crypto.randomUUID() +
          crypto.randomUUID();

        const tokenHash = await sha256(token);

        const expires = new Date(
          Date.now() + 7 * 24 * 60 * 60 * 1000
        ).toISOString();

        await env.DB
          .prepare(
            `INSERT INTO sessions
            (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)`
          )
          .bind(user.id, tokenHash, expires)
          .run();

        return Response.json({
          success: true,
          token: token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            balance: user.balance,
            views: user.views,
            earned: user.earned,
            plan: user.plan
          }
        });

      } catch (error) {
        return Response.json(
          { success: false, error: "Login failed" },
          { status: 500 }
        );
      }
    }

    // =========================
    // GET VIDEOS
    // =========================
    if (request.method === "GET" && url.pathname === "/api/videos") {
      try {
        const result = await env.DB
          .prepare(
            `SELECT
              id,
              title,
              url,
              duration,
              reward_free,
              reward_premium
            FROM videos
            WHERE active = 1
            ORDER BY id ASC`
          )
          .all();

        return Response.json({
          success: true,
          videos: result.results
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Could not load videos"
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // DATABASE TEST
    // =========================
    if (url.pathname === "/api/test") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS ok")
          .first();

        return Response.json({
          success: true,
          database: result
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Database error"
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // SERVE WEBSITE
    // =========================
    return env.ASSETS.fetch(request);
  }
};


// =========================
// PASSWORD HASH
// =========================
async function hashPassword(password) {
  const data = new TextEncoder().encode(password);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return toHex(hash);
}


// =========================
// VERIFY PASSWORD
// =========================
async function verifyPassword(password, storedHash) {
  const hash = await hashPassword(password);

  return hash === storedHash;
}


// =========================
// SHA256
// =========================
async function sha256(value) {
  const data = new TextEncoder().encode(value);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return toHex(hash);
}


// =========================
// BUFFER TO HEX
// =========================
function toHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}