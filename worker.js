export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // REGISTER
    // =========================
    if (request.method === "POST" && url.pathname === "/api/register") {
      try {
        const { username, email, password } = await request.json();

        if (
          typeof username !== "string" ||
          typeof email !== "string" ||
          typeof password !== "string" ||
          !username.trim() ||
          !email.trim() ||
          !password
        ) {
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

        const cleanUsername = username.trim();
        const cleanEmail = email.trim().toLowerCase();

        const existing = await env.DB
          .prepare(
            "SELECT id FROM users WHERE username = ? OR email = ?"
          )
          .bind(cleanUsername, cleanEmail)
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
          .bind(cleanUsername, cleanEmail, passwordHash)
          .run();

        return Response.json({
          success: true,
          user_id: result.meta.last_row_id
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Registration failed"
          },
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

        if (
          typeof email !== "string" ||
          typeof password !== "string" ||
          !email.trim() ||
          !password
        ) {
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
          .bind(email.trim().toLowerCase())
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
          token,
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
          {
            success: false,
            error: "Login failed"
          },
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
    // START VIDEO WATCH SESSION
    // =========================
    if (
      request.method === "POST" &&
      url.pathname === "/api/start-video"
    ) {
      try {
        const user = await getUserFromToken(request, env);

        if (!user) {
          return Response.json(
            { success: false, error: "Unauthorized" },
            { status: 401 }
          );
        }

        const body = await request.json();
        const videoId = Number(body.video_id);

        if (!Number.isSafeInteger(videoId) || videoId <= 0) {
          return Response.json(
            { success: false, error: "Invalid video ID" },
            { status: 400 }
          );
        }

        const video = await env.DB
          .prepare(
            `SELECT id, duration
             FROM videos
             WHERE id = ? AND active = 1`
          )
          .bind(videoId)
          .first();

        if (!video) {
          return Response.json(
            { success: false, error: "Video not found" },
            { status: 404 }
          );
        }

        const duration = Number(video.duration);

        if (!Number.isFinite(duration) || duration <= 0) {
          return Response.json(
            { success: false, error: "Invalid video duration" },
            { status: 500 }
          );
        }

        // لا تسمح ببدء جلسة جديدة إذا سبق الحصول على مكافأة هذا الفيديو.
        const alreadyClaimed = await env.DB
          .prepare(
            `SELECT id
             FROM video_views
             WHERE user_id = ? AND video_id = ?`
          )
          .bind(user.id, video.id)
          .first();

        if (alreadyClaimed) {
          return Response.json(
            {
              success: false,
              error: "You have already claimed this video"
            },
            { status: 409 }
          );
        }

        const startedAt = Math.floor(Date.now() / 1000);

        await env.DB
          .prepare(
            `INSERT INTO video_watch_sessions
              (user_id, video_id, started_at, claimed)
             VALUES (?, ?, ?, 0)`
          )
          .bind(user.id, video.id, startedAt)
          .run();

        return Response.json({
          success: true,
          message: "Watch session started",
          video_id: video.id,
          duration
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Could not start video session"
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // CLAIM VIDEO REWARD
    // =========================
    if (
      request.method === "POST" &&
      url.pathname === "/api/claim-video"
    ) {
      try {
        const user = await getUserFromToken(request, env);

        if (!user) {
          return Response.json(
            { success: false, error: "Unauthorized" },
            { status: 401 }
          );
        }

        const body = await request.json();
        const videoId = Number(body.video_id);

        if (!Number.isSafeInteger(videoId) || videoId <= 0) {
          return Response.json(
            { success: false, error: "Invalid video ID" },
            { status: 400 }
          );
        }

        const video = await env.DB
          .prepare(
            `SELECT
              id,
              title,
              duration,
              reward_free,
              reward_premium
             FROM videos
             WHERE id = ? AND active = 1`
          )
          .bind(videoId)
          .first();

        if (!video) {
          return Response.json(
            { success: false, error: "Video not found" },
            { status: 404 }
          );
        }

        const duration = Number(video.duration);

        if (!Number.isFinite(duration) || duration <= 0) {
          return Response.json(
            { success: false, error: "Invalid video duration" },
            { status: 500 }
          );
        }

        // التحقق من وجود جلسة مشاهدة اكتملت مدتها على الخادم.
        const now = Math.floor(Date.now() / 1000);
        const earliestAllowedStart = now - duration;

        const watchSession = await env.DB
          .prepare(
            `SELECT id, started_at
             FROM video_watch_sessions
             WHERE user_id = ?
               AND video_id = ?
               AND claimed = 0
               AND started_at <= ?
             ORDER BY started_at DESC, id DESC
             LIMIT 1`
          )
          .bind(
            user.id,
            video.id,
            earliestAllowedStart
          )
          .first();

        if (!watchSession) {
          return Response.json(
            {
              success: false,
              error: "Please complete the video watch time first",
              required_seconds: duration
            },
            { status: 409 }
          );
        }

        let reward = Number(video.reward_free);

        if (user.plan === "premium") {
          reward = Number(video.reward_premium);
        }

        if (!Number.isFinite(reward) || reward <= 0) {
          return Response.json(
            { success: false, error: "Invalid reward" },
            { status: 500 }
          );
        }

        // تحديث الجلسة وإضافة المشاهدة والرصيد داخل دفعة واحدة.
        // قيد UNIQUE(user_id, video_id) في video_views يمنع تكرار المكافأة.
        try {
          await env.DB.batch([
            env.DB
              .prepare(
                `UPDATE video_watch_sessions
                 SET claimed = 1
                 WHERE id = ?
                   AND user_id = ?
                   AND video_id = ?
                   AND claimed = 0`
              )
              .bind(
                watchSession.id,
                user.id,
                video.id
              ),

            env.DB
              .prepare(
                `INSERT INTO video_views
                  (user_id, video_id, reward)
                 VALUES (?, ?, ?)`
              )
              .bind(user.id, video.id, reward),

            env.DB
              .prepare(
                `UPDATE users
                 SET
                   balance = balance + ?,
                   earned = earned + ?,
                   views = views + 1
                 WHERE id = ?`
              )
              .bind(reward, reward, user.id)
          ]);

        } catch (error) {
          return Response.json(
            {
              success: false,
              error: "Video already claimed or transaction failed"
            },
            { status: 409 }
          );
        }

        const updatedUser = await env.DB
          .prepare(
            `SELECT
              id,
              username,
              email,
              balance,
              views,
              earned,
              plan
             FROM users
             WHERE id = ?`
          )
          .bind(user.id)
          .first();

        return Response.json({
          success: true,
          message: "Reward added successfully",
          reward,
          user: updatedUser
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Could not claim video reward"
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // DATABASE TEST
    // =========================
    if (
      request.method === "GET" &&
      url.pathname === "/api/test"
    ) {
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


// =========================
// GET USER FROM SESSION
// =========================
async function getUserFromToken(request, env) {
  const auth = request.headers.get("Authorization");

  if (!auth || !auth.startsWith("Bearer ")) {
    return null;
  }

  const token = auth.slice(7);
  const tokenHash = await sha256(token);

  const user = await env.DB
    .prepare(`
      SELECT
        users.id,
        users.username,
        users.email,
        users.balance,
        users.views,
        users.earned,
        users.plan
      FROM sessions
      JOIN users
        ON users.id = sessions.user_id
      WHERE sessions.token_hash = ?
        AND datetime(sessions.expires_at) > datetime('now')
    `)
    .bind(tokenHash)
    .first();

  return user || null;
}