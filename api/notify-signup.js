import crypto from "crypto";

const FIRESTORE_BASE =
  "https://firestore.googleapis.com/v1/projects";

function getServiceAccount() {
  if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT is not configured");
  }

  return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
}

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64urlDecode(value) {
  return Buffer.from(
    value.replace(/-/g, "+").replace(/_/g, "/"),
    "base64"
  ).toString("utf8");
}

/*
 * Creates a signed approval token.
 * The token expires after 24 hours.
 */
function createActionToken(uid, action) {
  const serviceAccount = getServiceAccount();

  const payload = {
    uid,
    action,
    exp: Date.now() + 24 * 60 * 60 * 1000
  };

  const encodedPayload = base64url(JSON.stringify(payload));

  const signature = crypto
    .createHmac("sha256", serviceAccount.private_key)
    .update(encodedPayload)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return `${encodedPayload}.${signature}`;
}

function verifyActionToken(token) {
  const serviceAccount = getServiceAccount();

  const parts = token.split(".");

  if (parts.length !== 2) {
    throw new Error("Invalid approval link");
  }

  const [encodedPayload, signature] = parts;

  const expectedSignature = crypto
    .createHmac("sha256", serviceAccount.private_key)
    .update(encodedPayload)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  if (
    !crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    )
  ) {
    throw new Error("Invalid approval link");
  }

  const payload = JSON.parse(base64urlDecode(encodedPayload));

  if (!payload.uid || !payload.action || !payload.exp) {
    throw new Error("Invalid approval request");
  }

  if (Date.now() > payload.exp) {
    throw new Error("This approval link has expired");
  }

  if (!["approved", "rejected"].includes(payload.action)) {
    throw new Error("Invalid action");
  }

  return payload;
}

/*
 * Creates a Google OAuth access token using the Firebase
 * service-account credentials.
 */
async function getGoogleAccessToken() {
  const serviceAccount = getServiceAccount();

  const header = {
    alg: "RS256",
    typ: "JWT"
  };

  const now = Math.floor(Date.now() / 1000);

  const claimSet = {
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedClaimSet = base64url(JSON.stringify(claimSet));

  const unsignedToken = `${encodedHeader}.${encodedClaimSet}`;

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsignedToken);

  const signature = signer
    .sign(serviceAccount.private_key)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  const jwt = `${unsignedToken}.${signature}`;

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body:
      "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer" +
      `&assertion=${encodeURIComponent(jwt)}`
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.error_description || "Unable to authenticate with Firebase"
    );
  }

  return data.access_token;
}

/*
 * Updates the user's approval status in Firestore.
 */
async function updateFirestoreStatus(uid, status) {
  const serviceAccount = getServiceAccount();
  const accessToken = await getGoogleAccessToken();

  const projectId = serviceAccount.project_id;

  const documents = [
    `users/${uid}`,
    `membershipRequests/${uid}`
  ];

  for (const documentPath of documents) {
    const url =
      `${FIRESTORE_BASE}/${projectId}/databases/(default)/documents/` +
      `${documentPath}?updateMask.fieldPaths=status`;

    const response = await fetch(url, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        fields: {
          status: {
            stringValue: status
          }
        }
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Firestore update failed: ${errorText}`
      );
    }
  }
}

/*
 * Admin recipients: the emails stored in the Firestore roster (config/admins),
 * falling back to ADMIN_EMAILS / ADMIN_EMAIL. Never more than 3.
 */
async function getAdminEmails() {
  let emails = [];
  try {
    const sa = getServiceAccount();
    const token = await getGoogleAccessToken();
    const r = await fetch(
      `${FIRESTORE_BASE}/${sa.project_id}/databases/(default)/documents/config/admins`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (r.ok) {
      const d = await r.json();
      emails = ((d.fields && d.fields.emails && d.fields.emails.arrayValue.values) || [])
        .map((v) => v.stringValue);
    }
  } catch (e) { console.error("Roster lookup failed", e); }
  if (!emails.length) {
    emails = (process.env.ADMIN_EMAILS || process.env.ADMIN_EMAIL || "bukunmiiafolabi@gmail.com")
      .split(",").map((e) => e.trim());
  }
  return [...new Set(emails.filter(Boolean))].slice(0, 3);
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function resultPage(title, message) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #F4E3A1;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
    }

    .card {
      background: white;
      max-width: 500px;
      width: 100%;
      padding: 30px;
      border-radius: 18px;
      text-align: center;
      box-shadow: 0 10px 30px rgba(0,0,0,.12);
    }

    h1 {
      margin-top: 0;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
  </div>
</body>
</html>
`;
}

const SITE_KEY = process.env.FIREBASE_API_KEY || "AIzaSyCRiFj2kXIPGi2ZDPzePPYzVC4g0H4k5R8";
const fsUrl = (sa, path) => `${FIRESTORE_BASE}/${sa.project_id}/databases/(default)/documents/${path}`;
const field = (d, k) => (d && d.fields && d.fields[k] && d.fields[k].stringValue) || "";

/* Confirms who is calling, from their Firebase sign-in token. */
async function verifyIdToken(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || "");
  if (!m) throw new Error("Not signed in");
  const r = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${SITE_KEY}`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken: m[1] }) }
  );
  const d = await r.json();
  if (!r.ok || !d.users || !d.users[0]) throw new Error("Not signed in");
  return d.users[0].localId;
}

async function getUserDoc(uid) {
  const sa = getServiceAccount();
  const token = await getGoogleAccessToken();
  const r = await fetch(fsUrl(sa, `users/${uid}`), { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error("User not found");
  const d = await r.json();
  return { name: field(d, "name"), email: field(d, "email") };
}

async function isRosterAdmin(uid) {
  const sa = getServiceAccount();
  const token = await getGoogleAccessToken();
  const r = await fetch(fsUrl(sa, "config/admins"), { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) return false;
  const d = await r.json();
  const vals = (d.fields && d.fields.uids && d.fields.uids.arrayValue.values) || [];
  return vals.some((v) => v.stringValue === uid);
}

async function sendMail(to, subject, html) {
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Unconventional Wisdom <notifications@unconventionalwisdom.online>",
      to: Array.isArray(to) ? to : [to],
      subject,
      html
    })
  });
  if (!r.ok) throw new Error(`Email failed: ${await r.text()}`);
}

/* The email a member receives. */
function memberMail(name, status, baseUrl) {
  const hi = `<p>Hi ${escapeHtml(name || "there")},</p>`;
  const btn = (href, label) =>
    `<p><a href="${href}" style="display:inline-block;padding:12px 20px;background:#6B4026;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold">${label}</a></p>`;
  const wrap = (body) => `<div style="font-family:Arial,sans-serif;line-height:1.6">${hi}${body}<p>Unconventional Wisdom</p></div>`;
  if (status === "approved")
    return ["You're approved - welcome to Unconventional Wisdom",
      wrap(`<p>Your account has been approved. You can now sign in at any time.</p>${btn(baseUrl + "/you.html", "Sign in")}`)];
  if (status === "rejected")
    return ["Your Unconventional Wisdom request was not approved",
      wrap(`<p>Your signup request was not approved this time. You are welcome to apply again.</p>${btn(baseUrl + "/you.html", "Apply again")}`)];
  return ["We received your request",
    wrap(`<p>Your signup request has been sent to the admin. You'll get an email as soon as it has been reviewed.</p>`)];
}

export default async function handler(req, res) {
  try {
    const baseUrl = process.env.VERCEL_PROJECT_PRODUCTION_URL
      ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
      : `https://${req.headers.host}`;

    /* One-click approve / decline links from the admin email */
    if (req.method === "GET") {
      const { token } = req.query || {};
      if (!token) return res.status(400).send(resultPage("Invalid Request", "The approval link is missing."));
      const payload = verifyActionToken(token);
      await updateFirestoreStatus(payload.uid, payload.action);
      try {
        const u = await getUserDoc(payload.uid);
        const [subject, html] = memberMail(u.name, payload.action, baseUrl);
        await sendMail(u.email, subject, html);
      } catch (e) { console.error("Member email failed", e); }
      return res.status(200).send(
        payload.action === "approved"
          ? resultPage("User Approved ✅", "The user has been approved successfully.")
          : resultPage("User Declined ❌", "The user's signup request has been declined.")
      );
    }

    if (req.method === "POST") {
      const callerUid = await verifyIdToken(req);
      const body = req.body || {};

      /* Admin approved/rejected someone on the dashboard: tell the member */
      if (body.action === "decision") {
        if (!(await isRosterAdmin(callerUid))) return res.status(403).json({ error: "Admins only" });
        if (!["approved", "rejected"].includes(body.status) || !body.uid)
          return res.status(400).json({ error: "Invalid request" });
        const u = await getUserDoc(body.uid);
        const [subject, html] = memberMail(u.name, body.status, baseUrl);
        await sendMail(u.email, subject, html);
        return res.status(200).json({ success: true });
      }

      /* Someone just requested access: confirm to them, alert the admins */
      const u = await getUserDoc(callerUid);
      const approveUrl = `${baseUrl}/api/notify-signup?token=${encodeURIComponent(createActionToken(callerUid, "approved"))}`;
      const declineUrl = `${baseUrl}/api/notify-signup?token=${encodeURIComponent(createActionToken(callerUid, "rejected"))}`;
      const [mSubject, mHtml] = memberMail(u.name, "pending", baseUrl);
      const adminHtml = `<div style="font-family:Arial,sans-serif;line-height:1.6"><h2>New signup request</h2><p><strong>Name:</strong> ${escapeHtml(u.name)}<br><strong>Email:</strong> ${escapeHtml(u.email)}</p><p><a href="${approveUrl}" style="padding:12px 20px;background:#198754;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold">APPROVE</a> &nbsp; <a href="${declineUrl}" style="padding:12px 20px;background:#dc3545;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold">DECLINE</a></p><p><a href="${baseUrl}/admin.html">Open the admin dashboard</a></p></div>`;
      const results = await Promise.allSettled([
        sendMail(u.email, mSubject, mHtml),
        sendMail(await getAdminEmails(), "New signup - approval required", adminHtml)
      ]);
      results.forEach((r) => r.status === "rejected" && console.error(r.reason));
      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error.message || "Server error" });
  }
    }
    
