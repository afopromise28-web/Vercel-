# Unconventional Wisdom: deploy files (v18)

Upload ALL files in this folder to the ROOT of your Vercel project (index.html must sit at the top level).

Pages: index.html, devotional.html, journals.html, leaderboard.html, you.html
Also upload: firebase-config.js, robots.txt, sitemap.xml

## Turn on real accounts + "Continue with Google"
1. Go to https://console.firebase.google.com and create a project (free).
2. Build > Authentication > Get started. Enable "Email/Password" and "Google".
3. Authentication > Settings > Authorized domains > Add domain: promise-teal.vercel.app (and any custom domain).
4. Project settings (gear) > Your apps > Web (</>) > register app > copy the config object.
5. Open firebase-config.js, replace `window.UW_FIREBASE = null;` with `window.UW_FIREBASE = { ...your config... };`
6. Re-upload firebase-config.js. Done. Until you do this, accounts are stored on the visitor's device only and the Google button explains it is not switched on.

## Settings
js is inlined in each HTML file. Search for `var CONFIG` in an HTML file to change: unlockHours (24), showSampleParticipants.
Replace https://your-domain.com with your real domain in the HTML files, robots.txt and sitemap.xml.


## Firebase integration added
The account page is already wired for Firebase Authentication and now also
creates/updates a Firestore document at `users/{firebaseUid}` containing:
`name`, `email`, `provider`, and `updatedAt`.

Before deploying:
1. Firebase Console > Project settings > Your apps > add/register a Web app.
2. Copy its Firebase Web SDK config into `firebase-config.js`.
3. Keep Email/Password and Google enabled under Authentication > Sign-in method.
4. In Firestore Rules, allow an authenticated user to create/update only their
   own `users/{userId}` document.
5. Add your deployed website domain under Authentication > Settings >
   Authorized domains.

The browser code does not contain a private/service-account key.

## Firestore rules

Use the included `firestore.rules` file in Firebase Console > Firestore Database > Rules. These rules protect:
- `users/{uid}` profiles and approval status
- `membershipRequests/{uid}` signup requests
- `admins/{uid}` admin access
- `leaderboard/{uid}` leaderboard writes

## Admin approval / signup requests
The account page now requires admin approval for new signups. A new email or Google signup creates:
- `users/{firebaseUid}` with `status: "pending"`
- `membershipRequests/{firebaseUid}` with the signup details and `status: "pending"`

After approval, the user can sign in normally on future visits; approval is not requested again. Rejected users are blocked from signing in.

### One-time admin setup
1. Sign up once using the account you want to be the site administrator.
2. In Firebase Authentication > Users, copy that account's **User UID**.
3. In Firestore, create a collection named `admins`.
4. Create a document whose **Document ID is exactly that User UID**. A field such as `role: admin` may be added, but the ID is what matters.
5. Publish the included `firestore.rules`.
6. Sign in again. The account will be recognised as an admin even if its membership status is still pending.
7. The **Admin — Signup requests** panel will appear on the You/account page, where you can Approve or Reject requests.

Do not give normal users write access to the `admins` collection.


## Admin dashboard (admin.html) — max 3 admins
Open `/admin.html` and sign in. Only accounts listed in ONE Firestore document can enter, and the database itself refuses a roster of more than 3.
It shows signup requests live (badge, sound, optional browser notification), lets you Approve/Reject/reverse, and has a Team panel to add or remove admins.

**One-time setup** (replaces the older `admins/{uid}` collection, which is no longer used):
1. Sign up on the site with the first admin's account, then copy its UID from Firebase Authentication > Users.
2. Firestore > create collection `config`, document ID `admins`, with fields: `uids` (array: that UID) and `emails` (array: that email, lowercase).
3. Publish `firestore.rules` (Firestore > Rules).
4. Rename nothing else: `firebase-config.js` must be named exactly that.
5. Sign in at `/admin.html`. Add the other two admins from the Team panel once they have signed up.

**Email alerts:** `api/notify-signup.js` now emails every admin in the roster (max 3) and links to the dashboard. If the roster can't be read it falls back to the `ADMIN_EMAILS` environment variable (comma-separated).
Also add `admin.html` to your Vercel upload; the Firestore composite index for requests is not needed (single-field sort).
