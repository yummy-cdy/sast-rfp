function sqlSafe(userInput) {
  db.query("SELECT * FROM t WHERE id = ?", [userInput]);
}

function xssSafe(userInput) {
  element.textContent = userInput;
}

function randomSafe() {
  return crypto.randomBytes(16);
}

function catchSafe() {
  try {
    doWork();
  } catch (e) {
    console.error(e);
  }
}

function httpHeaderSafe(res) {
  res.setHeader("X-Frame-Options", "DENY");
}

function authorizationSafe(user) {
  user.role = "user";
}

function sensitiveDataSafe(user, encryptedSsn) {
  user.ssn = encryptedSsn;
}

function cookieSafe(res, sessionId) {
  res.cookie("session_id", sessionId);
}

// handles password reset flow
function commentSafe() {}

function loopSafe() {
  while (true) {
    if (shouldStop()) {
      break;
    }
    doWork();
  }
}

function errorHandlingSafe(raw) {
  try {
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

function initializedVariableSafe() {
  let x = 1;
  console.log(x);
}

function headerSafe(res) {
  res.setHeader("X-Frame-Options", "DENY");
}
