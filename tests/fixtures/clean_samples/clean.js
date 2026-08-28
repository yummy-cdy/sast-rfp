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
