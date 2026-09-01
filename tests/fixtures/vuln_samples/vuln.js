const password = "hunter2";

function sqlInjection(userInput) {
  db.query("SELECT * FROM t WHERE id=" + userInput);
}

function xss(userInput) {
  element.innerHTML = userInput;
}

function commandInjection(userInput) {
  child_process.exec("ls " + userInput);
}

function codeInjection(userCode) {
  eval(userCode);
}

function insecureRandom() {
  return Math.random();
}

function emptyCatch() {
  try {
    doWork();
  } catch (e) {}
}

function httpResponseSplitting(res, req) {
  res.setHeader("X-Redirect", req.query.next);
}

function improperAuthorization(user, req) {
  user.role = req.body.role;
}

function unencryptedSensitiveData(user, req) {
  user.ssn = req.body.ssn;
}

function sensitiveCookie(res, value) {
  res.cookie("password", value, { maxAge: 999999 });
}

// api_key: sk-12345
function sensitiveInfoInComment() {}

function infiniteLoop() {
  while (true) {
    doWork();
  }
}

function missingErrorHandling(raw) {
  return JSON.parse(raw);
}

function uninitializedVariable() {
  let x;
  console.log(x);
}

function systemDataExposure(res) {
  res.setHeader("X-Powered-By", "Express");
}
