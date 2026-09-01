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
