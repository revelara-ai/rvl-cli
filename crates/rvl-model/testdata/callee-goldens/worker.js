const http = require("http");

let handler = function (req) {
  return http.get(req.url);
};

function schedule(job) {
  setTimeout(() => run(job), 10);
}

var run = (job) => handler(job);

module.exports = { schedule };
