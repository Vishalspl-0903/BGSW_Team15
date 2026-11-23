// Role E fixture: the application imports only its two direct dependencies.
// fx-beta, fx-gamma, fx-epsilon and fx-peerhost are reachable only through the lockfile.
const alpha = require("fx-alpha");
const delta = require("fx-delta");

module.exports = { alpha, delta };
