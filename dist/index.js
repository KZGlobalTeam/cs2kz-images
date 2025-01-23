"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/@actions/core/lib/utils.js
var require_utils = __commonJS({
  "node_modules/@actions/core/lib/utils.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.toCommandProperties = exports2.toCommandValue = void 0;
    function toCommandValue(input) {
      if (input === null || input === void 0) {
        return "";
      } else if (typeof input === "string" || input instanceof String) {
        return input;
      }
      return JSON.stringify(input);
    }
    exports2.toCommandValue = toCommandValue;
    function toCommandProperties(annotationProperties) {
      if (!Object.keys(annotationProperties).length) {
        return {};
      }
      return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
      };
    }
    exports2.toCommandProperties = toCommandProperties;
  }
});

// node_modules/@actions/core/lib/command.js
var require_command = __commonJS({
  "node_modules/@actions/core/lib/command.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule) return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.issue = exports2.issueCommand = void 0;
    var os = __importStar(require("os"));
    var utils_1 = require_utils();
    function issueCommand(command, properties, message) {
      const cmd = new Command(command, properties, message);
      process.stdout.write(cmd.toString() + os.EOL);
    }
    exports2.issueCommand = issueCommand;
    function issue(name, message = "") {
      issueCommand(name, {}, message);
    }
    exports2.issue = issue;
    var CMD_STRING = "::";
    var Command = class {
      constructor(command, properties, message) {
        if (!command) {
          command = "missing.command";
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
      }
      toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
          cmdStr += " ";
          let first = true;
          for (const key in this.properties) {
            if (this.properties.hasOwnProperty(key)) {
              const val = this.properties[key];
              if (val) {
                if (first) {
                  first = false;
                } else {
                  cmdStr += ",";
                }
                cmdStr += `${key}=${escapeProperty(val)}`;
              }
            }
          }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
      }
    };
    function escapeData(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    }
    function escapeProperty(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
    }
  }
});

// node_modules/@actions/core/lib/file-command.js
var require_file_command = __commonJS({
  "node_modules/@actions/core/lib/file-command.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule) return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.issueCommand = void 0;
    var fs3 = __importStar(require("fs"));
    var os = __importStar(require("os"));
    var utils_1 = require_utils();
    function issueCommand(command, message) {
      const filePath = process.env[`GITHUB_${command}`];
      if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
      }
      if (!fs3.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
      }
      fs3.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
        encoding: "utf8"
      });
    }
    exports2.issueCommand = issueCommand;
  }
});

// node_modules/uuid/dist/esm-node/rng.js
function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    import_crypto.default.randomFillSync(rnds8Pool);
    poolPtr = 0;
  }
  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}
var import_crypto, rnds8Pool, poolPtr;
var init_rng = __esm({
  "node_modules/uuid/dist/esm-node/rng.js"() {
    import_crypto = __toESM(require("crypto"));
    rnds8Pool = new Uint8Array(256);
    poolPtr = rnds8Pool.length;
  }
});

// node_modules/uuid/dist/esm-node/regex.js
var regex_default;
var init_regex = __esm({
  "node_modules/uuid/dist/esm-node/regex.js"() {
    regex_default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
  }
});

// node_modules/uuid/dist/esm-node/validate.js
function validate(uuid) {
  return typeof uuid === "string" && regex_default.test(uuid);
}
var validate_default;
var init_validate = __esm({
  "node_modules/uuid/dist/esm-node/validate.js"() {
    init_regex();
    validate_default = validate;
  }
});

// node_modules/uuid/dist/esm-node/stringify.js
function stringify(arr, offset = 0) {
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!validate_default(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
var byteToHex, stringify_default;
var init_stringify = __esm({
  "node_modules/uuid/dist/esm-node/stringify.js"() {
    init_validate();
    byteToHex = [];
    for (let i = 0; i < 256; ++i) {
      byteToHex.push((i + 256).toString(16).substr(1));
    }
    stringify_default = stringify;
  }
});

// node_modules/uuid/dist/esm-node/v1.js
function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== void 0 ? options.clockseq : _clockseq;
  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || rng)();
    if (node == null) {
      node = _nodeId = [seedBytes[0] | 1, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }
    if (clockseq == null) {
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 16383;
    }
  }
  let msecs = options.msecs !== void 0 ? options.msecs : Date.now();
  let nsecs = options.nsecs !== void 0 ? options.nsecs : _lastNSecs + 1;
  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 1e4;
  if (dt < 0 && options.clockseq === void 0) {
    clockseq = clockseq + 1 & 16383;
  }
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === void 0) {
    nsecs = 0;
  }
  if (nsecs >= 1e4) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }
  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;
  msecs += 122192928e5;
  const tl = ((msecs & 268435455) * 1e4 + nsecs) % 4294967296;
  b[i++] = tl >>> 24 & 255;
  b[i++] = tl >>> 16 & 255;
  b[i++] = tl >>> 8 & 255;
  b[i++] = tl & 255;
  const tmh = msecs / 4294967296 * 1e4 & 268435455;
  b[i++] = tmh >>> 8 & 255;
  b[i++] = tmh & 255;
  b[i++] = tmh >>> 24 & 15 | 16;
  b[i++] = tmh >>> 16 & 255;
  b[i++] = clockseq >>> 8 | 128;
  b[i++] = clockseq & 255;
  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }
  return buf || stringify_default(b);
}
var _nodeId, _clockseq, _lastMSecs, _lastNSecs, v1_default;
var init_v1 = __esm({
  "node_modules/uuid/dist/esm-node/v1.js"() {
    init_rng();
    init_stringify();
    _lastMSecs = 0;
    _lastNSecs = 0;
    v1_default = v1;
  }
});

// node_modules/uuid/dist/esm-node/parse.js
function parse(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  let v;
  const arr = new Uint8Array(16);
  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 255;
  arr[2] = v >>> 8 & 255;
  arr[3] = v & 255;
  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 255;
  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 255;
  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 255;
  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 1099511627776 & 255;
  arr[11] = v / 4294967296 & 255;
  arr[12] = v >>> 24 & 255;
  arr[13] = v >>> 16 & 255;
  arr[14] = v >>> 8 & 255;
  arr[15] = v & 255;
  return arr;
}
var parse_default;
var init_parse = __esm({
  "node_modules/uuid/dist/esm-node/parse.js"() {
    init_validate();
    parse_default = parse;
  }
});

// node_modules/uuid/dist/esm-node/v35.js
function stringToBytes(str) {
  str = unescape(encodeURIComponent(str));
  const bytes = [];
  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }
  return bytes;
}
function v35_default(name, version2, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === "string") {
      value = stringToBytes(value);
    }
    if (typeof namespace === "string") {
      namespace = parse_default(namespace);
    }
    if (namespace.length !== 16) {
      throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
    }
    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 15 | version2;
    bytes[8] = bytes[8] & 63 | 128;
    if (buf) {
      offset = offset || 0;
      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }
      return buf;
    }
    return stringify_default(bytes);
  }
  try {
    generateUUID.name = name;
  } catch (err) {
  }
  generateUUID.DNS = DNS;
  generateUUID.URL = URL2;
  return generateUUID;
}
var DNS, URL2;
var init_v35 = __esm({
  "node_modules/uuid/dist/esm-node/v35.js"() {
    init_stringify();
    init_parse();
    DNS = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    URL2 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
  }
});

// node_modules/uuid/dist/esm-node/md5.js
function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return import_crypto2.default.createHash("md5").update(bytes).digest();
}
var import_crypto2, md5_default;
var init_md5 = __esm({
  "node_modules/uuid/dist/esm-node/md5.js"() {
    import_crypto2 = __toESM(require("crypto"));
    md5_default = md5;
  }
});

// node_modules/uuid/dist/esm-node/v3.js
var v3, v3_default;
var init_v3 = __esm({
  "node_modules/uuid/dist/esm-node/v3.js"() {
    init_v35();
    init_md5();
    v3 = v35_default("v3", 48, md5_default);
    v3_default = v3;
  }
});

// node_modules/uuid/dist/esm-node/v4.js
function v4(options, buf, offset) {
  options = options || {};
  const rnds = options.random || (options.rng || rng)();
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  if (buf) {
    offset = offset || 0;
    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }
    return buf;
  }
  return stringify_default(rnds);
}
var v4_default;
var init_v4 = __esm({
  "node_modules/uuid/dist/esm-node/v4.js"() {
    init_rng();
    init_stringify();
    v4_default = v4;
  }
});

// node_modules/uuid/dist/esm-node/sha1.js
function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return import_crypto3.default.createHash("sha1").update(bytes).digest();
}
var import_crypto3, sha1_default;
var init_sha1 = __esm({
  "node_modules/uuid/dist/esm-node/sha1.js"() {
    import_crypto3 = __toESM(require("crypto"));
    sha1_default = sha1;
  }
});

// node_modules/uuid/dist/esm-node/v5.js
var v5, v5_default;
var init_v5 = __esm({
  "node_modules/uuid/dist/esm-node/v5.js"() {
    init_v35();
    init_sha1();
    v5 = v35_default("v5", 80, sha1_default);
    v5_default = v5;
  }
});

// node_modules/uuid/dist/esm-node/nil.js
var nil_default;
var init_nil = __esm({
  "node_modules/uuid/dist/esm-node/nil.js"() {
    nil_default = "00000000-0000-0000-0000-000000000000";
  }
});

// node_modules/uuid/dist/esm-node/version.js
function version(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  return parseInt(uuid.substr(14, 1), 16);
}
var version_default;
var init_version = __esm({
  "node_modules/uuid/dist/esm-node/version.js"() {
    init_validate();
    version_default = version;
  }
});

// node_modules/uuid/dist/esm-node/index.js
var esm_node_exports = {};
__export(esm_node_exports, {
  NIL: () => nil_default,
  parse: () => parse_default,
  stringify: () => stringify_default,
  v1: () => v1_default,
  v3: () => v3_default,
  v4: () => v4_default,
  v5: () => v5_default,
  validate: () => validate_default,
  version: () => version_default
});
var init_esm_node = __esm({
  "node_modules/uuid/dist/esm-node/index.js"() {
    init_v1();
    init_v3();
    init_v4();
    init_v5();
    init_nil();
    init_version();
    init_validate();
    init_stringify();
    init_parse();
  }
});

// node_modules/@actions/http-client/lib/proxy.js
var require_proxy = __commonJS({
  "node_modules/@actions/http-client/lib/proxy.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.checkBypass = exports2.getProxyUrl = void 0;
    function getProxyUrl(reqUrl) {
      const usingSsl = reqUrl.protocol === "https:";
      if (checkBypass(reqUrl)) {
        return void 0;
      }
      const proxyVar = (() => {
        if (usingSsl) {
          return process.env["https_proxy"] || process.env["HTTPS_PROXY"];
        } else {
          return process.env["http_proxy"] || process.env["HTTP_PROXY"];
        }
      })();
      if (proxyVar) {
        return new URL(proxyVar);
      } else {
        return void 0;
      }
    }
    exports2.getProxyUrl = getProxyUrl;
    function checkBypass(reqUrl) {
      if (!reqUrl.hostname) {
        return false;
      }
      const noProxy = process.env["no_proxy"] || process.env["NO_PROXY"] || "";
      if (!noProxy) {
        return false;
      }
      let reqPort;
      if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
      } else if (reqUrl.protocol === "http:") {
        reqPort = 80;
      } else if (reqUrl.protocol === "https:") {
        reqPort = 443;
      }
      const upperReqHosts = [reqUrl.hostname.toUpperCase()];
      if (typeof reqPort === "number") {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
      }
      for (const upperNoProxyItem of noProxy.split(",").map((x) => x.trim().toUpperCase()).filter((x) => x)) {
        if (upperReqHosts.some((x) => x === upperNoProxyItem)) {
          return true;
        }
      }
      return false;
    }
    exports2.checkBypass = checkBypass;
  }
});

// node_modules/tunnel/lib/tunnel.js
var require_tunnel = __commonJS({
  "node_modules/tunnel/lib/tunnel.js"(exports2) {
    "use strict";
    var net = require("net");
    var tls = require("tls");
    var http = require("http");
    var https = require("https");
    var events = require("events");
    var assert = require("assert");
    var util = require("util");
    exports2.httpOverHttp = httpOverHttp;
    exports2.httpsOverHttp = httpsOverHttp;
    exports2.httpOverHttps = httpOverHttps;
    exports2.httpsOverHttps = httpsOverHttps;
    function httpOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      return agent;
    }
    function httpsOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function httpOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      return agent;
    }
    function httpsOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function TunnelingAgent(options) {
      var self = this;
      self.options = options || {};
      self.proxyOptions = self.options.proxy || {};
      self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets;
      self.requests = [];
      self.sockets = [];
      self.on("free", function onFree(socket, host, port, localAddress) {
        var options2 = toOptions(host, port, localAddress);
        for (var i = 0, len = self.requests.length; i < len; ++i) {
          var pending = self.requests[i];
          if (pending.host === options2.host && pending.port === options2.port) {
            self.requests.splice(i, 1);
            pending.request.onSocket(socket);
            return;
          }
        }
        socket.destroy();
        self.removeSocket(socket);
      });
    }
    util.inherits(TunnelingAgent, events.EventEmitter);
    TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
      var self = this;
      var options = mergeOptions({ request: req }, self.options, toOptions(host, port, localAddress));
      if (self.sockets.length >= this.maxSockets) {
        self.requests.push(options);
        return;
      }
      self.createSocket(options, function(socket) {
        socket.on("free", onFree);
        socket.on("close", onCloseOrRemove);
        socket.on("agentRemove", onCloseOrRemove);
        req.onSocket(socket);
        function onFree() {
          self.emit("free", socket, options);
        }
        function onCloseOrRemove(err) {
          self.removeSocket(socket);
          socket.removeListener("free", onFree);
          socket.removeListener("close", onCloseOrRemove);
          socket.removeListener("agentRemove", onCloseOrRemove);
        }
      });
    };
    TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
      var self = this;
      var placeholder = {};
      self.sockets.push(placeholder);
      var connectOptions = mergeOptions({}, self.proxyOptions, {
        method: "CONNECT",
        path: options.host + ":" + options.port,
        agent: false,
        headers: {
          host: options.host + ":" + options.port
        }
      });
      if (options.localAddress) {
        connectOptions.localAddress = options.localAddress;
      }
      if (connectOptions.proxyAuth) {
        connectOptions.headers = connectOptions.headers || {};
        connectOptions.headers["Proxy-Authorization"] = "Basic " + new Buffer(connectOptions.proxyAuth).toString("base64");
      }
      debug("making CONNECT request");
      var connectReq = self.request(connectOptions);
      connectReq.useChunkedEncodingByDefault = false;
      connectReq.once("response", onResponse);
      connectReq.once("upgrade", onUpgrade);
      connectReq.once("connect", onConnect);
      connectReq.once("error", onError);
      connectReq.end();
      function onResponse(res) {
        res.upgrade = true;
      }
      function onUpgrade(res, socket, head) {
        process.nextTick(function() {
          onConnect(res, socket, head);
        });
      }
      function onConnect(res, socket, head) {
        connectReq.removeAllListeners();
        socket.removeAllListeners();
        if (res.statusCode !== 200) {
          debug(
            "tunneling socket could not be established, statusCode=%d",
            res.statusCode
          );
          socket.destroy();
          var error = new Error("tunneling socket could not be established, statusCode=" + res.statusCode);
          error.code = "ECONNRESET";
          options.request.emit("error", error);
          self.removeSocket(placeholder);
          return;
        }
        if (head.length > 0) {
          debug("got illegal response body from proxy");
          socket.destroy();
          var error = new Error("got illegal response body from proxy");
          error.code = "ECONNRESET";
          options.request.emit("error", error);
          self.removeSocket(placeholder);
          return;
        }
        debug("tunneling connection has established");
        self.sockets[self.sockets.indexOf(placeholder)] = socket;
        return cb(socket);
      }
      function onError(cause) {
        connectReq.removeAllListeners();
        debug(
          "tunneling socket could not be established, cause=%s\n",
          cause.message,
          cause.stack
        );
        var error = new Error("tunneling socket could not be established, cause=" + cause.message);
        error.code = "ECONNRESET";
        options.request.emit("error", error);
        self.removeSocket(placeholder);
      }
    };
    TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
      var pos = this.sockets.indexOf(socket);
      if (pos === -1) {
        return;
      }
      this.sockets.splice(pos, 1);
      var pending = this.requests.shift();
      if (pending) {
        this.createSocket(pending, function(socket2) {
          pending.request.onSocket(socket2);
        });
      }
    };
    function createSecureSocket(options, cb) {
      var self = this;
      TunnelingAgent.prototype.createSocket.call(self, options, function(socket) {
        var hostHeader = options.request.getHeader("host");
        var tlsOptions = mergeOptions({}, self.options, {
          socket,
          servername: hostHeader ? hostHeader.replace(/:.*$/, "") : options.host
        });
        var secureSocket = tls.connect(0, tlsOptions);
        self.sockets[self.sockets.indexOf(socket)] = secureSocket;
        cb(secureSocket);
      });
    }
    function toOptions(host, port, localAddress) {
      if (typeof host === "string") {
        return {
          host,
          port,
          localAddress
        };
      }
      return host;
    }
    function mergeOptions(target) {
      for (var i = 1, len = arguments.length; i < len; ++i) {
        var overrides = arguments[i];
        if (typeof overrides === "object") {
          var keys = Object.keys(overrides);
          for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
            var k = keys[j];
            if (overrides[k] !== void 0) {
              target[k] = overrides[k];
            }
          }
        }
      }
      return target;
    }
    var debug;
    if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
      debug = function() {
        var args = Array.prototype.slice.call(arguments);
        if (typeof args[0] === "string") {
          args[0] = "TUNNEL: " + args[0];
        } else {
          args.unshift("TUNNEL:");
        }
        console.error.apply(console, args);
      };
    } else {
      debug = function() {
      };
    }
    exports2.debug = debug;
  }
});

// node_modules/tunnel/index.js
var require_tunnel2 = __commonJS({
  "node_modules/tunnel/index.js"(exports2, module2) {
    module2.exports = require_tunnel();
  }
});

// node_modules/@actions/http-client/lib/index.js
var require_lib = __commonJS({
  "node_modules/@actions/http-client/lib/index.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule) return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.HttpClient = exports2.isHttps = exports2.HttpClientResponse = exports2.HttpClientError = exports2.getProxyUrl = exports2.MediaTypes = exports2.Headers = exports2.HttpCodes = void 0;
    var http = __importStar(require("http"));
    var https = __importStar(require("https"));
    var pm = __importStar(require_proxy());
    var tunnel = __importStar(require_tunnel2());
    var HttpCodes;
    (function(HttpCodes2) {
      HttpCodes2[HttpCodes2["OK"] = 200] = "OK";
      HttpCodes2[HttpCodes2["MultipleChoices"] = 300] = "MultipleChoices";
      HttpCodes2[HttpCodes2["MovedPermanently"] = 301] = "MovedPermanently";
      HttpCodes2[HttpCodes2["ResourceMoved"] = 302] = "ResourceMoved";
      HttpCodes2[HttpCodes2["SeeOther"] = 303] = "SeeOther";
      HttpCodes2[HttpCodes2["NotModified"] = 304] = "NotModified";
      HttpCodes2[HttpCodes2["UseProxy"] = 305] = "UseProxy";
      HttpCodes2[HttpCodes2["SwitchProxy"] = 306] = "SwitchProxy";
      HttpCodes2[HttpCodes2["TemporaryRedirect"] = 307] = "TemporaryRedirect";
      HttpCodes2[HttpCodes2["PermanentRedirect"] = 308] = "PermanentRedirect";
      HttpCodes2[HttpCodes2["BadRequest"] = 400] = "BadRequest";
      HttpCodes2[HttpCodes2["Unauthorized"] = 401] = "Unauthorized";
      HttpCodes2[HttpCodes2["PaymentRequired"] = 402] = "PaymentRequired";
      HttpCodes2[HttpCodes2["Forbidden"] = 403] = "Forbidden";
      HttpCodes2[HttpCodes2["NotFound"] = 404] = "NotFound";
      HttpCodes2[HttpCodes2["MethodNotAllowed"] = 405] = "MethodNotAllowed";
      HttpCodes2[HttpCodes2["NotAcceptable"] = 406] = "NotAcceptable";
      HttpCodes2[HttpCodes2["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
      HttpCodes2[HttpCodes2["RequestTimeout"] = 408] = "RequestTimeout";
      HttpCodes2[HttpCodes2["Conflict"] = 409] = "Conflict";
      HttpCodes2[HttpCodes2["Gone"] = 410] = "Gone";
      HttpCodes2[HttpCodes2["TooManyRequests"] = 429] = "TooManyRequests";
      HttpCodes2[HttpCodes2["InternalServerError"] = 500] = "InternalServerError";
      HttpCodes2[HttpCodes2["NotImplemented"] = 501] = "NotImplemented";
      HttpCodes2[HttpCodes2["BadGateway"] = 502] = "BadGateway";
      HttpCodes2[HttpCodes2["ServiceUnavailable"] = 503] = "ServiceUnavailable";
      HttpCodes2[HttpCodes2["GatewayTimeout"] = 504] = "GatewayTimeout";
    })(HttpCodes = exports2.HttpCodes || (exports2.HttpCodes = {}));
    var Headers;
    (function(Headers2) {
      Headers2["Accept"] = "accept";
      Headers2["ContentType"] = "content-type";
    })(Headers = exports2.Headers || (exports2.Headers = {}));
    var MediaTypes;
    (function(MediaTypes2) {
      MediaTypes2["ApplicationJson"] = "application/json";
    })(MediaTypes = exports2.MediaTypes || (exports2.MediaTypes = {}));
    function getProxyUrl(serverUrl) {
      const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
      return proxyUrl ? proxyUrl.href : "";
    }
    exports2.getProxyUrl = getProxyUrl;
    var HttpRedirectCodes = [
      HttpCodes.MovedPermanently,
      HttpCodes.ResourceMoved,
      HttpCodes.SeeOther,
      HttpCodes.TemporaryRedirect,
      HttpCodes.PermanentRedirect
    ];
    var HttpResponseRetryCodes = [
      HttpCodes.BadGateway,
      HttpCodes.ServiceUnavailable,
      HttpCodes.GatewayTimeout
    ];
    var RetryableHttpVerbs = ["OPTIONS", "GET", "DELETE", "HEAD"];
    var ExponentialBackoffCeiling = 10;
    var ExponentialBackoffTimeSlice = 5;
    var HttpClientError = class _HttpClientError extends Error {
      constructor(message, statusCode) {
        super(message);
        this.name = "HttpClientError";
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, _HttpClientError.prototype);
      }
    };
    exports2.HttpClientError = HttpClientError;
    var HttpClientResponse = class {
      constructor(message) {
        this.message = message;
      }
      readBody() {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2) => __awaiter(this, void 0, void 0, function* () {
            let output = Buffer.alloc(0);
            this.message.on("data", (chunk) => {
              output = Buffer.concat([output, chunk]);
            });
            this.message.on("end", () => {
              resolve2(output.toString());
            });
          }));
        });
      }
    };
    exports2.HttpClientResponse = HttpClientResponse;
    function isHttps(requestUrl) {
      const parsedUrl = new URL(requestUrl);
      return parsedUrl.protocol === "https:";
    }
    exports2.isHttps = isHttps;
    var HttpClient = class {
      constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
          if (requestOptions.ignoreSslError != null) {
            this._ignoreSslError = requestOptions.ignoreSslError;
          }
          this._socketTimeout = requestOptions.socketTimeout;
          if (requestOptions.allowRedirects != null) {
            this._allowRedirects = requestOptions.allowRedirects;
          }
          if (requestOptions.allowRedirectDowngrade != null) {
            this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
          }
          if (requestOptions.maxRedirects != null) {
            this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
          }
          if (requestOptions.keepAlive != null) {
            this._keepAlive = requestOptions.keepAlive;
          }
          if (requestOptions.allowRetries != null) {
            this._allowRetries = requestOptions.allowRetries;
          }
          if (requestOptions.maxRetries != null) {
            this._maxRetries = requestOptions.maxRetries;
          }
        }
      }
      options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("OPTIONS", requestUrl, null, additionalHeaders || {});
        });
      }
      get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("GET", requestUrl, null, additionalHeaders || {});
        });
      }
      del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("DELETE", requestUrl, null, additionalHeaders || {});
        });
      }
      post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("POST", requestUrl, data, additionalHeaders || {});
        });
      }
      patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PATCH", requestUrl, data, additionalHeaders || {});
        });
      }
      put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PUT", requestUrl, data, additionalHeaders || {});
        });
      }
      head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("HEAD", requestUrl, null, additionalHeaders || {});
        });
      }
      sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request(verb, requestUrl, stream, additionalHeaders);
        });
      }
      /**
       * Gets a typed object from an endpoint
       * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
       */
      getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          const res = yield this.get(requestUrl, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.post(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.put(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.patch(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      /**
       * Makes a raw http request.
       * All other methods such as get, post, patch, and request ultimately call this.
       * Prefer get, del, post and patch
       */
      request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._disposed) {
            throw new Error("Client has already been disposed.");
          }
          const parsedUrl = new URL(requestUrl);
          let info2 = this._prepareRequest(verb, parsedUrl, headers);
          const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb) ? this._maxRetries + 1 : 1;
          let numTries = 0;
          let response;
          do {
            response = yield this.requestRaw(info2, data);
            if (response && response.message && response.message.statusCode === HttpCodes.Unauthorized) {
              let authenticationHandler;
              for (const handler of this.handlers) {
                if (handler.canHandleAuthentication(response)) {
                  authenticationHandler = handler;
                  break;
                }
              }
              if (authenticationHandler) {
                return authenticationHandler.handleAuthentication(this, info2, data);
              } else {
                return response;
              }
            }
            let redirectsRemaining = this._maxRedirects;
            while (response.message.statusCode && HttpRedirectCodes.includes(response.message.statusCode) && this._allowRedirects && redirectsRemaining > 0) {
              const redirectUrl = response.message.headers["location"];
              if (!redirectUrl) {
                break;
              }
              const parsedRedirectUrl = new URL(redirectUrl);
              if (parsedUrl.protocol === "https:" && parsedUrl.protocol !== parsedRedirectUrl.protocol && !this._allowRedirectDowngrade) {
                throw new Error("Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.");
              }
              yield response.readBody();
              if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                for (const header in headers) {
                  if (header.toLowerCase() === "authorization") {
                    delete headers[header];
                  }
                }
              }
              info2 = this._prepareRequest(verb, parsedRedirectUrl, headers);
              response = yield this.requestRaw(info2, data);
              redirectsRemaining--;
            }
            if (!response.message.statusCode || !HttpResponseRetryCodes.includes(response.message.statusCode)) {
              return response;
            }
            numTries += 1;
            if (numTries < maxTries) {
              yield response.readBody();
              yield this._performExponentialBackoff(numTries);
            }
          } while (numTries < maxTries);
          return response;
        });
      }
      /**
       * Needs to be called if keepAlive is set to true in request options.
       */
      dispose() {
        if (this._agent) {
          this._agent.destroy();
        }
        this._disposed = true;
      }
      /**
       * Raw request.
       * @param info
       * @param data
       */
      requestRaw(info2, data) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2, reject) => {
            function callbackForResult(err, res) {
              if (err) {
                reject(err);
              } else if (!res) {
                reject(new Error("Unknown error"));
              } else {
                resolve2(res);
              }
            }
            this.requestRawWithCallback(info2, data, callbackForResult);
          });
        });
      }
      /**
       * Raw request with callback.
       * @param info
       * @param data
       * @param onResult
       */
      requestRawWithCallback(info2, data, onResult) {
        if (typeof data === "string") {
          if (!info2.options.headers) {
            info2.options.headers = {};
          }
          info2.options.headers["Content-Length"] = Buffer.byteLength(data, "utf8");
        }
        let callbackCalled = false;
        function handleResult(err, res) {
          if (!callbackCalled) {
            callbackCalled = true;
            onResult(err, res);
          }
        }
        const req = info2.httpModule.request(info2.options, (msg) => {
          const res = new HttpClientResponse(msg);
          handleResult(void 0, res);
        });
        let socket;
        req.on("socket", (sock) => {
          socket = sock;
        });
        req.setTimeout(this._socketTimeout || 3 * 6e4, () => {
          if (socket) {
            socket.end();
          }
          handleResult(new Error(`Request timeout: ${info2.options.path}`));
        });
        req.on("error", function(err) {
          handleResult(err);
        });
        if (data && typeof data === "string") {
          req.write(data, "utf8");
        }
        if (data && typeof data !== "string") {
          data.on("close", function() {
            req.end();
          });
          data.pipe(req);
        } else {
          req.end();
        }
      }
      /**
       * Gets an http agent. This function is useful when you need an http agent that handles
       * routing through a proxy server - depending upon the url and proxy environment variables.
       * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
       */
      getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
      }
      _prepareRequest(method, requestUrl, headers) {
        const info2 = {};
        info2.parsedUrl = requestUrl;
        const usingSsl = info2.parsedUrl.protocol === "https:";
        info2.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info2.options = {};
        info2.options.host = info2.parsedUrl.hostname;
        info2.options.port = info2.parsedUrl.port ? parseInt(info2.parsedUrl.port) : defaultPort;
        info2.options.path = (info2.parsedUrl.pathname || "") + (info2.parsedUrl.search || "");
        info2.options.method = method;
        info2.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
          info2.options.headers["user-agent"] = this.userAgent;
        }
        info2.options.agent = this._getAgent(info2.parsedUrl);
        if (this.handlers) {
          for (const handler of this.handlers) {
            handler.prepareRequest(info2.options);
          }
        }
        return info2;
      }
      _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
          return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
      }
      _getExistingOrDefaultHeader(additionalHeaders, header, _default) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
          clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default;
      }
      _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
          agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
          agent = this._agent;
        }
        if (agent) {
          return agent;
        }
        const usingSsl = parsedUrl.protocol === "https:";
        let maxSockets = 100;
        if (this.requestOptions) {
          maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        if (proxyUrl && proxyUrl.hostname) {
          const agentOptions = {
            maxSockets,
            keepAlive: this._keepAlive,
            proxy: Object.assign(Object.assign({}, (proxyUrl.username || proxyUrl.password) && {
              proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
            }), { host: proxyUrl.hostname, port: proxyUrl.port })
          };
          let tunnelAgent;
          const overHttps = proxyUrl.protocol === "https:";
          if (usingSsl) {
            tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
          } else {
            tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
          }
          agent = tunnelAgent(agentOptions);
          this._proxyAgent = agent;
        }
        if (this._keepAlive && !agent) {
          const options = { keepAlive: this._keepAlive, maxSockets };
          agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
          this._agent = agent;
        }
        if (!agent) {
          agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
          agent.options = Object.assign(agent.options || {}, {
            rejectUnauthorized: false
          });
        }
        return agent;
      }
      _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
          retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
          const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
          return new Promise((resolve2) => setTimeout(() => resolve2(), ms));
        });
      }
      _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2, reject) => __awaiter(this, void 0, void 0, function* () {
            const statusCode = res.message.statusCode || 0;
            const response = {
              statusCode,
              result: null,
              headers: {}
            };
            if (statusCode === HttpCodes.NotFound) {
              resolve2(response);
            }
            function dateTimeDeserializer(key, value) {
              if (typeof value === "string") {
                const a = new Date(value);
                if (!isNaN(a.valueOf())) {
                  return a;
                }
              }
              return value;
            }
            let obj;
            let contents;
            try {
              contents = yield res.readBody();
              if (contents && contents.length > 0) {
                if (options && options.deserializeDates) {
                  obj = JSON.parse(contents, dateTimeDeserializer);
                } else {
                  obj = JSON.parse(contents);
                }
                response.result = obj;
              }
              response.headers = res.message.headers;
            } catch (err) {
            }
            if (statusCode > 299) {
              let msg;
              if (obj && obj.message) {
                msg = obj.message;
              } else if (contents && contents.length > 0) {
                msg = contents;
              } else {
                msg = `Failed request: (${statusCode})`;
              }
              const err = new HttpClientError(msg, statusCode);
              err.result = response.result;
              reject(err);
            } else {
              resolve2(response);
            }
          }));
        });
      }
    };
    exports2.HttpClient = HttpClient;
    var lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => (c[k.toLowerCase()] = obj[k], c), {});
  }
});

// node_modules/@actions/http-client/lib/auth.js
var require_auth = __commonJS({
  "node_modules/@actions/http-client/lib/auth.js"(exports2) {
    "use strict";
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.PersonalAccessTokenCredentialHandler = exports2.BearerCredentialHandler = exports2.BasicCredentialHandler = void 0;
    var BasicCredentialHandler = class {
      constructor(username, password) {
        this.username = username;
        this.password = password;
      }
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports2.BasicCredentialHandler = BasicCredentialHandler;
    var BearerCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Bearer ${this.token}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports2.BearerCredentialHandler = BearerCredentialHandler;
    var PersonalAccessTokenCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`PAT:${this.token}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports2.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
  }
});

// node_modules/@actions/core/lib/oidc-utils.js
var require_oidc_utils = __commonJS({
  "node_modules/@actions/core/lib/oidc-utils.js"(exports2) {
    "use strict";
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.OidcClient = void 0;
    var http_client_1 = require_lib();
    var auth_1 = require_auth();
    var core_1 = require_core();
    var OidcClient = class _OidcClient {
      static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
          allowRetries: allowRetry,
          maxRetries: maxRetry
        };
        return new http_client_1.HttpClient("actions/oidc-client", [new auth_1.BearerCredentialHandler(_OidcClient.getRequestToken())], requestOptions);
      }
      static getRequestToken() {
        const token = process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
        if (!token) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable");
        }
        return token;
      }
      static getIDTokenUrl() {
        const runtimeUrl = process.env["ACTIONS_ID_TOKEN_REQUEST_URL"];
        if (!runtimeUrl) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable");
        }
        return runtimeUrl;
      }
      static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
          const httpclient = _OidcClient.createHttpClient();
          const res = yield httpclient.getJson(id_token_url).catch((error) => {
            throw new Error(`Failed to get ID Token. 
 
        Error Code : ${error.statusCode}
 
        Error Message: ${error.result.message}`);
          });
          const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
          if (!id_token) {
            throw new Error("Response json body do not have ID Token field");
          }
          return id_token;
        });
      }
      static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
          try {
            let id_token_url = _OidcClient.getIDTokenUrl();
            if (audience) {
              const encodedAudience = encodeURIComponent(audience);
              id_token_url = `${id_token_url}&audience=${encodedAudience}`;
            }
            core_1.debug(`ID token url is ${id_token_url}`);
            const id_token = yield _OidcClient.getCall(id_token_url);
            core_1.setSecret(id_token);
            return id_token;
          } catch (error) {
            throw new Error(`Error message: ${error.message}`);
          }
        });
      }
    };
    exports2.OidcClient = OidcClient;
  }
});

// node_modules/@actions/core/lib/summary.js
var require_summary = __commonJS({
  "node_modules/@actions/core/lib/summary.js"(exports2) {
    "use strict";
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.summary = exports2.markdownSummary = exports2.SUMMARY_DOCS_URL = exports2.SUMMARY_ENV_VAR = void 0;
    var os_1 = require("os");
    var fs_1 = require("fs");
    var { access, appendFile, writeFile } = fs_1.promises;
    exports2.SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY";
    exports2.SUMMARY_DOCS_URL = "https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary";
    var Summary = class {
      constructor() {
        this._buffer = "";
      }
      /**
       * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
       * Also checks r/w permissions.
       *
       * @returns step summary file path
       */
      filePath() {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._filePath) {
            return this._filePath;
          }
          const pathFromEnv = process.env[exports2.SUMMARY_ENV_VAR];
          if (!pathFromEnv) {
            throw new Error(`Unable to find environment variable for $${exports2.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
          }
          try {
            yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
          } catch (_a) {
            throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
          }
          this._filePath = pathFromEnv;
          return this._filePath;
        });
      }
      /**
       * Wraps content in an HTML tag, adding any HTML attributes
       *
       * @param {string} tag HTML tag to wrap
       * @param {string | null} content content within the tag
       * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
       *
       * @returns {string} content wrapped in HTML element
       */
      wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs).map(([key, value]) => ` ${key}="${value}"`).join("");
        if (!content) {
          return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
      }
      /**
       * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
       *
       * @param {SummaryWriteOptions} [options] (optional) options for write operation
       *
       * @returns {Promise<Summary>} summary instance
       */
      write(options) {
        return __awaiter(this, void 0, void 0, function* () {
          const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
          const filePath = yield this.filePath();
          const writeFunc = overwrite ? writeFile : appendFile;
          yield writeFunc(filePath, this._buffer, { encoding: "utf8" });
          return this.emptyBuffer();
        });
      }
      /**
       * Clears the summary buffer and wipes the summary file
       *
       * @returns {Summary} summary instance
       */
      clear() {
        return __awaiter(this, void 0, void 0, function* () {
          return this.emptyBuffer().write({ overwrite: true });
        });
      }
      /**
       * Returns the current summary buffer as a string
       *
       * @returns {string} string of summary buffer
       */
      stringify() {
        return this._buffer;
      }
      /**
       * If the summary buffer is empty
       *
       * @returns {boolen} true if the buffer is empty
       */
      isEmptyBuffer() {
        return this._buffer.length === 0;
      }
      /**
       * Resets the summary buffer without writing to summary file
       *
       * @returns {Summary} summary instance
       */
      emptyBuffer() {
        this._buffer = "";
        return this;
      }
      /**
       * Adds raw text to the summary buffer
       *
       * @param {string} text content to add
       * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
       *
       * @returns {Summary} summary instance
       */
      addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
      }
      /**
       * Adds the operating system-specific end-of-line marker to the buffer
       *
       * @returns {Summary} summary instance
       */
      addEOL() {
        return this.addRaw(os_1.EOL);
      }
      /**
       * Adds an HTML codeblock to the summary buffer
       *
       * @param {string} code content to render within fenced code block
       * @param {string} lang (optional) language to syntax highlight code
       *
       * @returns {Summary} summary instance
       */
      addCodeBlock(code, lang) {
        const attrs = Object.assign({}, lang && { lang });
        const element = this.wrap("pre", this.wrap("code", code), attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML list to the summary buffer
       *
       * @param {string[]} items list of items to render
       * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
       *
       * @returns {Summary} summary instance
       */
      addList(items, ordered = false) {
        const tag = ordered ? "ol" : "ul";
        const listItems = items.map((item) => this.wrap("li", item)).join("");
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML table to the summary buffer
       *
       * @param {SummaryTableCell[]} rows table rows
       *
       * @returns {Summary} summary instance
       */
      addTable(rows) {
        const tableBody = rows.map((row) => {
          const cells = row.map((cell) => {
            if (typeof cell === "string") {
              return this.wrap("td", cell);
            }
            const { header, data, colspan, rowspan } = cell;
            const tag = header ? "th" : "td";
            const attrs = Object.assign(Object.assign({}, colspan && { colspan }), rowspan && { rowspan });
            return this.wrap(tag, data, attrs);
          }).join("");
          return this.wrap("tr", cells);
        }).join("");
        const element = this.wrap("table", tableBody);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds a collapsable HTML details element to the summary buffer
       *
       * @param {string} label text for the closed state
       * @param {string} content collapsable content
       *
       * @returns {Summary} summary instance
       */
      addDetails(label, content) {
        const element = this.wrap("details", this.wrap("summary", label) + content);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML image tag to the summary buffer
       *
       * @param {string} src path to the image you to embed
       * @param {string} alt text description of the image
       * @param {SummaryImageOptions} options (optional) addition image attributes
       *
       * @returns {Summary} summary instance
       */
      addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, width && { width }), height && { height });
        const element = this.wrap("img", null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML section heading element
       *
       * @param {string} text heading text
       * @param {number | string} [level=1] (optional) the heading level, default: 1
       *
       * @returns {Summary} summary instance
       */
      addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ["h1", "h2", "h3", "h4", "h5", "h6"].includes(tag) ? tag : "h1";
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML thematic break (<hr>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addSeparator() {
        const element = this.wrap("hr", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML line break (<br>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addBreak() {
        const element = this.wrap("br", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML blockquote to the summary buffer
       *
       * @param {string} text quote text
       * @param {string} cite (optional) citation url
       *
       * @returns {Summary} summary instance
       */
      addQuote(text, cite) {
        const attrs = Object.assign({}, cite && { cite });
        const element = this.wrap("blockquote", text, attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML anchor tag to the summary buffer
       *
       * @param {string} text link text/content
       * @param {string} href hyperlink
       *
       * @returns {Summary} summary instance
       */
      addLink(text, href) {
        const element = this.wrap("a", text, { href });
        return this.addRaw(element).addEOL();
      }
    };
    var _summary = new Summary();
    exports2.markdownSummary = _summary;
    exports2.summary = _summary;
  }
});

// node_modules/@actions/core/lib/path-utils.js
var require_path_utils = __commonJS({
  "node_modules/@actions/core/lib/path-utils.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule) return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.toPlatformPath = exports2.toWin32Path = exports2.toPosixPath = void 0;
    var path3 = __importStar(require("path"));
    function toPosixPath(pth) {
      return pth.replace(/[\\]/g, "/");
    }
    exports2.toPosixPath = toPosixPath;
    function toWin32Path(pth) {
      return pth.replace(/[/]/g, "\\");
    }
    exports2.toWin32Path = toWin32Path;
    function toPlatformPath(pth) {
      return pth.replace(/[/\\]/g, path3.sep);
    }
    exports2.toPlatformPath = toPlatformPath;
  }
});

// node_modules/@actions/core/lib/core.js
var require_core = __commonJS({
  "node_modules/@actions/core/lib/core.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule) return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.getIDToken = exports2.getState = exports2.saveState = exports2.group = exports2.endGroup = exports2.startGroup = exports2.info = exports2.notice = exports2.warning = exports2.error = exports2.debug = exports2.isDebug = exports2.setFailed = exports2.setCommandEcho = exports2.setOutput = exports2.getBooleanInput = exports2.getMultilineInput = exports2.getInput = exports2.addPath = exports2.setSecret = exports2.exportVariable = exports2.ExitCode = void 0;
    var command_1 = require_command();
    var file_command_1 = require_file_command();
    var utils_1 = require_utils();
    var os = __importStar(require("os"));
    var path3 = __importStar(require("path"));
    var uuid_1 = (init_esm_node(), __toCommonJS(esm_node_exports));
    var oidc_utils_1 = require_oidc_utils();
    var ExitCode;
    (function(ExitCode2) {
      ExitCode2[ExitCode2["Success"] = 0] = "Success";
      ExitCode2[ExitCode2["Failure"] = 1] = "Failure";
    })(ExitCode = exports2.ExitCode || (exports2.ExitCode = {}));
    function exportVariable(name, val) {
      const convertedVal = utils_1.toCommandValue(val);
      process.env[name] = convertedVal;
      const filePath = process.env["GITHUB_ENV"] || "";
      if (filePath) {
        const delimiter = `ghadelimiter_${uuid_1.v4()}`;
        if (name.includes(delimiter)) {
          throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
        }
        if (convertedVal.includes(delimiter)) {
          throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
        }
        const commandValue = `${name}<<${delimiter}${os.EOL}${convertedVal}${os.EOL}${delimiter}`;
        file_command_1.issueCommand("ENV", commandValue);
      } else {
        command_1.issueCommand("set-env", { name }, convertedVal);
      }
    }
    exports2.exportVariable = exportVariable;
    function setSecret(secret) {
      command_1.issueCommand("add-mask", {}, secret);
    }
    exports2.setSecret = setSecret;
    function addPath(inputPath) {
      const filePath = process.env["GITHUB_PATH"] || "";
      if (filePath) {
        file_command_1.issueCommand("PATH", inputPath);
      } else {
        command_1.issueCommand("add-path", {}, inputPath);
      }
      process.env["PATH"] = `${inputPath}${path3.delimiter}${process.env["PATH"]}`;
    }
    exports2.addPath = addPath;
    function getInput(name, options) {
      const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
      if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
      }
      if (options && options.trimWhitespace === false) {
        return val;
      }
      return val.trim();
    }
    exports2.getInput = getInput;
    function getMultilineInput(name, options) {
      const inputs = getInput(name, options).split("\n").filter((x) => x !== "");
      return inputs;
    }
    exports2.getMultilineInput = getMultilineInput;
    function getBooleanInput(name, options) {
      const trueValue = ["true", "True", "TRUE"];
      const falseValue = ["false", "False", "FALSE"];
      const val = getInput(name, options);
      if (trueValue.includes(val))
        return true;
      if (falseValue.includes(val))
        return false;
      throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}
Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
    }
    exports2.getBooleanInput = getBooleanInput;
    function setOutput(name, value) {
      process.stdout.write(os.EOL);
      command_1.issueCommand("set-output", { name }, value);
    }
    exports2.setOutput = setOutput;
    function setCommandEcho(enabled) {
      command_1.issue("echo", enabled ? "on" : "off");
    }
    exports2.setCommandEcho = setCommandEcho;
    function setFailed2(message) {
      process.exitCode = ExitCode.Failure;
      error(message);
    }
    exports2.setFailed = setFailed2;
    function isDebug() {
      return process.env["RUNNER_DEBUG"] === "1";
    }
    exports2.isDebug = isDebug;
    function debug(message) {
      command_1.issueCommand("debug", {}, message);
    }
    exports2.debug = debug;
    function error(message, properties = {}) {
      command_1.issueCommand("error", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports2.error = error;
    function warning(message, properties = {}) {
      command_1.issueCommand("warning", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports2.warning = warning;
    function notice2(message, properties = {}) {
      command_1.issueCommand("notice", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports2.notice = notice2;
    function info2(message) {
      process.stdout.write(message + os.EOL);
    }
    exports2.info = info2;
    function startGroup2(name) {
      command_1.issue("group", name);
    }
    exports2.startGroup = startGroup2;
    function endGroup2() {
      command_1.issue("endgroup");
    }
    exports2.endGroup = endGroup2;
    function group(name, fn) {
      return __awaiter(this, void 0, void 0, function* () {
        startGroup2(name);
        let result;
        try {
          result = yield fn();
        } finally {
          endGroup2();
        }
        return result;
      });
    }
    exports2.group = group;
    function saveState(name, value) {
      command_1.issueCommand("save-state", { name }, value);
    }
    exports2.saveState = saveState;
    function getState(name) {
      return process.env[`STATE_${name}`] || "";
    }
    exports2.getState = getState;
    function getIDToken(aud) {
      return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
      });
    }
    exports2.getIDToken = getIDToken;
    var summary_1 = require_summary();
    Object.defineProperty(exports2, "summary", { enumerable: true, get: function() {
      return summary_1.summary;
    } });
    var summary_2 = require_summary();
    Object.defineProperty(exports2, "markdownSummary", { enumerable: true, get: function() {
      return summary_2.markdownSummary;
    } });
    var path_utils_1 = require_path_utils();
    Object.defineProperty(exports2, "toPosixPath", { enumerable: true, get: function() {
      return path_utils_1.toPosixPath;
    } });
    Object.defineProperty(exports2, "toWin32Path", { enumerable: true, get: function() {
      return path_utils_1.toWin32Path;
    } });
    Object.defineProperty(exports2, "toPlatformPath", { enumerable: true, get: function() {
      return path_utils_1.toPlatformPath;
    } });
  }
});

// node_modules/gm/lib/options.js
var require_options = __commonJS({
  "node_modules/gm/lib/options.js"(exports2, module2) {
    module2.exports = exports2 = function(proto) {
      proto._options = {};
      proto.options = function setOptions(options) {
        var keys = Object.keys(options), i = keys.length, key;
        while (i--) {
          key = keys[i];
          this._options[key] = options[key];
        }
        return this;
      };
    };
  }
});

// node_modules/gm/lib/getters.js
var require_getters = __commonJS({
  "node_modules/gm/lib/getters.js"(exports2, module2) {
    module2.exports = function(gm2) {
      var proto = gm2.prototype;
      const IDENTIFYING = 1;
      const IDENTIFIED = 2;
      var map = {
        "format": { key: "format", format: "%m ", helper: "Format" },
        "depth": { key: "depth", format: "%q" },
        "filesize": { key: "Filesize", format: "%b" },
        "size": { key: "size", format: "%wx%h ", helper: "Geometry" },
        "color": { key: "color", format: "%k", helper: "Colors" },
        "orientation": { key: "Orientation", format: "%[EXIF:Orientation]", helper: "Orientation" },
        "res": { key: "Resolution", verbose: true }
      };
      Object.keys(map).forEach(function(getter) {
        proto[getter] = function(opts, callback) {
          if (!callback) callback = opts, opts = {};
          if (!callback) return this;
          var val = map[getter], key = val.key, self = this;
          if (self.data[key]) {
            callback.call(self, null, self.data[key]);
            return self;
          }
          self.on(getter, callback);
          self.bufferStream = !!opts.bufferStream;
          if (val.verbose) {
            self.identify(opts, function(err, stdout, stderr, cmd) {
              if (err) {
                self.emit(getter, err, self.data[key], stdout, stderr, cmd);
              } else {
                self.emit(getter, err, self.data[key]);
              }
            });
            return self;
          }
          var args = makeArgs(self, val);
          self._exec(args, function(err, stdout, stderr, cmd) {
            if (err) {
              self.emit(getter, err, self.data[key], stdout, stderr, cmd);
              return;
            }
            var result = (stdout || "").trim();
            if (val.helper in helper) {
              helper[val.helper](self.data, result);
            } else {
              self.data[key] = result;
            }
            self.emit(getter, err, self.data[key]);
          });
          return self;
        };
      });
      proto.identify = function identify(opts, callback) {
        if (typeof opts === "string") {
          opts = {
            format: opts
          };
        }
        if (!callback) callback = opts, opts = {};
        if (!callback) return this;
        if (opts && opts.format) return identifyPattern.call(this, opts, callback);
        var self = this;
        if (IDENTIFIED === self._identifyState) {
          callback.call(self, null, self.data);
          return self;
        }
        self.on("identify", callback);
        if (IDENTIFYING === self._identifyState) {
          return self;
        }
        self._identifyState = IDENTIFYING;
        self.bufferStream = !!opts.bufferStream;
        var args = makeArgs(self, { verbose: true });
        self._exec(args, function(err, stdout, stderr, cmd) {
          if (err) {
            self.emit("identify", err, self.data, stdout, stderr, cmd);
            return;
          }
          err = parse3(stdout, self);
          if (err) {
            self.emit("identify", err, self.data, stdout, stderr, cmd);
            return;
          }
          self.data.path = self.source;
          self.emit("identify", null, self.data);
          self._identifyState = IDENTIFIED;
        });
        return self;
      };
      function identifyPattern(opts, callback) {
        var self = this;
        self.bufferStream = !!opts.bufferStream;
        var args = makeArgs(self, opts);
        self._exec(args, function(err, stdout, stderr, cmd) {
          if (err) {
            return callback.call(self, err, void 0, stdout, stderr, cmd);
          }
          callback.call(self, err, (stdout || "").trim());
        });
        return self;
      }
      function parse3(stdout, self) {
        var parts = (stdout || "").trim().replace(/\r\n|\r/g, "\n").split("\n");
        parts.shift();
        try {
          var len = parts.length, rgx1 = /^( *)(.+?): (.*)$/, rgx2 = /^( *)(.+?):$/, out = { indent: {} }, level = null, lastkey, i = 0, res, o;
          for (; i < len; ++i) {
            res = rgx1.exec(parts[i]) || rgx2.exec(parts[i]);
            if (!res) continue;
            var indent = res[1].length, key = res[2] ? res[2].trim() : "";
            if ("Image" == key || "Warning" == key) continue;
            var val = res[3] ? res[3].trim() : null;
            if (null === level) {
              level = indent;
              o = out.root = out.indent[level] = self.data;
            } else if (indent < level) {
              if (!(indent in out.indent)) {
                continue;
              }
              o = out.indent[indent];
            } else if (indent > level) {
              out.indent[level] = o;
              o = o[lastkey] = {};
            }
            level = indent;
            if (val) {
              if (o.hasOwnProperty(key)) {
                if (!Array.isArray(o[key])) {
                  var tmp = o[key];
                  o[key] = [tmp];
                }
                o[key].push(val);
              } else {
                o[key] = val;
              }
              if (key in helper) {
                helper[key](o, val);
              }
            }
            lastkey = key;
          }
        } catch (err) {
          err.message = err.message + "\n\n  Identify stdout:\n  " + stdout;
          return err;
        }
      }
      function makeArgs(self, val) {
        var args = [
          "identify",
          "-ping"
        ];
        if (val.format) {
          args.push("-format", val.format);
        }
        if (val.verbose) {
          args.push("-verbose");
        }
        args = args.concat(self.src());
        return args;
      }
      var orientations = {
        "1": "TopLeft",
        "2": "TopRight",
        "3": "BottomRight",
        "4": "BottomLeft",
        "5": "LeftTop",
        "6": "RightTop",
        "7": "RightBottom",
        "8": "LeftBottom"
      };
      var helper = gm2.identifyHelpers = {};
      helper.Geometry = function Geometry(o, val) {
        var split = val.split(" ").shift().split("x");
        var width = parseInt(split[0], 10);
        var height = parseInt(split[1], 10);
        if (o.size && o.size.width && o.size.height) {
          if (width > o.size.width) o.size.width = width;
          if (height > o.size.height) o.size.height = height;
        } else {
          o.size = {
            width,
            height
          };
        }
      };
      helper.Format = function Format(o, val) {
        o.format = val.split(" ")[0];
      };
      helper.Depth = function Depth(o, val) {
        o.depth = parseInt(val, 10);
      };
      helper.Colors = function Colors(o, val) {
        o.color = parseInt(val, 10);
      };
      helper.Orientation = function Orientation(o, val) {
        if (val in orientations) {
          o["Profile-EXIF"] || (o["Profile-EXIF"] = {});
          o["Profile-EXIF"].Orientation = val;
          o.Orientation = orientations[val];
        } else {
          o.Orientation = val || "Unknown";
        }
      };
    };
  }
});

// node_modules/gm/lib/utils.js
var require_utils2 = __commonJS({
  "node_modules/gm/lib/utils.js"(exports2) {
    exports2.escape = function escape(arg) {
      return '"' + String(arg).trim().replace(/"/g, '\\"') + '"';
    };
    exports2.unescape = function escape(arg) {
      return String(arg).trim().replace(/"/g, "");
    };
    exports2.argsToArray = function(args) {
      var arr = [];
      for (var i = 0; i <= arguments.length; i++) {
        if ("undefined" != typeof arguments[i])
          arr.push(arguments[i]);
      }
      return arr;
    };
    exports2.isUtil = function(v) {
      var ty = "object";
      switch (Object.prototype.toString.call(v)) {
        case "[object String]":
          ty = "String";
          break;
        case "[object Array]":
          ty = "Array";
          break;
        case "[object Boolean]":
          ty = "Boolean";
          break;
      }
      return ty;
    };
  }
});

// node_modules/gm/lib/args.js
var require_args = __commonJS({
  "node_modules/gm/lib/args.js"(exports2, module2) {
    var argsToArray = require_utils2().argsToArray;
    var isUtil = require_utils2().isUtil;
    module2.exports = function(proto) {
      proto.selectFrame = function(frame) {
        if (typeof frame === "number")
          this.sourceFrames = "[" + frame + "]";
        return this;
      };
      proto.command = proto.subCommand = function subCommand(name) {
        this._subCommand = name;
        return this;
      };
      proto.adjoin = function adjoin() {
        return this.out("-adjoin");
      };
      proto.affine = function affine(matrix) {
        return this.out("-affine", matrix);
      };
      proto.alpha = function alpha(type) {
        if (!this._options.imageMagick) return new Error("Method -alpha is not supported by GraphicsMagick");
        return this.out("-alpha", type);
      };
      proto.append = function append(img, ltr) {
        if (!this._append) {
          this._append = [];
          this.addSrcFormatter(function(src) {
            this.out(this._append.ltr ? "+append" : "-append");
            src.push.apply(src, this._append);
          });
        }
        if (0 === arguments.length) {
          this._append.ltr = false;
          return this;
        }
        for (var i = 0; i < arguments.length; ++i) {
          var arg = arguments[i];
          switch (isUtil(arg)) {
            case "Boolean":
              this._append.ltr = arg;
              break;
            case "String":
              this._append.push(arg);
              break;
            case "Array":
              for (var j = 0, len = arg.length; j < len; j++) {
                if (isUtil(arg[j]) == "String") {
                  this._append.push(arg[j]);
                }
              }
              break;
          }
        }
        return this;
      };
      proto.authenticate = function authenticate(string) {
        return this.out("-authenticate", string);
      };
      proto.average = function average() {
        return this.out("-average");
      };
      proto.backdrop = function backdrop() {
        return this.out("-backdrop");
      };
      proto.blackThreshold = function blackThreshold(red, green, blue, opacity) {
        return this.out("-black-threshold", argsToArray(red, green, blue, opacity).join(","));
      };
      proto.bluePrimary = function bluePrimary(x, y) {
        return this.out("-blue-primary", argsToArray(x, y).join(","));
      };
      proto.border = function border(width, height) {
        return this.out("-border", width + "x" + height);
      };
      proto.borderColor = function borderColor(color) {
        return this.out("-bordercolor", color);
      };
      proto.box = function box(color) {
        return this.out("-box", color);
      };
      proto.channel = function channel(type) {
        return this.out("-channel", type);
      };
      proto.chop = function chop(w, h, x, y) {
        return this.in("-chop", w + "x" + h + "+" + (x || 0) + "+" + (y || 0));
      };
      proto.clip = function clip() {
        return this.out("-clip");
      };
      proto.coalesce = function coalesce() {
        return this.out("-coalesce");
      };
      proto.colorize = function colorize(r, g, b) {
        return this.out("-colorize", [r, g, b].join(","));
      };
      proto.colorMap = function colorMap(type) {
        return this.out("-colormap", type);
      };
      proto.compose = function compose(operator) {
        return this.out("-compose", operator);
      };
      proto.compress = function compress(type) {
        return this.out("-compress", type);
      };
      proto.convolve = function convolve(kernel) {
        return this.out("-convolve", kernel);
      };
      proto.createDirectories = function createDirectories() {
        return this.out("-create-directories");
      };
      proto.deconstruct = function deconstruct() {
        return this.out("-deconstruct");
      };
      proto.define = function define(value) {
        return this.out("-define", value);
      };
      proto.delay = function delay(value) {
        return this.out("-delay", value);
      };
      proto.displace = function displace(horizontalScale, verticalScale) {
        return this.out("-displace", horizontalScale + "x" + verticalScale);
      };
      proto.display = function display(value) {
        return this.out("-display", value);
      };
      proto.dispose = function dispose(method) {
        return this.out("-dispose", method);
      };
      proto.dissolve = function dissolve(percent) {
        return this.out("-dissolve", percent + "%");
      };
      proto.encoding = function encoding(type) {
        return this.out("-encoding", type);
      };
      proto.endian = function endian(type) {
        return this.out("-endian", type);
      };
      proto.file = function file(filename) {
        return this.out("-file", filename);
      };
      proto.flatten = function flatten() {
        return this.out("-flatten");
      };
      proto.foreground = function foreground(color) {
        return this.out("-foreground", color);
      };
      proto.frame = function frame(width, height, outerBevelWidth, innerBevelWidth) {
        if (arguments.length == 0) return this.out("-frame");
        return this.out("-frame", width + "x" + height + "+" + outerBevelWidth + "+" + innerBevelWidth);
      };
      proto.fuzz = function fuzz(distance, percent) {
        return this.out("-fuzz", distance + (percent ? "%" : ""));
      };
      proto.gaussian = function gaussian(radius, sigma) {
        return this.out("-gaussian", argsToArray(radius, sigma).join("x"));
      };
      proto.geometry = function geometry(width, height, arg) {
        if (arguments.length == 1 && typeof arguments[0] === "string")
          return this.out("-geometry", arguments[0]);
        return this.out("-geometry", width + "x" + height + (arg || ""));
      };
      proto.greenPrimary = function greenPrimary(x, y) {
        return this.out("-green-primary", x + "," + y);
      };
      proto.highlightColor = function highlightColor(color) {
        return this.out("-highlight-color", color);
      };
      proto.highlightStyle = function highlightStyle(style) {
        return this.out("-highlight-style", style);
      };
      proto.iconGeometry = function iconGeometry(geometry) {
        return this.out("-iconGeometry", geometry);
      };
      proto.intent = function intent(type) {
        return this.out("-intent", type);
      };
      proto.lat = function lat(width, height, offset, percent) {
        return this.out("-lat", width + "x" + height + offset + (percent ? "%" : ""));
      };
      proto.level = function level(blackPoint, gamma, whitePoint, percent) {
        return this.out("-level", argsToArray(blackPoint, gamma, whitePoint).join(",") + (percent ? "%" : ""));
      };
      proto.list = function list(type) {
        return this.out("-list", type);
      };
      proto.log = function log(string) {
        return this.out("-log", string);
      };
      proto.loop = function loop(iterations) {
        return this.out("-loop", iterations);
      };
      proto.map = function map(filename) {
        return this.out("-map", filename);
      };
      proto.mask = function mask(filename) {
        return this.out("-mask", filename);
      };
      proto.matte = function matte() {
        return this.out("-matte");
      };
      proto.matteColor = function matteColor(color) {
        return this.out("-mattecolor", color);
      };
      proto.maximumError = function maximumError(limit) {
        return this.out("-maximum-error", limit);
      };
      proto.mode = function mode(value) {
        return this.out("-mode", value);
      };
      proto.monitor = function monitor() {
        return this.out("-monitor");
      };
      proto.mosaic = function mosaic() {
        return this.out("-mosaic");
      };
      proto.motionBlur = function motionBlur(radius, sigma, angle) {
        var arg = radius;
        if (typeof sigma != "undefined") arg += "x" + sigma;
        if (typeof angle != "undefined") arg += "+" + angle;
        return this.out("-motion-blur", arg);
      };
      proto.name = function name() {
        return this.out("-name");
      };
      proto.noop = function noop() {
        return this.out("-noop");
      };
      proto.normalize = function normalize() {
        return this.out("-normalize");
      };
      proto.opaque = function opaque(color) {
        return this.out("-opaque", color);
      };
      proto.operator = function operator(channel, operator, rvalue, percent) {
        return this.out("-operator", channel, operator, rvalue + (percent ? "%" : ""));
      };
      proto.orderedDither = function orderedDither(channeltype, NxN) {
        return this.out("-ordered-dither", channeltype, NxN);
      };
      proto.outputDirectory = function outputDirectory(directory) {
        return this.out("-output-directory", directory);
      };
      proto.page = function page(width, height, arg) {
        return this.out("-page", width + "x" + height + (arg || ""));
      };
      proto.pause = function pause(seconds) {
        return this.out("-pause", seconds);
      };
      proto.pen = function pen(color) {
        return this.out("-pen", color);
      };
      proto.ping = function ping() {
        return this.out("-ping");
      };
      proto.pointSize = function pointSize(value) {
        return this.out("-pointsize", value);
      };
      proto.preview = function preview(type) {
        return this.out("-preview", type);
      };
      proto.process = function process2(command) {
        return this.out("-process", command);
      };
      proto.profile = function profile(filename) {
        return this.out("-profile", filename);
      };
      proto.progress = function progress() {
        return this.out("+progress");
      };
      proto.randomThreshold = function randomThreshold(channeltype, LOWxHIGH) {
        return this.out("-random-threshold", channeltype, LOWxHIGH);
      };
      proto.recolor = function recolor(matrix) {
        return this.out("-recolor", matrix);
      };
      proto.redPrimary = function redPrimary(x, y) {
        return this.out("-red-primary", x, y);
      };
      proto.remote = function remote() {
        return this.out("-remote");
      };
      proto.render = function render() {
        return this.out("-render");
      };
      proto.repage = function repage(width, height, xoff, yoff, arg) {
        if (arguments[0] === "+") return this.out("+repage");
        return this.out("-repage", width + "x" + height + "+" + xoff + "+" + yoff + (arg || ""));
      };
      proto.sample = function sample(geometry) {
        return this.out("-sample", geometry);
      };
      proto.samplingFactor = function samplingFactor(horizontalFactor, verticalFactor) {
        return this.out("-sampling-factor", horizontalFactor + "x" + verticalFactor);
      };
      proto.scene = function scene(value) {
        return this.out("-scene", value);
      };
      proto.scenes = function scenes(start, end) {
        return this.out("-scenes", start + "-" + end);
      };
      proto.screen = function screen() {
        return this.out("-screen");
      };
      proto.set = function set(attribute, value) {
        return this.out("-set", attribute, value);
      };
      proto.segment = function segment(clusterThreshold, smoothingThreshold) {
        return this.out("-segment", clusterThreshold + "x" + smoothingThreshold);
      };
      proto.shade = function shade(azimuth, elevation) {
        return this.out("-shade", azimuth + "x" + elevation);
      };
      proto.shadow = function shadow(radius, sigma) {
        return this.out("-shadow", argsToArray(radius, sigma).join("x"));
      };
      proto.sharedMemory = function sharedMemory() {
        return this.out("-shared-memory");
      };
      proto.shave = function shave(width, height, percent) {
        return this.out("-shave", width + "x" + height + (percent ? "%" : ""));
      };
      proto.shear = function shear(xDegrees, yDegreees) {
        return this.out("-shear", xDegrees + "x" + yDegreees);
      };
      proto.silent = function silent(color) {
        return this.out("-silent");
      };
      proto.rawSize = function rawSize(width, height, offset) {
        var off = "undefined" != typeof offset ? "+" + offset : "";
        return this.out("-size", width + "x" + height + off);
      };
      proto.snaps = function snaps(value) {
        return this.out("-snaps", value);
      };
      proto.stegano = function stegano(offset) {
        return this.out("-stegano", offset);
      };
      proto.stereo = function stereo() {
        return this.out("-stereo");
      };
      proto.textFont = function textFont(name) {
        return this.out("-text-font", name);
      };
      proto.texture = function texture(filename) {
        return this.out("-texture", filename);
      };
      proto.threshold = function threshold(value, percent) {
        return this.out("-threshold", value + (percent ? "%" : ""));
      };
      proto.thumbnail = function thumbnail(w, h, options) {
        options = options || "";
        var geometry, wIsValid = Boolean(w || w === 0), hIsValid = Boolean(h || h === 0);
        if (wIsValid && hIsValid) {
          geometry = w + "x" + h + options;
        } else if (wIsValid) {
          geometry = this._options.imageMagick ? w + options : w + "x" + options;
        } else if (hIsValid) {
          geometry = "x" + h + options;
        } else {
          return this;
        }
        return this.out("-thumbnail", geometry);
      };
      proto.tile = function tile(filename) {
        return this.out("-tile", filename);
      };
      proto.title = function title(string) {
        return this.out("-title", string);
      };
      proto.transform = function transform(color) {
        return this.out("-transform", color);
      };
      proto.transparent = function transparent(color) {
        return this.out("-transparent", color);
      };
      proto.treeDepth = function treeDepth(value) {
        return this.out("-treedepth", value);
      };
      proto.update = function update(seconds) {
        return this.out("-update", seconds);
      };
      proto.units = function units(type) {
        return this.out("-units", type);
      };
      proto.unsharp = function unsharp(radius, sigma, amount, threshold) {
        var arg = radius;
        if (typeof sigma != "undefined") arg += "x" + sigma;
        if (typeof amount != "undefined") arg += "+" + amount;
        if (typeof threshold != "undefined") arg += "+" + threshold;
        return this.out("-unsharp", arg);
      };
      proto.usePixmap = function usePixmap() {
        return this.out("-use-pixmap");
      };
      proto.view = function view(string) {
        return this.out("-view", string);
      };
      proto.virtualPixel = function virtualPixel(method) {
        return this.out("-virtual-pixel", method);
      };
      proto.visual = function visual(type) {
        return this.out("-visual", type);
      };
      proto.watermark = function watermark(brightness, saturation) {
        return this.out("-watermark", brightness + "x" + saturation);
      };
      proto.wave = function wave(amplitude, wavelength) {
        return this.out("-wave", amplitude + "x" + wavelength);
      };
      proto.whitePoint = function whitePoint(x, y) {
        return this.out("-white-point", x + "x" + y);
      };
      proto.whiteThreshold = function whiteThreshold(red, green, blue, opacity) {
        return this.out("-white-threshold", argsToArray(red, green, blue, opacity).join(","));
      };
      proto.window = function window2(id) {
        return this.out("-window", id);
      };
      proto.windowGroup = function windowGroup() {
        return this.out("-window-group");
      };
      proto.strip = function strip() {
        if (this._options.imageMagick) return this.out("-strip");
        return this.noProfile().out("+comment");
      };
      proto.interlace = function interlace(type) {
        return this.out("-interlace", type || "None");
      };
      proto.setFormat = function setFormat(format) {
        if (format) this._outputFormat = format;
        return this;
      };
      proto.resize = function resize(w, h, options) {
        options = options || "";
        var geometry, wIsValid = Boolean(w || w === 0), hIsValid = Boolean(h || h === 0);
        if (wIsValid && hIsValid) {
          geometry = w + "x" + h + options;
        } else if (wIsValid) {
          geometry = this._options.imageMagick ? w + options : w + "x" + options;
        } else if (hIsValid) {
          geometry = "x" + h + options;
        } else {
          return this;
        }
        return this.out("-resize", geometry);
      };
      proto.resizeExact = function resize(w, h) {
        var options = "!";
        return proto.resize.apply(this, [w, h, options]);
      };
      proto.scale = function scale(w, h, options) {
        options = options || "";
        var geometry;
        if (w && h) {
          geometry = w + "x" + h + options;
        } else if (w && !h) {
          geometry = this._options.imageMagick ? w + options : w + "x" + options;
        } else if (!w && h) {
          geometry = "x" + h + options;
        }
        return this.out("-scale", geometry);
      };
      proto.filter = function filter(val) {
        return this.out("-filter", val);
      };
      proto.density = function density(w, h) {
        if (w && !h && this._options.imageMagick) {
          return this.in("-density", w);
        }
        return this.in("-density", w + "x" + h);
      };
      proto.noProfile = function noProfile() {
        this.out("+profile", '"*"');
        return this;
      };
      proto.resample = function resample(w, h) {
        return this.out("-resample", w + "x" + h);
      };
      proto.rotate = function rotate(color, deg) {
        return this.out("-background", color, "-rotate", String(deg || 0));
      };
      proto.flip = function flip() {
        return this.out("-flip");
      };
      proto.flop = function flop() {
        return this.out("-flop");
      };
      proto.crop = function crop(w, h, x, y, percent) {
        if (this.inputIs("jpg")) {
          var index = this._in.indexOf("-size");
          if (~index) {
            this._in.splice(index, 2);
          }
        }
        return this.out("-crop", w + "x" + h + "+" + (x || 0) + "+" + (y || 0) + (percent ? "%" : ""));
      };
      proto.magnify = function magnify(factor) {
        return this.in("-magnify");
      };
      proto.minify = function minify() {
        return this.in("-minify");
      };
      proto.quality = function quality(val) {
        return this.in("-quality", val || 75);
      };
      proto.blur = function blur(radius, sigma) {
        return this.out("-blur", radius + (sigma ? "x" + sigma : ""));
      };
      proto.charcoal = function charcoal(factor) {
        return this.out("-charcoal", factor || 2);
      };
      proto.modulate = function modulate(b, s, h) {
        return this.out("-modulate", [b, s, h].join(","));
      };
      proto.antialias = function antialias(disable) {
        return false === disable ? this.out("+antialias") : this;
      };
      proto.bitdepth = function bitdepth(val) {
        return this.out("-depth", val);
      };
      proto.colors = function colors(val) {
        return this.out("-colors", val || 128);
      };
      proto.colorspace = function colorspace(val) {
        return this.out("-colorspace", val);
      };
      proto.comment = comment("-comment");
      proto.contrast = function contrast(mult) {
        var arg = (parseInt(mult, 10) || 0) > 0 ? "+contrast" : "-contrast";
        mult = Math.abs(mult) || 1;
        while (mult--) {
          this.out(arg);
        }
        return this;
      };
      proto.cycle = function cycle(amount) {
        return this.out("-cycle", amount || 2);
      };
      proto.despeckle = function despeckle() {
        return this.out("-despeckle");
      };
      proto.dither = function dither(on) {
        var sign = false === on ? "+" : "-";
        return this.out(sign + "dither");
      };
      proto.monochrome = function monochrome() {
        return this.out("-monochrome");
      };
      proto.edge = function edge(radius) {
        return this.out("-edge", radius || 1);
      };
      proto.emboss = function emboss(radius) {
        return this.out("-emboss", radius || 1);
      };
      proto.enhance = function enhance() {
        return this.out("-enhance");
      };
      proto.equalize = function equalize() {
        return this.out("-equalize");
      };
      proto.gamma = function gamma(r, g, b) {
        return this.out("-gamma", [r, g, b].join());
      };
      proto.implode = function implode(factor) {
        return this.out("-implode", factor || 1);
      };
      proto.label = comment("-label");
      var limits = ["disk", "file", "map", "memory", "pixels", "threads"];
      proto.limit = function limit(type, val) {
        type = type.toLowerCase();
        if (!~limits.indexOf(type)) {
          return this;
        }
        return this.out("-limit", type, val);
      };
      proto.median = function median(radius) {
        return this.out("-median", radius || 1);
      };
      proto.negative = function negative(grayscale) {
        var sign = grayscale ? "+" : "-";
        return this.out(sign + "negate");
      };
      var noises = [
        "uniform",
        "gaussian",
        "multiplicative",
        "impulse",
        "laplacian",
        "poisson"
      ];
      proto.noise = function noise(radius) {
        radius = String(radius).toLowerCase();
        var sign = ~noises.indexOf(radius) ? "+" : "-";
        return this.out(sign + "noise", radius);
      };
      proto.paint = function paint(radius) {
        return this.out("-paint", radius);
      };
      proto.raise = function raise(w, h) {
        return this.out("-raise", (w || 0) + "x" + (h || 0));
      };
      proto.lower = function lower(w, h) {
        return this.out("+raise", (w || 0) + "x" + (h || 0));
      };
      proto.region = function region(w, h, x, y) {
        w = w || 0;
        h = h || 0;
        x = x || 0;
        y = y || 0;
        return this.out("-region", w + "x" + h + "+" + x + "+" + y);
      };
      proto.roll = function roll(x, y) {
        x = ((x = parseInt(x, 10) || 0) >= 0 ? "+" : "") + x;
        y = ((y = parseInt(y, 10) || 0) >= 0 ? "+" : "") + y;
        return this.out("-roll", x + y);
      };
      proto.sharpen = function sharpen(radius, sigma) {
        sigma = sigma ? "x" + sigma : "";
        return this.out("-sharpen", radius + sigma);
      };
      proto.solarize = function solarize(factor) {
        return this.out("-solarize", (factor || 1) + "%");
      };
      proto.spread = function spread(amount) {
        return this.out("-spread", amount || 5);
      };
      proto.swirl = function swirl(degrees) {
        return this.out("-swirl", degrees || 180);
      };
      proto.type = function type(type) {
        return this.in("-type", type);
      };
      proto.trim = function trim() {
        return this.out("-trim");
      };
      proto.extent = function extent(w, h, options) {
        options = options || "";
        var geometry;
        if (w && h) {
          geometry = w + "x" + h + options;
        } else if (w && !h) {
          geometry = this._options.imageMagick ? w + options : w + "x" + options;
        } else if (!w && h) {
          geometry = "x" + h + options;
        }
        return this.out("-extent", geometry);
      };
      proto.gravity = function gravity(type) {
        if (!type || !~gravity.types.indexOf(type)) {
          type = "NorthWest";
        }
        return this.out("-gravity", type);
      };
      proto.gravity.types = [
        "NorthWest",
        "North",
        "NorthEast",
        "West",
        "Center",
        "East",
        "SouthWest",
        "South",
        "SouthEast"
      ];
      proto.flatten = function flatten() {
        return this.out("-flatten");
      };
      proto.background = function background(color) {
        return this.in("-background", color);
      };
    };
    function comment(arg) {
      return function(format) {
        format = String(format);
        format = "@" == format.charAt(0) ? format.substring(1) : format;
        return this.out(arg, '"' + format + '"');
      };
    }
  }
});

// node_modules/gm/lib/drawing.js
var require_drawing = __commonJS({
  "node_modules/gm/lib/drawing.js"(exports2, module2) {
    var escape = require_utils2().escape;
    module2.exports = function(proto) {
      proto.fill = function fill(color) {
        return this.out("-fill", color || "none");
      };
      proto.stroke = function stroke(color, width) {
        if (width) {
          this.strokeWidth(width);
        }
        return this.out("-stroke", color || "none");
      };
      proto.strokeWidth = function strokeWidth(width) {
        return this.out("-strokewidth", width);
      };
      proto.font = function font(font, size) {
        if (size) {
          this.fontSize(size);
        }
        return this.out("-font", font);
      };
      proto.fontSize = function fontSize(size) {
        return this.out("-pointsize", size);
      };
      proto.draw = function draw(args) {
        return this.out("-draw", [].slice.call(arguments).join(" "));
      };
      proto.drawPoint = function drawPoint(x, y) {
        return this.draw("point", x + "," + y);
      };
      proto.drawLine = function drawLine(x0, y0, x1, y1) {
        return this.draw("line", x0 + "," + y0, x1 + "," + y1);
      };
      proto.drawRectangle = function drawRectangle(x0, y0, x1, y1, wc, hc) {
        var shape = "rectangle", lastarg;
        if ("undefined" !== typeof wc) {
          shape = "roundRectangle";
          if ("undefined" === typeof hc) {
            hc = wc;
          }
          lastarg = wc + "," + hc;
        }
        return this.draw(shape, x0 + "," + y0, x1 + "," + y1, lastarg);
      };
      proto.drawArc = function drawArc(x0, y0, x1, y1, a0, a1) {
        return this.draw("arc", x0 + "," + y0, x1 + "," + y1, a0 + "," + a1);
      };
      proto.drawEllipse = function drawEllipse(x0, y0, rx, ry, a0, a1) {
        if (a0 == void 0) a0 = 0;
        if (a1 == void 0) a1 = 360;
        return this.draw("ellipse", x0 + "," + y0, rx + "," + ry, a0 + "," + a1);
      };
      proto.drawCircle = function drawCircle(x0, y0, x1, y1) {
        return this.draw("circle", x0 + "," + y0, x1 + "," + y1);
      };
      proto.drawPolyline = function drawPolyline() {
        return this.draw("polyline", formatPoints(arguments));
      };
      proto.drawPolygon = function drawPolygon() {
        return this.draw("polygon", formatPoints(arguments));
      };
      proto.drawBezier = function drawBezier() {
        return this.draw("bezier", formatPoints(arguments));
      };
      proto._gravities = [
        "northwest",
        "north",
        "northeast",
        "west",
        "center",
        "east",
        "southwest",
        "south",
        "southeast"
      ];
      proto.drawText = function drawText(x0, y0, text, gravity) {
        var gravity = String(gravity || "").toLowerCase(), arg = ["text " + x0 + "," + y0 + " " + escape(text)];
        if (~this._gravities.indexOf(gravity)) {
          arg.unshift("gravity", gravity);
        }
        return this.draw.apply(this, arg);
      };
      proto._drawProps = ["color", "matte"];
      proto.setDraw = function setDraw(prop, x, y, method) {
        prop = String(prop || "").toLowerCase();
        if (!~this._drawProps.indexOf(prop)) {
          return this;
        }
        return this.draw(prop, x + "," + y, method);
      };
    };
    function formatPoints(points) {
      var len = points.length, result = [], i = 0;
      for (; i < len; ++i) {
        result.push(points[i].join(","));
      }
      return result;
    }
  }
});

// node_modules/gm/lib/convenience/thumb.js
var require_thumb = __commonJS({
  "node_modules/gm/lib/convenience/thumb.js"(exports2, module2) {
    module2.exports = function(proto) {
      proto.thumb = function thumb(w, h, name, quality, align, progressive, callback, opts) {
        var self = this, args = Array.prototype.slice.call(arguments);
        opts = args.pop();
        if (typeof opts === "function") {
          callback = opts;
          opts = "";
        } else {
          callback = args.pop();
        }
        w = args.shift();
        h = args.shift();
        name = args.shift();
        quality = args.shift() || 63;
        align = args.shift() || "topleft";
        var interlace = args.shift() ? "Line" : "None";
        self.size(function(err, size) {
          if (err) {
            return callback.apply(self, arguments);
          }
          w = parseInt(w, 10);
          h = parseInt(h, 10);
          var w1, h1;
          var xoffset = 0;
          var yoffset = 0;
          if (size.width < size.height) {
            w1 = w;
            h1 = Math.floor(size.height * (w / size.width));
            if (h1 < h) {
              w1 = Math.floor(w1 * ((h - h1) / h + 1));
              h1 = h;
            }
          } else if (size.width > size.height) {
            h1 = h;
            w1 = Math.floor(size.width * (h / size.height));
            if (w1 < w) {
              h1 = Math.floor(h1 * ((w - w1) / w + 1));
              w1 = w;
            }
          } else if (size.width == size.height) {
            var bigger = w > h ? w : h;
            w1 = bigger;
            h1 = bigger;
          }
          if (align == "center") {
            if (w < w1) {
              xoffset = (w1 - w) / 2;
            }
            if (h < h1) {
              yoffset = (h1 - h) / 2;
            }
          }
          self.quality(quality).in("-size", w1 + "x" + h1).scale(w1, h1, opts).crop(w, h, xoffset, yoffset).interlace(interlace).noProfile().write(name, function() {
            callback.apply(self, arguments);
          });
        });
        return self;
      };
      proto.thumbExact = function() {
        var self = this, args = Array.prototype.slice.call(arguments);
        args.push("!");
        self.thumb.apply(self, args);
      };
    };
  }
});

// node_modules/array-parallel/index.js
var require_array_parallel = __commonJS({
  "node_modules/array-parallel/index.js"(exports2, module2) {
    module2.exports = function parallel(fns, context, callback) {
      if (!callback) {
        if (typeof context === "function") {
          callback = context;
          context = null;
        } else {
          callback = noop;
        }
      }
      var pending = fns && fns.length;
      if (!pending) return callback(null, []);
      var finished = false;
      var results = new Array(pending);
      fns.forEach(context ? function(fn, i) {
        fn.call(context, maybeDone(i));
      } : function(fn, i) {
        fn(maybeDone(i));
      });
      function maybeDone(i) {
        return function(err, result) {
          if (finished) return;
          if (err) {
            callback(err, results);
            finished = true;
            return;
          }
          results[i] = result;
          if (!--pending) callback(null, results);
        };
      }
    };
    function noop() {
    }
  }
});

// node_modules/gm/lib/convenience/morph.js
var require_morph = __commonJS({
  "node_modules/gm/lib/convenience/morph.js"(exports2, module2) {
    var fs3 = require("fs");
    var parallel = require_array_parallel();
    module2.exports = function(proto) {
      function noop() {
      }
      proto.morph = function morph(other, outname, callback) {
        if (!outname) {
          throw new Error("an output filename is required");
        }
        callback = (callback || noop).bind(this);
        var self = this;
        if (Array.isArray(other)) {
          other.forEach(function(img) {
            self.out(img);
          });
          self.out("-morph", other.length);
        } else {
          self.out(other, "-morph", 1);
        }
        self.write(outname, function(err, stdout, stderr, cmd) {
          if (err) return callback(err, stdout, stderr, cmd);
          fs3.exists(outname, function(exists) {
            if (exists) return callback(null, stdout, stderr, cmd);
            parallel([
              fs3.unlink.bind(fs3, outname + ".0"),
              fs3.unlink.bind(fs3, outname + ".2"),
              fs3.rename.bind(fs3, outname + ".1", outname)
            ], function(err2) {
              callback(err2, stdout, stderr, cmd);
            });
          });
        });
        return self;
      };
    };
  }
});

// node_modules/gm/lib/convenience/sepia.js
var require_sepia = __commonJS({
  "node_modules/gm/lib/convenience/sepia.js"(exports2, module2) {
    module2.exports = function(proto) {
      proto.sepia = function sepia() {
        return this.modulate(115, 0, 100).colorize(7, 21, 50);
      };
    };
  }
});

// node_modules/gm/lib/convenience/autoOrient.js
var require_autoOrient = __commonJS({
  "node_modules/gm/lib/convenience/autoOrient.js"(exports2, module2) {
    module2.exports = function(proto) {
      var exifTransforms = {
        topleft: "",
        topright: ["-flop"],
        bottomright: ["-rotate", 180],
        bottomleft: ["-flip"],
        lefttop: ["-flip", "-rotate", 90],
        righttop: ["-rotate", 90],
        rightbottom: ["-flop", "-rotate", 90],
        leftbottom: ["-rotate", 270]
      };
      proto.autoOrient = function autoOrient() {
        if (this._options.nativeAutoOrient || this._options.imageMagick) {
          this.out("-auto-orient");
          return this;
        }
        this.preprocessor(function(callback) {
          this.orientation({ bufferStream: true }, function(err, orientation) {
            if (err) return callback(err);
            var transforms = exifTransforms[orientation.toLowerCase()];
            if (transforms) {
              var index = this._out.indexOf(transforms[0]);
              if (~index) {
                this._out.splice(index, transforms.length);
              }
              this._out.unshift.apply(this._out, transforms.concat("-page", "+0+0"));
            }
            callback();
          });
        });
        return this;
      };
    };
  }
});

// node_modules/gm/lib/convenience.js
var require_convenience = __commonJS({
  "node_modules/gm/lib/convenience.js"(exports2, module2) {
    module2.exports = function(proto) {
      require_thumb()(proto);
      require_morph()(proto);
      require_sepia()(proto);
      require_autoOrient()(proto);
    };
  }
});

// node_modules/pseudomap/pseudomap.js
var require_pseudomap = __commonJS({
  "node_modules/pseudomap/pseudomap.js"(exports2, module2) {
    var hasOwnProperty = Object.prototype.hasOwnProperty;
    module2.exports = PseudoMap;
    function PseudoMap(set2) {
      if (!(this instanceof PseudoMap))
        throw new TypeError("Constructor PseudoMap requires 'new'");
      this.clear();
      if (set2) {
        if (set2 instanceof PseudoMap || typeof Map === "function" && set2 instanceof Map)
          set2.forEach(function(value, key) {
            this.set(key, value);
          }, this);
        else if (Array.isArray(set2))
          set2.forEach(function(kv) {
            this.set(kv[0], kv[1]);
          }, this);
        else
          throw new TypeError("invalid argument");
      }
    }
    PseudoMap.prototype.forEach = function(fn, thisp) {
      thisp = thisp || this;
      Object.keys(this._data).forEach(function(k) {
        if (k !== "size")
          fn.call(thisp, this._data[k].value, this._data[k].key);
      }, this);
    };
    PseudoMap.prototype.has = function(k) {
      return !!find(this._data, k);
    };
    PseudoMap.prototype.get = function(k) {
      var res = find(this._data, k);
      return res && res.value;
    };
    PseudoMap.prototype.set = function(k, v) {
      set(this._data, k, v);
    };
    PseudoMap.prototype.delete = function(k) {
      var res = find(this._data, k);
      if (res) {
        delete this._data[res._index];
        this._data.size--;
      }
    };
    PseudoMap.prototype.clear = function() {
      var data = /* @__PURE__ */ Object.create(null);
      data.size = 0;
      Object.defineProperty(this, "_data", {
        value: data,
        enumerable: false,
        configurable: true,
        writable: false
      });
    };
    Object.defineProperty(PseudoMap.prototype, "size", {
      get: function() {
        return this._data.size;
      },
      set: function(n) {
      },
      enumerable: true,
      configurable: true
    });
    PseudoMap.prototype.values = PseudoMap.prototype.keys = PseudoMap.prototype.entries = function() {
      throw new Error("iterators are not implemented in this version");
    };
    function same(a, b) {
      return a === b || a !== a && b !== b;
    }
    function Entry(k, v, i) {
      this.key = k;
      this.value = v;
      this._index = i;
    }
    function find(data, k) {
      for (var i = 0, s = "_" + k, key = s; hasOwnProperty.call(data, key); key = s + i++) {
        if (same(data[key].key, k))
          return data[key];
      }
    }
    function set(data, k, v) {
      for (var i = 0, s = "_" + k, key = s; hasOwnProperty.call(data, key); key = s + i++) {
        if (same(data[key].key, k)) {
          data[key].value = v;
          return;
        }
      }
      data.size++;
      data[key] = new Entry(k, v, key);
    }
  }
});

// node_modules/pseudomap/map.js
var require_map = __commonJS({
  "node_modules/pseudomap/map.js"(exports2, module2) {
    if (process.env.npm_package_name === "pseudomap" && process.env.npm_lifecycle_script === "test")
      process.env.TEST_PSEUDOMAP = "true";
    if (typeof Map === "function" && !process.env.TEST_PSEUDOMAP) {
      module2.exports = Map;
    } else {
      module2.exports = require_pseudomap();
    }
  }
});

// node_modules/yallist/yallist.js
var require_yallist = __commonJS({
  "node_modules/yallist/yallist.js"(exports2, module2) {
    module2.exports = Yallist;
    Yallist.Node = Node;
    Yallist.create = Yallist;
    function Yallist(list) {
      var self = this;
      if (!(self instanceof Yallist)) {
        self = new Yallist();
      }
      self.tail = null;
      self.head = null;
      self.length = 0;
      if (list && typeof list.forEach === "function") {
        list.forEach(function(item) {
          self.push(item);
        });
      } else if (arguments.length > 0) {
        for (var i = 0, l = arguments.length; i < l; i++) {
          self.push(arguments[i]);
        }
      }
      return self;
    }
    Yallist.prototype.removeNode = function(node) {
      if (node.list !== this) {
        throw new Error("removing node which does not belong to this list");
      }
      var next = node.next;
      var prev = node.prev;
      if (next) {
        next.prev = prev;
      }
      if (prev) {
        prev.next = next;
      }
      if (node === this.head) {
        this.head = next;
      }
      if (node === this.tail) {
        this.tail = prev;
      }
      node.list.length--;
      node.next = null;
      node.prev = null;
      node.list = null;
    };
    Yallist.prototype.unshiftNode = function(node) {
      if (node === this.head) {
        return;
      }
      if (node.list) {
        node.list.removeNode(node);
      }
      var head = this.head;
      node.list = this;
      node.next = head;
      if (head) {
        head.prev = node;
      }
      this.head = node;
      if (!this.tail) {
        this.tail = node;
      }
      this.length++;
    };
    Yallist.prototype.pushNode = function(node) {
      if (node === this.tail) {
        return;
      }
      if (node.list) {
        node.list.removeNode(node);
      }
      var tail = this.tail;
      node.list = this;
      node.prev = tail;
      if (tail) {
        tail.next = node;
      }
      this.tail = node;
      if (!this.head) {
        this.head = node;
      }
      this.length++;
    };
    Yallist.prototype.push = function() {
      for (var i = 0, l = arguments.length; i < l; i++) {
        push(this, arguments[i]);
      }
      return this.length;
    };
    Yallist.prototype.unshift = function() {
      for (var i = 0, l = arguments.length; i < l; i++) {
        unshift(this, arguments[i]);
      }
      return this.length;
    };
    Yallist.prototype.pop = function() {
      if (!this.tail) {
        return void 0;
      }
      var res = this.tail.value;
      this.tail = this.tail.prev;
      if (this.tail) {
        this.tail.next = null;
      } else {
        this.head = null;
      }
      this.length--;
      return res;
    };
    Yallist.prototype.shift = function() {
      if (!this.head) {
        return void 0;
      }
      var res = this.head.value;
      this.head = this.head.next;
      if (this.head) {
        this.head.prev = null;
      } else {
        this.tail = null;
      }
      this.length--;
      return res;
    };
    Yallist.prototype.forEach = function(fn, thisp) {
      thisp = thisp || this;
      for (var walker = this.head, i = 0; walker !== null; i++) {
        fn.call(thisp, walker.value, i, this);
        walker = walker.next;
      }
    };
    Yallist.prototype.forEachReverse = function(fn, thisp) {
      thisp = thisp || this;
      for (var walker = this.tail, i = this.length - 1; walker !== null; i--) {
        fn.call(thisp, walker.value, i, this);
        walker = walker.prev;
      }
    };
    Yallist.prototype.get = function(n) {
      for (var i = 0, walker = this.head; walker !== null && i < n; i++) {
        walker = walker.next;
      }
      if (i === n && walker !== null) {
        return walker.value;
      }
    };
    Yallist.prototype.getReverse = function(n) {
      for (var i = 0, walker = this.tail; walker !== null && i < n; i++) {
        walker = walker.prev;
      }
      if (i === n && walker !== null) {
        return walker.value;
      }
    };
    Yallist.prototype.map = function(fn, thisp) {
      thisp = thisp || this;
      var res = new Yallist();
      for (var walker = this.head; walker !== null; ) {
        res.push(fn.call(thisp, walker.value, this));
        walker = walker.next;
      }
      return res;
    };
    Yallist.prototype.mapReverse = function(fn, thisp) {
      thisp = thisp || this;
      var res = new Yallist();
      for (var walker = this.tail; walker !== null; ) {
        res.push(fn.call(thisp, walker.value, this));
        walker = walker.prev;
      }
      return res;
    };
    Yallist.prototype.reduce = function(fn, initial) {
      var acc;
      var walker = this.head;
      if (arguments.length > 1) {
        acc = initial;
      } else if (this.head) {
        walker = this.head.next;
        acc = this.head.value;
      } else {
        throw new TypeError("Reduce of empty list with no initial value");
      }
      for (var i = 0; walker !== null; i++) {
        acc = fn(acc, walker.value, i);
        walker = walker.next;
      }
      return acc;
    };
    Yallist.prototype.reduceReverse = function(fn, initial) {
      var acc;
      var walker = this.tail;
      if (arguments.length > 1) {
        acc = initial;
      } else if (this.tail) {
        walker = this.tail.prev;
        acc = this.tail.value;
      } else {
        throw new TypeError("Reduce of empty list with no initial value");
      }
      for (var i = this.length - 1; walker !== null; i--) {
        acc = fn(acc, walker.value, i);
        walker = walker.prev;
      }
      return acc;
    };
    Yallist.prototype.toArray = function() {
      var arr = new Array(this.length);
      for (var i = 0, walker = this.head; walker !== null; i++) {
        arr[i] = walker.value;
        walker = walker.next;
      }
      return arr;
    };
    Yallist.prototype.toArrayReverse = function() {
      var arr = new Array(this.length);
      for (var i = 0, walker = this.tail; walker !== null; i++) {
        arr[i] = walker.value;
        walker = walker.prev;
      }
      return arr;
    };
    Yallist.prototype.slice = function(from, to) {
      to = to || this.length;
      if (to < 0) {
        to += this.length;
      }
      from = from || 0;
      if (from < 0) {
        from += this.length;
      }
      var ret = new Yallist();
      if (to < from || to < 0) {
        return ret;
      }
      if (from < 0) {
        from = 0;
      }
      if (to > this.length) {
        to = this.length;
      }
      for (var i = 0, walker = this.head; walker !== null && i < from; i++) {
        walker = walker.next;
      }
      for (; walker !== null && i < to; i++, walker = walker.next) {
        ret.push(walker.value);
      }
      return ret;
    };
    Yallist.prototype.sliceReverse = function(from, to) {
      to = to || this.length;
      if (to < 0) {
        to += this.length;
      }
      from = from || 0;
      if (from < 0) {
        from += this.length;
      }
      var ret = new Yallist();
      if (to < from || to < 0) {
        return ret;
      }
      if (from < 0) {
        from = 0;
      }
      if (to > this.length) {
        to = this.length;
      }
      for (var i = this.length, walker = this.tail; walker !== null && i > to; i--) {
        walker = walker.prev;
      }
      for (; walker !== null && i > from; i--, walker = walker.prev) {
        ret.push(walker.value);
      }
      return ret;
    };
    Yallist.prototype.reverse = function() {
      var head = this.head;
      var tail = this.tail;
      for (var walker = head; walker !== null; walker = walker.prev) {
        var p = walker.prev;
        walker.prev = walker.next;
        walker.next = p;
      }
      this.head = tail;
      this.tail = head;
      return this;
    };
    function push(self, item) {
      self.tail = new Node(item, self.tail, null, self);
      if (!self.head) {
        self.head = self.tail;
      }
      self.length++;
    }
    function unshift(self, item) {
      self.head = new Node(item, null, self.head, self);
      if (!self.tail) {
        self.tail = self.head;
      }
      self.length++;
    }
    function Node(value, prev, next, list) {
      if (!(this instanceof Node)) {
        return new Node(value, prev, next, list);
      }
      this.list = list;
      this.value = value;
      if (prev) {
        prev.next = this;
        this.prev = prev;
      } else {
        this.prev = null;
      }
      if (next) {
        next.prev = this;
        this.next = next;
      } else {
        this.next = null;
      }
    }
  }
});

// node_modules/lru-cache/index.js
var require_lru_cache = __commonJS({
  "node_modules/lru-cache/index.js"(exports2, module2) {
    "use strict";
    module2.exports = LRUCache;
    var Map2 = require_map();
    var util = require("util");
    var Yallist = require_yallist();
    var hasSymbol = typeof Symbol === "function" && process.env._nodeLRUCacheForceNoSymbol !== "1";
    var makeSymbol;
    if (hasSymbol) {
      makeSymbol = function(key) {
        return Symbol(key);
      };
    } else {
      makeSymbol = function(key) {
        return "_" + key;
      };
    }
    var MAX = makeSymbol("max");
    var LENGTH = makeSymbol("length");
    var LENGTH_CALCULATOR = makeSymbol("lengthCalculator");
    var ALLOW_STALE = makeSymbol("allowStale");
    var MAX_AGE = makeSymbol("maxAge");
    var DISPOSE = makeSymbol("dispose");
    var NO_DISPOSE_ON_SET = makeSymbol("noDisposeOnSet");
    var LRU_LIST = makeSymbol("lruList");
    var CACHE = makeSymbol("cache");
    function naiveLength() {
      return 1;
    }
    function LRUCache(options) {
      if (!(this instanceof LRUCache)) {
        return new LRUCache(options);
      }
      if (typeof options === "number") {
        options = { max: options };
      }
      if (!options) {
        options = {};
      }
      var max = this[MAX] = options.max;
      if (!max || !(typeof max === "number") || max <= 0) {
        this[MAX] = Infinity;
      }
      var lc = options.length || naiveLength;
      if (typeof lc !== "function") {
        lc = naiveLength;
      }
      this[LENGTH_CALCULATOR] = lc;
      this[ALLOW_STALE] = options.stale || false;
      this[MAX_AGE] = options.maxAge || 0;
      this[DISPOSE] = options.dispose;
      this[NO_DISPOSE_ON_SET] = options.noDisposeOnSet || false;
      this.reset();
    }
    Object.defineProperty(LRUCache.prototype, "max", {
      set: function(mL) {
        if (!mL || !(typeof mL === "number") || mL <= 0) {
          mL = Infinity;
        }
        this[MAX] = mL;
        trim(this);
      },
      get: function() {
        return this[MAX];
      },
      enumerable: true
    });
    Object.defineProperty(LRUCache.prototype, "allowStale", {
      set: function(allowStale) {
        this[ALLOW_STALE] = !!allowStale;
      },
      get: function() {
        return this[ALLOW_STALE];
      },
      enumerable: true
    });
    Object.defineProperty(LRUCache.prototype, "maxAge", {
      set: function(mA) {
        if (!mA || !(typeof mA === "number") || mA < 0) {
          mA = 0;
        }
        this[MAX_AGE] = mA;
        trim(this);
      },
      get: function() {
        return this[MAX_AGE];
      },
      enumerable: true
    });
    Object.defineProperty(LRUCache.prototype, "lengthCalculator", {
      set: function(lC) {
        if (typeof lC !== "function") {
          lC = naiveLength;
        }
        if (lC !== this[LENGTH_CALCULATOR]) {
          this[LENGTH_CALCULATOR] = lC;
          this[LENGTH] = 0;
          this[LRU_LIST].forEach(function(hit) {
            hit.length = this[LENGTH_CALCULATOR](hit.value, hit.key);
            this[LENGTH] += hit.length;
          }, this);
        }
        trim(this);
      },
      get: function() {
        return this[LENGTH_CALCULATOR];
      },
      enumerable: true
    });
    Object.defineProperty(LRUCache.prototype, "length", {
      get: function() {
        return this[LENGTH];
      },
      enumerable: true
    });
    Object.defineProperty(LRUCache.prototype, "itemCount", {
      get: function() {
        return this[LRU_LIST].length;
      },
      enumerable: true
    });
    LRUCache.prototype.rforEach = function(fn, thisp) {
      thisp = thisp || this;
      for (var walker = this[LRU_LIST].tail; walker !== null; ) {
        var prev = walker.prev;
        forEachStep(this, fn, walker, thisp);
        walker = prev;
      }
    };
    function forEachStep(self, fn, node, thisp) {
      var hit = node.value;
      if (isStale(self, hit)) {
        del(self, node);
        if (!self[ALLOW_STALE]) {
          hit = void 0;
        }
      }
      if (hit) {
        fn.call(thisp, hit.value, hit.key, self);
      }
    }
    LRUCache.prototype.forEach = function(fn, thisp) {
      thisp = thisp || this;
      for (var walker = this[LRU_LIST].head; walker !== null; ) {
        var next = walker.next;
        forEachStep(this, fn, walker, thisp);
        walker = next;
      }
    };
    LRUCache.prototype.keys = function() {
      return this[LRU_LIST].toArray().map(function(k) {
        return k.key;
      }, this);
    };
    LRUCache.prototype.values = function() {
      return this[LRU_LIST].toArray().map(function(k) {
        return k.value;
      }, this);
    };
    LRUCache.prototype.reset = function() {
      if (this[DISPOSE] && this[LRU_LIST] && this[LRU_LIST].length) {
        this[LRU_LIST].forEach(function(hit) {
          this[DISPOSE](hit.key, hit.value);
        }, this);
      }
      this[CACHE] = new Map2();
      this[LRU_LIST] = new Yallist();
      this[LENGTH] = 0;
    };
    LRUCache.prototype.dump = function() {
      return this[LRU_LIST].map(function(hit) {
        if (!isStale(this, hit)) {
          return {
            k: hit.key,
            v: hit.value,
            e: hit.now + (hit.maxAge || 0)
          };
        }
      }, this).toArray().filter(function(h) {
        return h;
      });
    };
    LRUCache.prototype.dumpLru = function() {
      return this[LRU_LIST];
    };
    LRUCache.prototype.inspect = function(n, opts) {
      var str = "LRUCache {";
      var extras = false;
      var as = this[ALLOW_STALE];
      if (as) {
        str += "\n  allowStale: true";
        extras = true;
      }
      var max = this[MAX];
      if (max && max !== Infinity) {
        if (extras) {
          str += ",";
        }
        str += "\n  max: " + util.inspect(max, opts);
        extras = true;
      }
      var maxAge = this[MAX_AGE];
      if (maxAge) {
        if (extras) {
          str += ",";
        }
        str += "\n  maxAge: " + util.inspect(maxAge, opts);
        extras = true;
      }
      var lc = this[LENGTH_CALCULATOR];
      if (lc && lc !== naiveLength) {
        if (extras) {
          str += ",";
        }
        str += "\n  length: " + util.inspect(this[LENGTH], opts);
        extras = true;
      }
      var didFirst = false;
      this[LRU_LIST].forEach(function(item) {
        if (didFirst) {
          str += ",\n  ";
        } else {
          if (extras) {
            str += ",\n";
          }
          didFirst = true;
          str += "\n  ";
        }
        var key = util.inspect(item.key).split("\n").join("\n  ");
        var val = { value: item.value };
        if (item.maxAge !== maxAge) {
          val.maxAge = item.maxAge;
        }
        if (lc !== naiveLength) {
          val.length = item.length;
        }
        if (isStale(this, item)) {
          val.stale = true;
        }
        val = util.inspect(val, opts).split("\n").join("\n  ");
        str += key + " => " + val;
      });
      if (didFirst || extras) {
        str += "\n";
      }
      str += "}";
      return str;
    };
    LRUCache.prototype.set = function(key, value, maxAge) {
      maxAge = maxAge || this[MAX_AGE];
      var now = maxAge ? Date.now() : 0;
      var len = this[LENGTH_CALCULATOR](value, key);
      if (this[CACHE].has(key)) {
        if (len > this[MAX]) {
          del(this, this[CACHE].get(key));
          return false;
        }
        var node = this[CACHE].get(key);
        var item = node.value;
        if (this[DISPOSE]) {
          if (!this[NO_DISPOSE_ON_SET]) {
            this[DISPOSE](key, item.value);
          }
        }
        item.now = now;
        item.maxAge = maxAge;
        item.value = value;
        this[LENGTH] += len - item.length;
        item.length = len;
        this.get(key);
        trim(this);
        return true;
      }
      var hit = new Entry(key, value, len, now, maxAge);
      if (hit.length > this[MAX]) {
        if (this[DISPOSE]) {
          this[DISPOSE](key, value);
        }
        return false;
      }
      this[LENGTH] += hit.length;
      this[LRU_LIST].unshift(hit);
      this[CACHE].set(key, this[LRU_LIST].head);
      trim(this);
      return true;
    };
    LRUCache.prototype.has = function(key) {
      if (!this[CACHE].has(key)) return false;
      var hit = this[CACHE].get(key).value;
      if (isStale(this, hit)) {
        return false;
      }
      return true;
    };
    LRUCache.prototype.get = function(key) {
      return get(this, key, true);
    };
    LRUCache.prototype.peek = function(key) {
      return get(this, key, false);
    };
    LRUCache.prototype.pop = function() {
      var node = this[LRU_LIST].tail;
      if (!node) return null;
      del(this, node);
      return node.value;
    };
    LRUCache.prototype.del = function(key) {
      del(this, this[CACHE].get(key));
    };
    LRUCache.prototype.load = function(arr) {
      this.reset();
      var now = Date.now();
      for (var l = arr.length - 1; l >= 0; l--) {
        var hit = arr[l];
        var expiresAt = hit.e || 0;
        if (expiresAt === 0) {
          this.set(hit.k, hit.v);
        } else {
          var maxAge = expiresAt - now;
          if (maxAge > 0) {
            this.set(hit.k, hit.v, maxAge);
          }
        }
      }
    };
    LRUCache.prototype.prune = function() {
      var self = this;
      this[CACHE].forEach(function(value, key) {
        get(self, key, false);
      });
    };
    function get(self, key, doUse) {
      var node = self[CACHE].get(key);
      if (node) {
        var hit = node.value;
        if (isStale(self, hit)) {
          del(self, node);
          if (!self[ALLOW_STALE]) hit = void 0;
        } else {
          if (doUse) {
            self[LRU_LIST].unshiftNode(node);
          }
        }
        if (hit) hit = hit.value;
      }
      return hit;
    }
    function isStale(self, hit) {
      if (!hit || !hit.maxAge && !self[MAX_AGE]) {
        return false;
      }
      var stale = false;
      var diff = Date.now() - hit.now;
      if (hit.maxAge) {
        stale = diff > hit.maxAge;
      } else {
        stale = self[MAX_AGE] && diff > self[MAX_AGE];
      }
      return stale;
    }
    function trim(self) {
      if (self[LENGTH] > self[MAX]) {
        for (var walker = self[LRU_LIST].tail; self[LENGTH] > self[MAX] && walker !== null; ) {
          var prev = walker.prev;
          del(self, walker);
          walker = prev;
        }
      }
    }
    function del(self, node) {
      if (node) {
        var hit = node.value;
        if (self[DISPOSE]) {
          self[DISPOSE](hit.key, hit.value);
        }
        self[LENGTH] -= hit.length;
        self[CACHE].delete(hit.key);
        self[LRU_LIST].removeNode(node);
      }
    }
    function Entry(key, value, length, now, maxAge) {
      this.key = key;
      this.value = value;
      this.length = length;
      this.now = now;
      this.maxAge = maxAge || 0;
    }
  }
});

// node_modules/isexe/windows.js
var require_windows = __commonJS({
  "node_modules/isexe/windows.js"(exports2, module2) {
    module2.exports = isexe;
    isexe.sync = sync;
    var fs3 = require("fs");
    function checkPathExt(path3, options) {
      var pathext = options.pathExt !== void 0 ? options.pathExt : process.env.PATHEXT;
      if (!pathext) {
        return true;
      }
      pathext = pathext.split(";");
      if (pathext.indexOf("") !== -1) {
        return true;
      }
      for (var i = 0; i < pathext.length; i++) {
        var p = pathext[i].toLowerCase();
        if (p && path3.substr(-p.length).toLowerCase() === p) {
          return true;
        }
      }
      return false;
    }
    function checkStat(stat, path3, options) {
      if (!stat.isSymbolicLink() && !stat.isFile()) {
        return false;
      }
      return checkPathExt(path3, options);
    }
    function isexe(path3, options, cb) {
      fs3.stat(path3, function(er, stat) {
        cb(er, er ? false : checkStat(stat, path3, options));
      });
    }
    function sync(path3, options) {
      return checkStat(fs3.statSync(path3), path3, options);
    }
  }
});

// node_modules/isexe/mode.js
var require_mode = __commonJS({
  "node_modules/isexe/mode.js"(exports2, module2) {
    module2.exports = isexe;
    isexe.sync = sync;
    var fs3 = require("fs");
    function isexe(path3, options, cb) {
      fs3.stat(path3, function(er, stat) {
        cb(er, er ? false : checkStat(stat, options));
      });
    }
    function sync(path3, options) {
      return checkStat(fs3.statSync(path3), options);
    }
    function checkStat(stat, options) {
      return stat.isFile() && checkMode(stat, options);
    }
    function checkMode(stat, options) {
      var mod = stat.mode;
      var uid = stat.uid;
      var gid = stat.gid;
      var myUid = options.uid !== void 0 ? options.uid : process.getuid && process.getuid();
      var myGid = options.gid !== void 0 ? options.gid : process.getgid && process.getgid();
      var u = parseInt("100", 8);
      var g = parseInt("010", 8);
      var o = parseInt("001", 8);
      var ug = u | g;
      var ret = mod & o || mod & g && gid === myGid || mod & u && uid === myUid || mod & ug && myUid === 0;
      return ret;
    }
  }
});

// node_modules/isexe/index.js
var require_isexe = __commonJS({
  "node_modules/isexe/index.js"(exports2, module2) {
    var fs3 = require("fs");
    var core3;
    if (process.platform === "win32" || global.TESTING_WINDOWS) {
      core3 = require_windows();
    } else {
      core3 = require_mode();
    }
    module2.exports = isexe;
    isexe.sync = sync;
    function isexe(path3, options, cb) {
      if (typeof options === "function") {
        cb = options;
        options = {};
      }
      if (!cb) {
        if (typeof Promise !== "function") {
          throw new TypeError("callback not provided");
        }
        return new Promise(function(resolve2, reject) {
          isexe(path3, options || {}, function(er, is) {
            if (er) {
              reject(er);
            } else {
              resolve2(is);
            }
          });
        });
      }
      core3(path3, options || {}, function(er, is) {
        if (er) {
          if (er.code === "EACCES" || options && options.ignoreErrors) {
            er = null;
            is = false;
          }
        }
        cb(er, is);
      });
    }
    function sync(path3, options) {
      try {
        return core3.sync(path3, options || {});
      } catch (er) {
        if (options && options.ignoreErrors || er.code === "EACCES") {
          return false;
        } else {
          throw er;
        }
      }
    }
  }
});

// node_modules/which/which.js
var require_which = __commonJS({
  "node_modules/which/which.js"(exports2, module2) {
    module2.exports = which;
    which.sync = whichSync;
    var isWindows = process.platform === "win32" || process.env.OSTYPE === "cygwin" || process.env.OSTYPE === "msys";
    var path3 = require("path");
    var COLON = isWindows ? ";" : ":";
    var isexe = require_isexe();
    function getNotFoundError(cmd) {
      var er = new Error("not found: " + cmd);
      er.code = "ENOENT";
      return er;
    }
    function getPathInfo(cmd, opt) {
      var colon = opt.colon || COLON;
      var pathEnv = opt.path || process.env.PATH || "";
      var pathExt = [""];
      pathEnv = pathEnv.split(colon);
      var pathExtExe = "";
      if (isWindows) {
        pathEnv.unshift(process.cwd());
        pathExtExe = opt.pathExt || process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM";
        pathExt = pathExtExe.split(colon);
        if (cmd.indexOf(".") !== -1 && pathExt[0] !== "")
          pathExt.unshift("");
      }
      if (cmd.match(/\//) || isWindows && cmd.match(/\\/))
        pathEnv = [""];
      return {
        env: pathEnv,
        ext: pathExt,
        extExe: pathExtExe
      };
    }
    function which(cmd, opt, cb) {
      if (typeof opt === "function") {
        cb = opt;
        opt = {};
      }
      var info2 = getPathInfo(cmd, opt);
      var pathEnv = info2.env;
      var pathExt = info2.ext;
      var pathExtExe = info2.extExe;
      var found = [];
      (function F(i, l) {
        if (i === l) {
          if (opt.all && found.length)
            return cb(null, found);
          else
            return cb(getNotFoundError(cmd));
        }
        var pathPart = pathEnv[i];
        if (pathPart.charAt(0) === '"' && pathPart.slice(-1) === '"')
          pathPart = pathPart.slice(1, -1);
        var p = path3.join(pathPart, cmd);
        if (!pathPart && /^\.[\\\/]/.test(cmd)) {
          p = cmd.slice(0, 2) + p;
        }
        ;
        (function E(ii, ll) {
          if (ii === ll) return F(i + 1, l);
          var ext = pathExt[ii];
          isexe(p + ext, { pathExt: pathExtExe }, function(er, is) {
            if (!er && is) {
              if (opt.all)
                found.push(p + ext);
              else
                return cb(null, p + ext);
            }
            return E(ii + 1, ll);
          });
        })(0, pathExt.length);
      })(0, pathEnv.length);
    }
    function whichSync(cmd, opt) {
      opt = opt || {};
      var info2 = getPathInfo(cmd, opt);
      var pathEnv = info2.env;
      var pathExt = info2.ext;
      var pathExtExe = info2.extExe;
      var found = [];
      for (var i = 0, l = pathEnv.length; i < l; i++) {
        var pathPart = pathEnv[i];
        if (pathPart.charAt(0) === '"' && pathPart.slice(-1) === '"')
          pathPart = pathPart.slice(1, -1);
        var p = path3.join(pathPart, cmd);
        if (!pathPart && /^\.[\\\/]/.test(cmd)) {
          p = cmd.slice(0, 2) + p;
        }
        for (var j = 0, ll = pathExt.length; j < ll; j++) {
          var cur = p + pathExt[j];
          var is;
          try {
            is = isexe.sync(cur, { pathExt: pathExtExe });
            if (is) {
              if (opt.all)
                found.push(cur);
              else
                return cur;
            }
          } catch (ex) {
          }
        }
      }
      if (opt.all && found.length)
        return found;
      if (opt.nothrow)
        return null;
      throw getNotFoundError(cmd);
    }
  }
});

// node_modules/cross-spawn/lib/resolveCommand.js
var require_resolveCommand = __commonJS({
  "node_modules/cross-spawn/lib/resolveCommand.js"(exports2, module2) {
    "use strict";
    var path3 = require("path");
    var which = require_which();
    var LRU = require_lru_cache();
    var commandCache = new LRU({ max: 50, maxAge: 30 * 1e3 });
    function resolveCommand(command, noExtension) {
      var resolved;
      noExtension = !!noExtension;
      resolved = commandCache.get(command + "!" + noExtension);
      if (commandCache.has(command)) {
        return commandCache.get(command);
      }
      try {
        resolved = !noExtension ? which.sync(command) : which.sync(command, { pathExt: path3.delimiter + (process.env.PATHEXT || "") });
      } catch (e) {
      }
      commandCache.set(command + "!" + noExtension, resolved);
      return resolved;
    }
    module2.exports = resolveCommand;
  }
});

// node_modules/cross-spawn/lib/hasBrokenSpawn.js
var require_hasBrokenSpawn = __commonJS({
  "node_modules/cross-spawn/lib/hasBrokenSpawn.js"(exports2, module2) {
    "use strict";
    module2.exports = function() {
      if (process.platform !== "win32") {
        return false;
      }
      var nodeVer = process.version.substr(1).split(".").map(function(num) {
        return parseInt(num, 10);
      });
      return nodeVer[0] === 0 && nodeVer[1] < 12;
    }();
  }
});

// node_modules/cross-spawn/lib/parse.js
var require_parse = __commonJS({
  "node_modules/cross-spawn/lib/parse.js"(exports2, module2) {
    "use strict";
    var fs3 = require("fs");
    var LRU = require_lru_cache();
    var resolveCommand = require_resolveCommand();
    var hasBrokenSpawn = require_hasBrokenSpawn();
    var isWin = process.platform === "win32";
    var shebangCache = new LRU({ max: 50, maxAge: 30 * 1e3 });
    function readShebang(command) {
      var buffer;
      var fd;
      var match;
      var shebang;
      if (shebangCache.has(command)) {
        return shebangCache.get(command);
      }
      buffer = new Buffer(150);
      try {
        fd = fs3.openSync(command, "r");
        fs3.readSync(fd, buffer, 0, 150, 0);
        fs3.closeSync(fd);
      } catch (e) {
      }
      match = buffer.toString().trim().match(/#!(.+)/i);
      if (match) {
        shebang = match[1].replace(/\/usr\/bin\/env\s+/i, "");
      }
      shebangCache.set(command, shebang);
      return shebang;
    }
    function escapeArg(arg, quote) {
      arg = "" + arg;
      if (!quote) {
        arg = arg.replace(/([\(\)%!\^<>&|;,"'\s])/g, "^$1");
      } else {
        arg = arg.replace(/(\\*)"/g, '$1$1\\"');
        arg = arg.replace(/(\\*)$/, "$1$1");
        arg = '"' + arg + '"';
      }
      return arg;
    }
    function escapeCommand(command) {
      return /^[a-z0-9_-]+$/i.test(command) ? command : escapeArg(command, true);
    }
    function requiresShell(command) {
      return !/\.(?:com|exe)$/i.test(command);
    }
    function parse3(command, args, options) {
      var shebang;
      var applyQuotes;
      var file;
      var original;
      var shell;
      if (args && !Array.isArray(args)) {
        options = args;
        args = null;
      }
      args = args ? args.slice(0) : [];
      options = options || {};
      original = command;
      if (isWin) {
        file = resolveCommand(command);
        file = file || resolveCommand(command, true);
        shebang = file && readShebang(file);
        shell = options.shell || hasBrokenSpawn;
        if (shebang) {
          args.unshift(file);
          command = shebang;
          shell = shell || requiresShell(resolveCommand(shebang) || resolveCommand(shebang, true));
        } else {
          shell = shell || requiresShell(file);
        }
        if (shell) {
          applyQuotes = command !== "echo";
          command = escapeCommand(command);
          args = args.map(function(arg) {
            return escapeArg(arg, applyQuotes);
          });
          args = ["/s", "/c", '"' + command + (args.length ? " " + args.join(" ") : "") + '"'];
          command = process.env.comspec || "cmd.exe";
          options.windowsVerbatimArguments = true;
        }
      }
      return {
        command,
        args,
        options,
        file,
        original
      };
    }
    module2.exports = parse3;
  }
});

// node_modules/cross-spawn/lib/enoent.js
var require_enoent = __commonJS({
  "node_modules/cross-spawn/lib/enoent.js"(exports2, module2) {
    "use strict";
    var isWin = process.platform === "win32";
    var resolveCommand = require_resolveCommand();
    var isNode10 = process.version.indexOf("v0.10.") === 0;
    function notFoundError(command, syscall) {
      var err;
      err = new Error(syscall + " " + command + " ENOENT");
      err.code = err.errno = "ENOENT";
      err.syscall = syscall + " " + command;
      return err;
    }
    function hookChildProcess(cp, parsed) {
      var originalEmit;
      if (!isWin) {
        return;
      }
      originalEmit = cp.emit;
      cp.emit = function(name, arg1) {
        var err;
        if (name === "exit") {
          err = verifyENOENT(arg1, parsed, "spawn");
          if (err) {
            return originalEmit.call(cp, "error", err);
          }
        }
        return originalEmit.apply(cp, arguments);
      };
    }
    function verifyENOENT(status, parsed) {
      if (isWin && status === 1 && !parsed.file) {
        return notFoundError(parsed.original, "spawn");
      }
      return null;
    }
    function verifyENOENTSync(status, parsed) {
      if (isWin && status === 1 && !parsed.file) {
        return notFoundError(parsed.original, "spawnSync");
      }
      if (isNode10 && status === -1) {
        parsed.file = isWin ? parsed.file : resolveCommand(parsed.original);
        if (!parsed.file) {
          return notFoundError(parsed.original, "spawnSync");
        }
      }
      return null;
    }
    module2.exports.hookChildProcess = hookChildProcess;
    module2.exports.verifyENOENT = verifyENOENT;
    module2.exports.verifyENOENTSync = verifyENOENTSync;
    module2.exports.notFoundError = notFoundError;
  }
});

// node_modules/cross-spawn/index.js
var require_cross_spawn = __commonJS({
  "node_modules/cross-spawn/index.js"(exports2, module2) {
    "use strict";
    var cp = require("child_process");
    var parse3 = require_parse();
    var enoent = require_enoent();
    var cpSpawnSync = cp.spawnSync;
    function spawn(command, args, options) {
      var parsed;
      var spawned;
      parsed = parse3(command, args, options);
      spawned = cp.spawn(parsed.command, parsed.args, parsed.options);
      enoent.hookChildProcess(spawned, parsed);
      return spawned;
    }
    function spawnSync(command, args, options) {
      var parsed;
      var result;
      if (!cpSpawnSync) {
        try {
          cpSpawnSync = require("spawn-sync");
        } catch (ex) {
          throw new Error(
            "In order to use spawnSync on node 0.10 or older, you must install spawn-sync:\n\n  npm install spawn-sync --save"
          );
        }
      }
      parsed = parse3(command, args, options);
      result = cpSpawnSync(parsed.command, parsed.args, parsed.options);
      result.error = result.error || enoent.verifyENOENTSync(result.status, parsed);
      return result;
    }
    module2.exports = spawn;
    module2.exports.spawn = spawn;
    module2.exports.sync = spawnSync;
    module2.exports._parse = parse3;
    module2.exports._enoent = enoent;
  }
});

// node_modules/ms/index.js
var require_ms = __commonJS({
  "node_modules/ms/index.js"(exports2, module2) {
    var s = 1e3;
    var m = s * 60;
    var h = m * 60;
    var d = h * 24;
    var w = d * 7;
    var y = d * 365.25;
    module2.exports = function(val, options) {
      options = options || {};
      var type = typeof val;
      if (type === "string" && val.length > 0) {
        return parse3(val);
      } else if (type === "number" && isFinite(val)) {
        return options.long ? fmtLong(val) : fmtShort(val);
      }
      throw new Error(
        "val is not a non-empty string or a valid number. val=" + JSON.stringify(val)
      );
    };
    function parse3(str) {
      str = String(str);
      if (str.length > 100) {
        return;
      }
      var match = /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
        str
      );
      if (!match) {
        return;
      }
      var n = parseFloat(match[1]);
      var type = (match[2] || "ms").toLowerCase();
      switch (type) {
        case "years":
        case "year":
        case "yrs":
        case "yr":
        case "y":
          return n * y;
        case "weeks":
        case "week":
        case "w":
          return n * w;
        case "days":
        case "day":
        case "d":
          return n * d;
        case "hours":
        case "hour":
        case "hrs":
        case "hr":
        case "h":
          return n * h;
        case "minutes":
        case "minute":
        case "mins":
        case "min":
        case "m":
          return n * m;
        case "seconds":
        case "second":
        case "secs":
        case "sec":
        case "s":
          return n * s;
        case "milliseconds":
        case "millisecond":
        case "msecs":
        case "msec":
        case "ms":
          return n;
        default:
          return void 0;
      }
    }
    function fmtShort(ms) {
      var msAbs = Math.abs(ms);
      if (msAbs >= d) {
        return Math.round(ms / d) + "d";
      }
      if (msAbs >= h) {
        return Math.round(ms / h) + "h";
      }
      if (msAbs >= m) {
        return Math.round(ms / m) + "m";
      }
      if (msAbs >= s) {
        return Math.round(ms / s) + "s";
      }
      return ms + "ms";
    }
    function fmtLong(ms) {
      var msAbs = Math.abs(ms);
      if (msAbs >= d) {
        return plural(ms, msAbs, d, "day");
      }
      if (msAbs >= h) {
        return plural(ms, msAbs, h, "hour");
      }
      if (msAbs >= m) {
        return plural(ms, msAbs, m, "minute");
      }
      if (msAbs >= s) {
        return plural(ms, msAbs, s, "second");
      }
      return ms + " ms";
    }
    function plural(ms, msAbs, n, name) {
      var isPlural = msAbs >= n * 1.5;
      return Math.round(ms / n) + " " + name + (isPlural ? "s" : "");
    }
  }
});

// node_modules/debug/src/common.js
var require_common = __commonJS({
  "node_modules/debug/src/common.js"(exports2, module2) {
    "use strict";
    function setup(env) {
      createDebug.debug = createDebug;
      createDebug.default = createDebug;
      createDebug.coerce = coerce;
      createDebug.disable = disable;
      createDebug.enable = enable;
      createDebug.enabled = enabled;
      createDebug.humanize = require_ms();
      Object.keys(env).forEach(function(key) {
        createDebug[key] = env[key];
      });
      createDebug.instances = [];
      createDebug.names = [];
      createDebug.skips = [];
      createDebug.formatters = {};
      function selectColor(namespace) {
        var hash = 0;
        for (var i = 0; i < namespace.length; i++) {
          hash = (hash << 5) - hash + namespace.charCodeAt(i);
          hash |= 0;
        }
        return createDebug.colors[Math.abs(hash) % createDebug.colors.length];
      }
      createDebug.selectColor = selectColor;
      function createDebug(namespace) {
        var prevTime;
        function debug() {
          if (!debug.enabled) {
            return;
          }
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          var self = debug;
          var curr = Number(/* @__PURE__ */ new Date());
          var ms = curr - (prevTime || curr);
          self.diff = ms;
          self.prev = prevTime;
          self.curr = curr;
          prevTime = curr;
          args[0] = createDebug.coerce(args[0]);
          if (typeof args[0] !== "string") {
            args.unshift("%O");
          }
          var index = 0;
          args[0] = args[0].replace(/%([a-zA-Z%])/g, function(match, format) {
            if (match === "%%") {
              return match;
            }
            index++;
            var formatter = createDebug.formatters[format];
            if (typeof formatter === "function") {
              var val = args[index];
              match = formatter.call(self, val);
              args.splice(index, 1);
              index--;
            }
            return match;
          });
          createDebug.formatArgs.call(self, args);
          var logFn = self.log || createDebug.log;
          logFn.apply(self, args);
        }
        debug.namespace = namespace;
        debug.enabled = createDebug.enabled(namespace);
        debug.useColors = createDebug.useColors();
        debug.color = selectColor(namespace);
        debug.destroy = destroy;
        debug.extend = extend;
        if (typeof createDebug.init === "function") {
          createDebug.init(debug);
        }
        createDebug.instances.push(debug);
        return debug;
      }
      function destroy() {
        var index = createDebug.instances.indexOf(this);
        if (index !== -1) {
          createDebug.instances.splice(index, 1);
          return true;
        }
        return false;
      }
      function extend(namespace, delimiter) {
        return createDebug(this.namespace + (typeof delimiter === "undefined" ? ":" : delimiter) + namespace);
      }
      function enable(namespaces) {
        createDebug.save(namespaces);
        createDebug.names = [];
        createDebug.skips = [];
        var i;
        var split = (typeof namespaces === "string" ? namespaces : "").split(/[\s,]+/);
        var len = split.length;
        for (i = 0; i < len; i++) {
          if (!split[i]) {
            continue;
          }
          namespaces = split[i].replace(/\*/g, ".*?");
          if (namespaces[0] === "-") {
            createDebug.skips.push(new RegExp("^" + namespaces.substr(1) + "$"));
          } else {
            createDebug.names.push(new RegExp("^" + namespaces + "$"));
          }
        }
        for (i = 0; i < createDebug.instances.length; i++) {
          var instance = createDebug.instances[i];
          instance.enabled = createDebug.enabled(instance.namespace);
        }
      }
      function disable() {
        createDebug.enable("");
      }
      function enabled(name) {
        if (name[name.length - 1] === "*") {
          return true;
        }
        var i;
        var len;
        for (i = 0, len = createDebug.skips.length; i < len; i++) {
          if (createDebug.skips[i].test(name)) {
            return false;
          }
        }
        for (i = 0, len = createDebug.names.length; i < len; i++) {
          if (createDebug.names[i].test(name)) {
            return true;
          }
        }
        return false;
      }
      function coerce(val) {
        if (val instanceof Error) {
          return val.stack || val.message;
        }
        return val;
      }
      createDebug.enable(createDebug.load());
      return createDebug;
    }
    module2.exports = setup;
  }
});

// node_modules/debug/src/browser.js
var require_browser = __commonJS({
  "node_modules/debug/src/browser.js"(exports2, module2) {
    "use strict";
    function _typeof(obj) {
      if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") {
        _typeof = function _typeof2(obj2) {
          return typeof obj2;
        };
      } else {
        _typeof = function _typeof2(obj2) {
          return obj2 && typeof Symbol === "function" && obj2.constructor === Symbol && obj2 !== Symbol.prototype ? "symbol" : typeof obj2;
        };
      }
      return _typeof(obj);
    }
    exports2.log = log;
    exports2.formatArgs = formatArgs;
    exports2.save = save;
    exports2.load = load;
    exports2.useColors = useColors;
    exports2.storage = localstorage();
    exports2.colors = ["#0000CC", "#0000FF", "#0033CC", "#0033FF", "#0066CC", "#0066FF", "#0099CC", "#0099FF", "#00CC00", "#00CC33", "#00CC66", "#00CC99", "#00CCCC", "#00CCFF", "#3300CC", "#3300FF", "#3333CC", "#3333FF", "#3366CC", "#3366FF", "#3399CC", "#3399FF", "#33CC00", "#33CC33", "#33CC66", "#33CC99", "#33CCCC", "#33CCFF", "#6600CC", "#6600FF", "#6633CC", "#6633FF", "#66CC00", "#66CC33", "#9900CC", "#9900FF", "#9933CC", "#9933FF", "#99CC00", "#99CC33", "#CC0000", "#CC0033", "#CC0066", "#CC0099", "#CC00CC", "#CC00FF", "#CC3300", "#CC3333", "#CC3366", "#CC3399", "#CC33CC", "#CC33FF", "#CC6600", "#CC6633", "#CC9900", "#CC9933", "#CCCC00", "#CCCC33", "#FF0000", "#FF0033", "#FF0066", "#FF0099", "#FF00CC", "#FF00FF", "#FF3300", "#FF3333", "#FF3366", "#FF3399", "#FF33CC", "#FF33FF", "#FF6600", "#FF6633", "#FF9900", "#FF9933", "#FFCC00", "#FFCC33"];
    function useColors() {
      if (typeof window !== "undefined" && window.process && (window.process.type === "renderer" || window.process.__nwjs)) {
        return true;
      }
      if (typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/(edge|trident)\/(\d+)/)) {
        return false;
      }
      return typeof document !== "undefined" && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance || // Is firebug? http://stackoverflow.com/a/398120/376773
      typeof window !== "undefined" && window.console && (window.console.firebug || window.console.exception && window.console.table) || // Is firefox >= v31?
      // https://developer.mozilla.org/en-US/docs/Tools/Web_Console#Styling_messages
      typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/) && parseInt(RegExp.$1, 10) >= 31 || // Double check webkit in userAgent just in case we are in a worker
      typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/);
    }
    function formatArgs(args) {
      args[0] = (this.useColors ? "%c" : "") + this.namespace + (this.useColors ? " %c" : " ") + args[0] + (this.useColors ? "%c " : " ") + "+" + module2.exports.humanize(this.diff);
      if (!this.useColors) {
        return;
      }
      var c = "color: " + this.color;
      args.splice(1, 0, c, "color: inherit");
      var index = 0;
      var lastC = 0;
      args[0].replace(/%[a-zA-Z%]/g, function(match) {
        if (match === "%%") {
          return;
        }
        index++;
        if (match === "%c") {
          lastC = index;
        }
      });
      args.splice(lastC, 0, c);
    }
    function log() {
      var _console;
      return (typeof console === "undefined" ? "undefined" : _typeof(console)) === "object" && console.log && (_console = console).log.apply(_console, arguments);
    }
    function save(namespaces) {
      try {
        if (namespaces) {
          exports2.storage.setItem("debug", namespaces);
        } else {
          exports2.storage.removeItem("debug");
        }
      } catch (error) {
      }
    }
    function load() {
      var r;
      try {
        r = exports2.storage.getItem("debug");
      } catch (error) {
      }
      if (!r && typeof process !== "undefined" && "env" in process) {
        r = process.env.DEBUG;
      }
      return r;
    }
    function localstorage() {
      try {
        return localStorage;
      } catch (error) {
      }
    }
    module2.exports = require_common()(exports2);
    var formatters = module2.exports.formatters;
    formatters.j = function(v) {
      try {
        return JSON.stringify(v);
      } catch (error) {
        return "[UnexpectedJSONParseError]: " + error.message;
      }
    };
  }
});

// node_modules/has-flag/index.js
var require_has_flag = __commonJS({
  "node_modules/has-flag/index.js"(exports2, module2) {
    "use strict";
    module2.exports = (flag, argv = process.argv) => {
      const prefix = flag.startsWith("-") ? "" : flag.length === 1 ? "-" : "--";
      const position = argv.indexOf(prefix + flag);
      const terminatorPosition = argv.indexOf("--");
      return position !== -1 && (terminatorPosition === -1 || position < terminatorPosition);
    };
  }
});

// node_modules/supports-color/index.js
var require_supports_color = __commonJS({
  "node_modules/supports-color/index.js"(exports2, module2) {
    "use strict";
    var os = require("os");
    var tty = require("tty");
    var hasFlag = require_has_flag();
    var { env } = process;
    var forceColor;
    if (hasFlag("no-color") || hasFlag("no-colors") || hasFlag("color=false") || hasFlag("color=never")) {
      forceColor = 0;
    } else if (hasFlag("color") || hasFlag("colors") || hasFlag("color=true") || hasFlag("color=always")) {
      forceColor = 1;
    }
    if ("FORCE_COLOR" in env) {
      if (env.FORCE_COLOR === "true") {
        forceColor = 1;
      } else if (env.FORCE_COLOR === "false") {
        forceColor = 0;
      } else {
        forceColor = env.FORCE_COLOR.length === 0 ? 1 : Math.min(parseInt(env.FORCE_COLOR, 10), 3);
      }
    }
    function translateLevel(level) {
      if (level === 0) {
        return false;
      }
      return {
        level,
        hasBasic: true,
        has256: level >= 2,
        has16m: level >= 3
      };
    }
    function supportsColor(haveStream, streamIsTTY) {
      if (forceColor === 0) {
        return 0;
      }
      if (hasFlag("color=16m") || hasFlag("color=full") || hasFlag("color=truecolor")) {
        return 3;
      }
      if (hasFlag("color=256")) {
        return 2;
      }
      if (haveStream && !streamIsTTY && forceColor === void 0) {
        return 0;
      }
      const min = forceColor || 0;
      if (env.TERM === "dumb") {
        return min;
      }
      if (process.platform === "win32") {
        const osRelease = os.release().split(".");
        if (Number(osRelease[0]) >= 10 && Number(osRelease[2]) >= 10586) {
          return Number(osRelease[2]) >= 14931 ? 3 : 2;
        }
        return 1;
      }
      if ("CI" in env) {
        if (["TRAVIS", "CIRCLECI", "APPVEYOR", "GITLAB_CI", "GITHUB_ACTIONS", "BUILDKITE"].some((sign) => sign in env) || env.CI_NAME === "codeship") {
          return 1;
        }
        return min;
      }
      if ("TEAMCITY_VERSION" in env) {
        return /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/.test(env.TEAMCITY_VERSION) ? 1 : 0;
      }
      if (env.COLORTERM === "truecolor") {
        return 3;
      }
      if ("TERM_PROGRAM" in env) {
        const version2 = parseInt((env.TERM_PROGRAM_VERSION || "").split(".")[0], 10);
        switch (env.TERM_PROGRAM) {
          case "iTerm.app":
            return version2 >= 3 ? 3 : 2;
          case "Apple_Terminal":
            return 2;
        }
      }
      if (/-256(color)?$/i.test(env.TERM)) {
        return 2;
      }
      if (/^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(env.TERM)) {
        return 1;
      }
      if ("COLORTERM" in env) {
        return 1;
      }
      return min;
    }
    function getSupportLevel(stream) {
      const level = supportsColor(stream, stream && stream.isTTY);
      return translateLevel(level);
    }
    module2.exports = {
      supportsColor: getSupportLevel,
      stdout: translateLevel(supportsColor(true, tty.isatty(1))),
      stderr: translateLevel(supportsColor(true, tty.isatty(2)))
    };
  }
});

// node_modules/debug/src/node.js
var require_node = __commonJS({
  "node_modules/debug/src/node.js"(exports2, module2) {
    "use strict";
    var tty = require("tty");
    var util = require("util");
    exports2.init = init;
    exports2.log = log;
    exports2.formatArgs = formatArgs;
    exports2.save = save;
    exports2.load = load;
    exports2.useColors = useColors;
    exports2.colors = [6, 2, 3, 4, 5, 1];
    try {
      supportsColor = require_supports_color();
      if (supportsColor && (supportsColor.stderr || supportsColor).level >= 2) {
        exports2.colors = [20, 21, 26, 27, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 56, 57, 62, 63, 68, 69, 74, 75, 76, 77, 78, 79, 80, 81, 92, 93, 98, 99, 112, 113, 128, 129, 134, 135, 148, 149, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 178, 179, 184, 185, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 214, 215, 220, 221];
      }
    } catch (error) {
    }
    var supportsColor;
    exports2.inspectOpts = Object.keys(process.env).filter(function(key) {
      return /^debug_/i.test(key);
    }).reduce(function(obj, key) {
      var prop = key.substring(6).toLowerCase().replace(/_([a-z])/g, function(_, k) {
        return k.toUpperCase();
      });
      var val = process.env[key];
      if (/^(yes|on|true|enabled)$/i.test(val)) {
        val = true;
      } else if (/^(no|off|false|disabled)$/i.test(val)) {
        val = false;
      } else if (val === "null") {
        val = null;
      } else {
        val = Number(val);
      }
      obj[prop] = val;
      return obj;
    }, {});
    function useColors() {
      return "colors" in exports2.inspectOpts ? Boolean(exports2.inspectOpts.colors) : tty.isatty(process.stderr.fd);
    }
    function formatArgs(args) {
      var name = this.namespace, useColors2 = this.useColors;
      if (useColors2) {
        var c = this.color;
        var colorCode = "\x1B[3" + (c < 8 ? c : "8;5;" + c);
        var prefix = "  ".concat(colorCode, ";1m").concat(name, " \x1B[0m");
        args[0] = prefix + args[0].split("\n").join("\n" + prefix);
        args.push(colorCode + "m+" + module2.exports.humanize(this.diff) + "\x1B[0m");
      } else {
        args[0] = getDate() + name + " " + args[0];
      }
    }
    function getDate() {
      if (exports2.inspectOpts.hideDate) {
        return "";
      }
      return (/* @__PURE__ */ new Date()).toISOString() + " ";
    }
    function log() {
      return process.stderr.write(util.format.apply(util, arguments) + "\n");
    }
    function save(namespaces) {
      if (namespaces) {
        process.env.DEBUG = namespaces;
      } else {
        delete process.env.DEBUG;
      }
    }
    function load() {
      return process.env.DEBUG;
    }
    function init(debug) {
      debug.inspectOpts = {};
      var keys = Object.keys(exports2.inspectOpts);
      for (var i = 0; i < keys.length; i++) {
        debug.inspectOpts[keys[i]] = exports2.inspectOpts[keys[i]];
      }
    }
    module2.exports = require_common()(exports2);
    var formatters = module2.exports.formatters;
    formatters.o = function(v) {
      this.inspectOpts.colors = this.useColors;
      return util.inspect(v, this.inspectOpts).split("\n").map(function(str) {
        return str.trim();
      }).join(" ");
    };
    formatters.O = function(v) {
      this.inspectOpts.colors = this.useColors;
      return util.inspect(v, this.inspectOpts);
    };
  }
});

// node_modules/debug/src/index.js
var require_src = __commonJS({
  "node_modules/debug/src/index.js"(exports2, module2) {
    "use strict";
    if (typeof process === "undefined" || process.type === "renderer" || process.browser === true || process.__nwjs) {
      module2.exports = require_browser();
    } else {
      module2.exports = require_node();
    }
  }
});

// node_modules/array-series/index.js
var require_array_series = __commonJS({
  "node_modules/array-series/index.js"(exports2, module2) {
    module2.exports = function series(fns, context, callback) {
      if (!callback) {
        if (typeof context === "function") {
          callback = context;
          context = null;
        } else {
          callback = noop;
        }
      }
      if (!(fns && fns.length)) return callback();
      fns = fns.slice(0);
      var call = context ? function() {
        fns.length ? fns.shift().call(context, next) : callback();
      } : function() {
        fns.length ? fns.shift()(next) : callback();
      };
      call();
      function next(err) {
        err ? callback(err) : call();
      }
    };
    function noop() {
    }
  }
});

// node_modules/gm/lib/command.js
var require_command2 = __commonJS({
  "node_modules/gm/lib/command.js"(exports2, module2) {
    var spawn = require_cross_spawn();
    var utils = require_utils2();
    var debug = require_src()("gm");
    var series = require_array_series();
    var PassThrough = require("stream").PassThrough;
    var noBufferConcat = "gm v1.9.0+ required node v0.8+. Please update your version of node, downgrade gm < 1.9, or do not use `bufferStream`.";
    module2.exports = function(proto) {
      function args(prop) {
        return function args2() {
          var len = arguments.length;
          var a = [];
          var i = 0;
          for (; i < len; ++i) {
            a.push(arguments[i]);
          }
          this[prop] = this[prop].concat(a);
          return this;
        };
      }
      function streamToUnemptyBuffer(stream, callback) {
        var done = false;
        var buffers = [];
        stream.on("data", function(data) {
          buffers.push(data);
        });
        stream.on("end", function() {
          if (done)
            return;
          done = true;
          let result = Buffer.concat(buffers);
          buffers = null;
          if (result.length === 0) {
            const err = new Error("Stream yields empty buffer");
            callback(err, null);
          } else {
            callback(null, result);
          }
        });
        stream.on("error", function(err) {
          done = true;
          buffers = null;
          callback(err);
        });
      }
      proto.in = args("_in");
      proto.out = args("_out");
      proto._preprocessor = [];
      proto.preprocessor = args("_preprocessor");
      proto.write = function write(name, callback) {
        if (!callback) callback = name, name = null;
        if ("function" !== typeof callback) {
          throw new TypeError("gm().write() expects a callback function");
        }
        if (!name) {
          return callback(TypeError("gm().write() expects a filename when writing new files"));
        }
        this.outname = name;
        var self = this;
        this._preprocess(function(err) {
          if (err) return callback(err);
          self._spawn(self.args(), true, callback);
        });
      };
      proto.stream = function stream(format, callback) {
        if (!callback && typeof format === "function") {
          callback = format;
          format = null;
        }
        var throughStream;
        if ("function" !== typeof callback) {
          throughStream = new PassThrough();
          callback = function(err, stdout, stderr) {
            if (err) throughStream.emit("error", err);
            else stdout.pipe(throughStream);
          };
        }
        if (format) {
          format = format.split(".").pop();
          this.outname = format + ":-";
        }
        var self = this;
        this._preprocess(function(err) {
          if (err) return callback(err);
          return self._spawn(self.args(), false, callback);
        });
        return throughStream || this;
      };
      proto.toBuffer = function toBuffer(format, callback) {
        if (!callback) callback = format, format = null;
        if ("function" !== typeof callback) {
          throw new Error("gm().toBuffer() expects a callback.");
        }
        return this.stream(format, function(err, stdout) {
          if (err) return callback(err);
          streamToUnemptyBuffer(stdout, callback);
        });
      };
      proto._preprocess = function _preprocess(callback) {
        series(this._preprocessor, this, callback);
      };
      proto._exec = function _exec(args2, callback) {
        return this._spawn(args2, true, callback);
      };
      proto._spawn = function _spawn(args2, bufferOutput, callback) {
        var appPath = this._options.appPath || "";
        var bin;
        switch (this._options.imageMagick) {
          // legacy behavior
          case true:
            bin = args2.shift();
            break;
          // ImgeMagick >= 7
          case "7+":
            bin = "magick";
            break;
          // GraphicsMagick
          default:
            bin = "gm";
            break;
        }
        bin = appPath + bin;
        var cmd = bin + " " + args2.map(utils.escape).join(" "), self = this, proc, err, timeout = parseInt(this._options.timeout), disposers = this._options.disposers, timeoutId;
        debug(cmd);
        if (args2.indexOf("-minify") > -1 && this._options.imageMagick) {
          return cb(new Error("imageMagick does not support minify, use -scale or -sample. Alternatively, use graphicsMagick"));
        }
        try {
          proc = spawn(bin, args2);
        } catch (e) {
          return cb(e);
        }
        proc.stdin.once("error", cb);
        proc.on("error", function(err2) {
          if (err2.code === "ENOENT") {
            cb(new Error("Could not execute GraphicsMagick/ImageMagick: " + cmd + " this most likely means the gm/convert binaries can't be found"));
          } else {
            cb(err2);
          }
        });
        if (timeout) {
          timeoutId = setTimeout(function() {
            dispose("gm() resulted in a timeout.");
          }, timeout);
        }
        if (disposers) {
          disposers.forEach(function(disposer) {
            disposer.events.forEach(function(event) {
              disposer.emitter.on(event, dispose);
            });
          });
        }
        if (self.sourceBuffer) {
          proc.stdin.write(this.sourceBuffer);
          proc.stdin.end();
        } else if (self.sourceStream) {
          if (!self.sourceStream.readable) {
            return cb(new Error("gm().stream() or gm().write() with a non-readable stream."));
          }
          self.sourceStream.pipe(proc.stdin);
          if (self.bufferStream && !this._buffering) {
            if (!Buffer.concat) {
              throw new Error(noBufferConcat);
            }
            self._buffering = true;
            streamToUnemptyBuffer(self.sourceStream, function(err2, buffer) {
              self.sourceBuffer = buffer;
              self.sourceStream = null;
            });
          }
        }
        if (bufferOutput) {
          var stdout = "", stderr = "", onOut, onErr, onExit;
          proc.stdout.on("data", onOut = function(data) {
            stdout += data;
          });
          proc.stderr.on("data", onErr = function(data) {
            stderr += data;
          });
          proc.on("close", onExit = function(code, signal) {
            let err2;
            if (code !== 0 || signal !== null) {
              err2 = new Error("Command failed: " + stderr);
              err2.code = code;
              err2.signal = signal;
            }
            ;
            cb(err2, stdout, stderr, cmd);
            stdout = stderr = onOut = onErr = onExit = null;
          });
        } else {
          cb(null, proc.stdout, proc.stderr, cmd);
        }
        return self;
        function cb(err2, stdout2, stderr2, cmd2) {
          if (cb.called) return;
          if (timeoutId) clearTimeout(timeoutId);
          cb.called = 1;
          if (args2[0] !== "identify" && bin !== "identify") {
            self._in = [];
            self._out = [];
          }
          callback.call(self, err2, stdout2, stderr2, cmd2);
        }
        function dispose(msg) {
          const message = msg ? msg : "gm() was disposed";
          const err2 = new Error(message);
          cb(err2);
          if (proc.exitCode === null) {
            proc.stdin.pause();
            proc.kill();
          }
        }
      };
      proto.args = function args2() {
        var outname = this.outname || "-";
        if (this._outputFormat) outname = this._outputFormat + ":" + outname;
        return [].concat(
          this._subCommand,
          this._in,
          this.src(),
          this._out,
          outname
        ).filter(Boolean);
      };
      proto.addSrcFormatter = function addSrcFormatter(formatter) {
        if ("function" != typeof formatter)
          throw new TypeError("sourceFormatter must be a function");
        this._sourceFormatters || (this._sourceFormatters = []);
        this._sourceFormatters.push(formatter);
        return this;
      };
      proto.src = function src() {
        var arr = [];
        for (var i = 0; i < this._sourceFormatters.length; ++i) {
          this._sourceFormatters[i].call(this, arr);
        }
        return arr;
      };
      var types = {
        "jpg": /\.jpe?g$/i,
        "png": /\.png$/i,
        "gif": /\.gif$/i,
        "tiff": /\.tif?f$/i,
        "bmp": /(?:\.bmp|\.dib)$/i,
        "webp": /\.webp$/i
      };
      types.jpeg = types.jpg;
      types.tif = types.tiff;
      types.dib = types.bmp;
      proto.inputIs = function inputIs(type) {
        if (!type) return false;
        var rgx = types[type];
        if (!rgx) {
          if ("." !== type[0]) type = "." + type;
          rgx = new RegExp("\\" + type + "$", "i");
        }
        return rgx.test(this.source);
      };
      proto.addDisposer = function addDisposer(emitter, events) {
        if (!this._options.disposers) {
          this._options.disposers = [];
        }
        this._options.disposers.push({
          emitter,
          events
        });
        return this;
      };
    };
  }
});

// node_modules/gm/lib/compare.js
var require_compare = __commonJS({
  "node_modules/gm/lib/compare.js"(exports2, module2) {
    var spawn = require_cross_spawn();
    var debug = require_src()("gm");
    var utils = require_utils2();
    module2.exports = exports2 = function(proto) {
      function compare(orig, compareTo, options, cb) {
        var isImageMagick = this._options && this._options.imageMagick;
        var appPath = this._options && this._options.appPath || "";
        var args = ["-metric", "mse", orig, compareTo];
        let bin;
        switch (isImageMagick) {
          case true:
            bin = "compare";
            break;
          case "7+":
            bin = "magick";
            args.unshift("compare");
            break;
          default:
            bin = "gm";
            args.unshift("compare");
            break;
        }
        bin = appPath + bin;
        var tolerance = 0.4;
        if (typeof options === "object") {
          if (options.highlightColor && options.highlightColor.indexOf('"') < 0) {
            options.highlightColor = '"' + options.highlightColor + '"';
          }
          if (options.file) {
            if (typeof options.file !== "string") {
              throw new TypeError("The path for the diff output is invalid");
            }
            if (options.highlightColor) {
              args.push("-highlight-color");
              args.push(options.highlightColor);
            }
            if (options.highlightStyle) {
              args.push("-highlight-style");
              args.push(options.highlightStyle);
            }
            if (!isImageMagick) {
              args.push("-file");
            }
            args.push(options.file);
          }
          if (typeof options.tolerance != "undefined") {
            if (typeof options.tolerance !== "number") {
              throw new TypeError("The tolerance value should be a number");
            }
            tolerance = options.tolerance;
          }
        } else {
          if (isImageMagick) {
            args.push("null:");
          }
          if (typeof options == "function") {
            cb = options;
          } else {
            tolerance = options;
          }
        }
        var cmd = bin + " " + args.map(utils.escape).join(" ");
        debug(cmd);
        var proc = spawn(bin, args);
        var stdout = "";
        var stderr = "";
        proc.stdout.on("data", function(data) {
          stdout += data;
        });
        proc.stderr.on("data", function(data) {
          stderr += data;
        });
        proc.on("close", function(code) {
          if (isImageMagick) {
            if (code === 0) {
              return cb(null, 0 <= tolerance, 0, stdout);
            } else if (code === 1) {
              stdout = stderr;
            } else {
              return cb(stderr);
            }
          } else {
            if (code !== 0) {
              return cb(stderr);
            }
          }
          var regex = isImageMagick ? /\((\d+\.?[\d\-\+e]*)\)/m : /Total: (\d+\.?\d*)/m;
          var match = regex.exec(stdout);
          if (!match) {
            return cb(new Error("Unable to parse output.\nGot " + stdout));
          }
          var equality = parseFloat(match[1]);
          cb(null, equality <= tolerance, equality, stdout, orig, compareTo);
        });
      }
      if (proto) {
        proto.compare = compare;
      }
      return compare;
    };
  }
});

// node_modules/gm/lib/composite.js
var require_composite = __commonJS({
  "node_modules/gm/lib/composite.js"(exports2, module2) {
    module2.exports = exports2 = function(proto) {
      proto.composite = function(other, mask) {
        this.in(other);
        if (typeof mask !== "undefined")
          this.out(mask);
        this.subCommand("composite");
        return this;
      };
    };
  }
});

// node_modules/gm/lib/montage.js
var require_montage = __commonJS({
  "node_modules/gm/lib/montage.js"(exports2, module2) {
    module2.exports = exports2 = function(proto) {
      proto.montage = function(other) {
        this.in(other);
        this.subCommand("montage");
        return this;
      };
    };
  }
});

// node_modules/gm/package.json
var require_package = __commonJS({
  "node_modules/gm/package.json"(exports2, module2) {
    module2.exports = {
      name: "gm",
      description: "GraphicsMagick and ImageMagick for node.js",
      version: "1.25.0",
      author: "Aaron Heckmann <aaron.heckmann+github@gmail.com>",
      keywords: [
        "graphics",
        "magick",
        "image",
        "graphicsmagick",
        "imagemagick",
        "gm",
        "convert",
        "identify",
        "compare"
      ],
      engines: {
        node: ">=14"
      },
      bugs: {
        url: "http://github.com/aheckmann/gm/issues"
      },
      licenses: [
        {
          type: "MIT",
          url: "http://www.opensource.org/licenses/mit-license.php"
        }
      ],
      main: "./index",
      scripts: {
        security: "npm audit",
        test: "npm run security && npm run test-integration",
        "test-integration": "node test/ --integration",
        "test-unit": "node test/"
      },
      repository: {
        type: "git",
        url: "https://github.com/aheckmann/gm.git"
      },
      license: "MIT",
      devDependencies: {
        async: "~0.9.0"
      },
      dependencies: {
        "array-parallel": "~0.1.3",
        "array-series": "~0.1.5",
        "cross-spawn": "^4.0.0",
        debug: "^3.1.0"
      }
    };
  }
});

// node_modules/gm/index.js
var require_gm = __commonJS({
  "node_modules/gm/index.js"(exports2, module2) {
    var Stream = require("stream").Stream;
    var EventEmitter = require("events").EventEmitter;
    var util = require("util");
    util.inherits(gm2, EventEmitter);
    function gm2(source, height, color) {
      var width;
      if (!(this instanceof gm2)) {
        return new gm2(source, height, color);
      }
      EventEmitter.call(this);
      this._options = {};
      this.options(this.__proto__._options);
      this.data = {};
      this._in = [];
      this._out = [];
      this._outputFormat = null;
      this._subCommand = "convert";
      if (source instanceof Stream) {
        this.sourceStream = source;
        source = height || "unknown.jpg";
      } else if (Buffer.isBuffer(source)) {
        this.sourceBuffer = source;
        source = height || "unknown.jpg";
      } else if (height) {
        width = source;
        source = "";
        this.in("-size", width + "x" + height);
        if (color) {
          this.in("xc:" + color);
        }
      }
      if (typeof source === "string") {
        var frames = source.match(/(\[.+\])$/);
        if (frames) {
          this.sourceFrames = source.substr(frames.index, frames[0].length);
          source = source.substr(0, frames.index);
        }
      }
      this.source = source;
      this.addSrcFormatter(function(src) {
        var inputFromStdin = this.sourceStream || this.sourceBuffer;
        var ret = inputFromStdin ? "-" : this.source;
        const fileNameProvied = typeof height === "string";
        if (inputFromStdin && fileNameProvied && /\.ico$/i.test(this.source)) {
          ret = `ico:-`;
        }
        if (ret && this.sourceFrames) ret += this.sourceFrames;
        src.length = 0;
        src[0] = ret;
      });
    }
    var parent = gm2;
    gm2.subClass = function subClass(options) {
      function gm3(source, height, color) {
        if (!(this instanceof parent)) {
          return new gm3(source, height, color);
        }
        parent.call(this, source, height, color);
      }
      gm3.prototype.__proto__ = parent.prototype;
      gm3.prototype._options = {};
      gm3.prototype.options(options);
      return gm3;
    };
    require_options()(gm2.prototype);
    require_getters()(gm2);
    require_args()(gm2.prototype);
    require_drawing()(gm2.prototype);
    require_convenience()(gm2.prototype);
    require_command2()(gm2.prototype);
    require_compare()(gm2.prototype);
    require_composite()(gm2.prototype);
    require_montage()(gm2.prototype);
    module2.exports = exports2 = gm2;
    module2.exports.utils = require_utils2();
    module2.exports.compare = require_compare()();
    module2.exports.version = require_package().version;
  }
});

// src/index.ts
var index_exports = {};
__export(index_exports, {
  run: () => run
});
module.exports = __toCommonJS(index_exports);
var core2 = __toESM(require_core());

// src/images.ts
var import_gm = __toESM(require_gm());
var fs2 = __toESM(require("fs"));
var path2 = __toESM(require("path"));

// src/utils.ts
var fs = __toESM(require("fs"));
var path = __toESM(require("path"));
var core = __toESM(require_core());
var ensureDir = async (dir) => {
  return fs.promises.mkdir(dir, { recursive: true });
};
var timePromise = async (label, promise) => {
  console.time(label);
  await promise;
  console.timeEnd(label);
};
var listEntries = (groupName, items) => {
  core.startGroup(`${groupName} (${items.length} entries)`);
  items.forEach((item) => {
    core.info(`- "${item}"`);
  });
  return core.endGroup();
};

// src/images.ts
var variants = {
  full: [1920, 1080],
  medium: [512, void 0],
  thumbnail: [200, void 0]
};
var variantDirs = {
  jpg: {
    full: "full",
    medium: "medium",
    thumbnail: "thumbnail"
  },
  webp: {
    full: "webp/full",
    medium: "webp/medium",
    thumbnail: "webp/thumbnail"
  }
};
var ImageService = class {
  buildDir;
  constructor(buildDir) {
    this.buildDir = buildDir;
  }
  resizeImage(image, destPath, [w, h]) {
    console.log("writing path", destPath);
    return new Promise((resolve2, reject) => {
      (0, import_gm.default)(image).resize(w, h, "!").noProfile().write(destPath, (err) => {
        if (err) return reject(err);
        return resolve2(destPath);
      });
    });
  }
  removeImage(srcImage) {
    return Promise.all([
      this.removeImageFormat(srcImage, "jpg" /* JPG */),
      this.removeImageFormat(srcImage, "webp" /* WEBP */)
    ]);
  }
  removeImageFormat(srcImage, format) {
    return Promise.all([
      this.removeImageVariant(srcImage, format, "full" /* Full */),
      this.removeImageVariant(srcImage, format, "medium" /* Medium */),
      this.removeImageVariant(srcImage, format, "thumbnail" /* Thumbnail */)
    ]);
  }
  removeImageVariant(srcImage, format, variant) {
    const destDir = path2.join(this.buildDir, variantDirs[format][variant], srcImage.map);
    const destImage = path2.join(destDir, `${srcImage.name}.${format}`);
    console.log("removing path", path2.resolve(destImage));
    console.log("image exists?", fs2.existsSync(path2.resolve(destImage)));
    return fs2.promises.rm(path2.resolve(destImage), { force: true });
  }
  generateImage(srcImage) {
    return Promise.all([
      this.generateImageFormat(srcImage, "jpg" /* JPG */),
      this.generateImageFormat(srcImage, "webp" /* WEBP */)
    ]);
  }
  generateImageFormat(srcImage, format) {
    return Promise.all([
      this.generateImageVariant(srcImage, format, "full" /* Full */),
      this.generateImageVariant(srcImage, format, "medium" /* Medium */),
      this.generateImageVariant(srcImage, format, "thumbnail" /* Thumbnail */)
    ]);
  }
  async generateImageVariant(srcImage, format, variant) {
    const destDir = path2.join(this.buildDir, variantDirs[format][variant], srcImage.map);
    await ensureDir(destDir);
    const destImage = path2.join(destDir, `${srcImage.name}.${format}`);
    const dimensions = variants[variant];
    return this.resizeImage(path2.resolve(srcImage.filepath), path2.resolve(destImage), dimensions);
  }
};

// src/index.ts
var run = async () => {
  const srcDir = "images";
  const buildDir = "public";
  const toRemove = [{ map: "bkz_bonus", name: "4", filepath: "images/bkz_bonus/4.jpg" }];
  const toGenerate = [];
  listEntries(
    "To be removed images",
    toRemove.map((f) => `${f.map} - ${f.name}`)
  );
  listEntries(
    "To be generated images",
    toGenerate.map((f) => `${f.map} - ${f.name}`)
  );
  const imageService = new ImageService(buildDir);
  const removeTasks = toRemove.map((image) => {
    return imageService.removeImage(image);
  });
  const generateTasks = toGenerate.map((image) => {
    return imageService.generateImage(image);
  });
  await ensureDir(buildDir);
  await timePromise("Remove images", Promise.all(removeTasks));
  await timePromise("Generate images", Promise.all(generateTasks));
  core2.notice(`Removed ${removeTasks.length} images`);
  core2.notice(`Generated ${generateTasks.length} images`);
};
run().catch((err) => {
  const errMsg = err?.message ?? "Unknown error";
  console.error(errMsg);
  core2.setFailed(`Failed building images: ${errMsg}`);
});
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  run
});
