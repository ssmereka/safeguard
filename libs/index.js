// Library global variables, to be defined later.
var crypto, _;


/* ************************************************** *
 * ******************** Constructor
 * ************************************************** */

/**
 * Constructor to setup and initialize a new or existing
 * instance.
 *
 * @param {object|undefined} config is a seedio configuration object.
 * @param {object|undefined} log is a seedio-log instance.
 * @param {object|undefined} error is a seedio-error instance.
 * @returns {object} the new or current Safeguard instance.
 * @constructor
 */
var Safeguard = function(config, log, error) {
  "use strict";

  // Auto instantiate the module when it is required.
  if(! (this instanceof Safeguard)) {
    return new Safeguard(config, log, error);
  } else {

    this.setConfig(config);
    this.setLog(log);
    this.setError(error);

    // Attempt to load external libraries.
    try {
      _ = require('lodash');
      crypto = require('crypto');
    } catch(err) {
      log.e('Error initializing the local library dependencies.  Do you need to run npm install?');
      throw err;
    }

    return this;
  }
};


/* ************************************************** *
 * ******************** Getters and Setters
 * ************************************************** */

var setConfig = function(config) {
  this.config = config || {
    crypto: {
      iterations: 10000,
      keySize: 64,
      saltSize: 64
    },
    libsDirectory: "./",
    log: {
      error: true,
      databaseLog: false,
      debug: true,
      mongoose: undefined,
      name: 'seedio-security',
      trace: false
    }
  };
};

var setLog = function(log) {
  if(log) {
    this.log = log;
  } else {
    this.log = new (require('seedio-log'))({
      mongoose: mongoose,
      debug: config.log.debug,
      trace: config.log.trace,
      error: config.log.error,
      name: config.server.name,
      databaseLog: config.server.databaseLog});
  }
};

var setError = function(error) {
  if(error) {
    this.error = error;
  } else {
    this.error = {
      build: function(message, code) {
        var err = new Error(message);
        err.status = code || 500;
        return err;
      }
    };
  }
};


/* ************************************************** *
 * ******************** Private Methods
 * ************************************************** */

/**
 * Convert a hash packet object into a string that
 * contains all of the packets information concatenated
 * in a CSV format.
 * @param {object} hashPacketObject is the hash packet object
 * to be converted to a string.
 * @returns {string} the hash packet string.
 */
var hashPacketObjectToString = function(hashPacketObject) {
  return hashPacketObject.keySize + ","
    + hashPacketObject.iterations + ","
    + hashPacketObject.saltSize + ","
    + hashPacketObject.salt
    + hashPacketObject.hash;
};

/**
 * Create a hash packet object from a hash packet csv string.
 * @param {string} hashPacketString is a string that contains
 * all of the hash packet information in a csv format.
 * @param {hashPacketObjectCallback} cb is a callback method
 */
var hashPacketStringToObject = function(hashPacketString, cb) {
  // Create the default object using values from the config file.
  var obj = createDefaultHashPacket();

  // If the hashPacketString is defined, then the hash string values
  // will overwrite the defaults.
  if( ! hashPacketString || ! _.isString(hashPacketString)) {
    cb(error.build("Invalid Hash Packet:  Must be a defined string.  Returning default hash packet.", 500), obj);
  } else {
    var hashPacketItems = hashPacketString.split(','),  // Split the CVS string into an ordered list of items.
      headerLength = 3;  // A counter for the length of the hash header, initialized to include the three commas that exist in the header string.

    // If the hash packet string does not have at least 5
    // items separated by commas then it is invalid.
    if(hashPacketItems.length < 5) {
      cb(error.build("Invalid Hash Packet:  Expected 5 items, but only "+hashPacketItems+" were found.  Returning default hash packet.", 500), obj);
    } else {

      // Key size is the first parameter representing how long the
      // hash value will be.  Remember that since we are storing the
      // hash values as hex, they will actually be double the size.
      obj.keySize = Number(hashPacketItems[0]);
      headerLength += hashPacketItems[0].length;

      // Iterations is the second parameter representing how many
      // rounds to use when hashing.
      obj.iterations = Number(hashPacketItems[1]);
      headerLength += hashPacketItems[1].length;

      // Salt size is the third parameter representing how long the
      // salt value will be.  Remember that since we are storing the
      // salt values as hex, they will actually be double the size.
      obj.saltSize = Number(hashPacketItems[2]);
      headerLength += hashPacketItems[2].length;

      // Salt is the fourth parameter and should be double the length of the salt string length.
      obj.salt = hashPacketString.substring(headerLength, headerLength + (obj.saltSize * 2));

      // Hash is the final parameter and should be double the length of the key string length.
      obj.hash = hashPacketString.substring(headerLength + (obj.keySize * 2));

      cb(undefined, obj);
    }
  }
};

/**
 * Create a default hash packet object using values from the
 * server configuration object.
 * @returns {object} a hash packet object.
 */
var createDefaultHashPacket = function() {
  return {
    hash: '',
    iterations: this.config.crypto.iterations,
    keySize: this.config.crypto.keySize,
    salt: '',
    saltSize: this.config.crypto.saltSize
  };
};

/**
 * Hash a plain text string and return a hack packet string
 * that can be saved or compared to an existing hash.
 * @param {string} text is the plain text to be hashed.
 * @param {hashCallback} cb is a callback method.
 */
var hasher = function(text, cb) {
  // Create a hash packet with the default values.
  var hashPacket = createDefaultHashPacket();

  // If the text is invalid (undefined, null, false, 0, or ""), then create a random string to hash.
  if( ! text) {
    text = createRandomStringSync(this.config.crypto.plainTextSize)
  }

  // Generate a new salt if one does not exist.
  if( ! hashPacket.salt === undefined) {
    hashPacket.salt = createRandomStringSync(hashPacket.saltSize).toString('hex');
  }

  // Hash the plain text using the hashPacket settings.
  crypto.pbkdf2(text, hashPacket.salt, hashPacket.iterations, hashPacket.keySize, function(err, hash) {
    if(err) {
      cb(err);
    } else {
      // Add the hash in hex to the hash packet.
      hashPacket.hash = hash.toString('hex');

      // Return the hash packet as a string.
      cb(undefined, hashPacketObjectToString(hashPacket));
    }
  });
};

/**
 * Compare a plain text string to a hashed string.
 * @param {string} text is the plain text to compare.
 * @param {string} hashPacketString is the hashed string.
 * @param {hashCompareCallback} cb is a callback method.
 */
var compareToHash = function(text, hashPacketString, cb) {
  // If the plain text is invalid, then return false.
  if( ! text) {
    cb(undefined, false);
  } else {
    // Create a hash packet object from the string.
    hashPacketStringToObject(hashPacketString, function(err, hashPacket) {
      if(err) {
        cb(err);
      } else {
        // Encrypt the plain text using the same parameters as the stored hash.
        crypto.pbkdf2(text, hashPacket.salt, hashPacket.iterations, hashPacket.keySize, function(err, hash) {
          if(err || ! hash) {
            cb(err, false);
          } else {
            // Return the hash comparison result.
            cb(undefined, hash.toString('hex') == hashPacket.hash);
          }
        });
      }
    });
  }
};

/**
 * Create a random string of text of the given size.
 * If a length is not defined, the default length will be used.
 * @param {number|undefined} length is the length of the random string.
 * @returns {string} a random string of the given length.
 */
var createRandomStringSync = function(length) {
  var text;
  try {
    text = crypto.randomBytes(length || 256);
  } catch(err) {
    log.e(err);
    text = uuid.v4();
  }

  return text;
};



/* ************************************************** *
 * ******************** Public API
 * ************************************************** */

Safeguard.prototype.hasher = hasher;
Safeguard.prototype.compareToHash = compareToHash;
Safeguard.prototype.createRandomStringSync = createRandomStringSync;

Safeguard.prototype.setLog = setLog;
Safeguard.prototype.setConfig = setConfig;
Safeguard.prototype.setError = setError;

exports = module.exports = Safeguard;
exports = Safeguard;


/* ************************************************** *
 * ******************** Documentation Stubs
 * ************************************************** */

/**
 * The results of hashing a string are returned to this
 * callback method.
 *
 * @callback hashCallback
 * @param {object|undefined} error describes the error that occurred
 * @return {string} the hash packet as a comma separated value string.
 */

/**
 * The results comparing a plain text string to a hashed
 * string are returned to this callback method.
 *
 * @callback hashCompareCallback
 * @param {object|undefined} error describes the error that occurred
 * @return {boolean} whether or not the plain text and hash strings match.
 */

/**
 * The results of converting a possible hash packet object string
 * into a hash packet object are returned to this callback method.
 *
 * @callback hashPacketObjectCallback
 * @param {object|undefined} error describes the error that occurred
 * @return {object} the hash packet object.
 */