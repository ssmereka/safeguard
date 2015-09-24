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

Safeguard.prototype.setConfig = function(config) {
  if( ! this.config) {
    this.config = {
      crypto: {
        iterations: 10000, 
        keyLength: 128,
        saltLength: 64
      },
      log: {
        error: true,
        databaseLog: false,
        debug: false,
        mongoose: undefined,
        name: 'seedio-security',
        trace: false
      } 
    };
  }

  if(config) {
    if(config.crypto) {
      this.config.crypto = {
        iterations: config.crypto.iterations || this.config.crypto.iterations,
        keyLength: config.crypto.keyLength || this.config.crypto.keyLength,
        saltLength: config.crypto.saltLength || this.config.crypto.saltLength
      }
    }

    if(config.log) {
      this.config.log = {
        error: (config.log.error === true || config.log.error === false) ? config.log.error : this.config.log.error,
        databaseLog: (config.log.databaseLog === true || config.log.databaseLog === false) ? config.log.databaseLog : this.config.log.databaseLog,
        debug: (config.log.debug === true || config.log.debug === false) ? config.log.debug : this.config.log.debug,
        mongoose: config.log.mongoose || this.config.log.mongoose,
        name: config.log.name || this.config.log.name,
        trace: (config.log.trace === true || config.log.trace === false) ? config.log.trace : this.config.log.trace,
      }
    }
  }
};

Safeguard.prototype.setLog = function(log) {
  if(log) {
    this.log = log;
  } else {
    var seedioLog;
    try {
      seedioLog = require('seedio-log');
      this.log = new (seedioLog)({
        mongoose: this.config.log.mongoose,
        debug: this.config.log.debug,
        trace: this.config.log.trace,
        error: this.config.log.error,
        name: this.config.name,
        databaseLog: this.config.databaseLog});
    } catch(err) {
      console.log('Error initializing the local library dependencies.  Do you need to run npm install?');
      throw err;
    }
  }
};

Safeguard.prototype.setError = function(error) {
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
Safeguard.prototype.hashPacketObjectToString = function(hashPacketObject) {
  return hashPacketObject.keyLength + ","
    + hashPacketObject.iterations + ","
    + hashPacketObject.saltLength + ","
    + hashPacketObject.salt
    + hashPacketObject.hash;
};

/**
 * Create a hash packet object from a hash packet csv string.
 * @param {string} hashPacketString is a string that contains
 * all of the hash packet information in a csv format.
 * @param {hashPacketObjectCallback} cb is a callback method
 */
Safeguard.prototype.hashPacketStringToObject = function(hashPacketString, cb) {
  var safeguard = this;

  // Create the default object using values from the config file.
  var obj = safeguard.createDefaultHashPacket();

  // If the hashPacketString is defined, then the hash string values
  // will overwrite the defaults.
  if( ! hashPacketString || ! _.isString(hashPacketString)) {
    cb(safeguard.error.build("Invalid Hash Packet:  Must be a defined string.  Returning default hash packet.", 500), obj);
  } else {
    var hashPacketItems = hashPacketString.split(','),  // Split the CVS string into an ordered list of items.
      headerLength = 3;  // A counter for the length of the hash header, initialized to include the three commas that exist in the header string.

    // If the hash packet string does not have at least 4
    // items separated by commas then it is invalid.
    if(hashPacketItems.length < 4) {
      cb(safeguard.error.build("Invalid Hash Packet:  Expected 4 items, but "+hashPacketItems.length+" were found.  Returning default hash packet.", 500), obj);
    } else {

      // Key length is the first parameter representing how long the
      // hash value will be.  Remember that since we are storing the
      // hash values as hex, they will actually be double the size.
      obj.keyLength = Number(hashPacketItems[0]);
      headerLength += hashPacketItems[0].length;

      // Iterations is the second parameter representing how many
      // rounds to use when hashing.
      obj.iterations = Number(hashPacketItems[1]);
      headerLength += hashPacketItems[1].length;

      // Salt length is the third parameter representing how long the
      // salt value will be.  Remember that since we are storing the
      // salt values as hex, they will actually be double the size.
      obj.saltLength = Number(hashPacketItems[2]);
      headerLength += hashPacketItems[2].length;

      // Salt is the fourth parameter and should be double the length of the salt string length.
      obj.salt = hashPacketString.substring(headerLength, headerLength + obj.saltLength);

      // Hash is the final parameter and should be double the length of the key string length.
      obj.hash = hashPacketString.substring(headerLength + obj.saltLength);

      cb(undefined, obj);
    }
  }
};

/**
 * Create a default hash packet object using values from the
 * server configuration object.
 * @returns {object} a hash packet object.
 */
Safeguard.prototype.createDefaultHashPacket = function() {
  return {
    hash: '',
    iterations: this.config.crypto.iterations,
    keyLength: this.config.crypto.keyLength,
    salt: '',
    saltLength: this.config.crypto.saltLength
  };
};

/**
 * Hash a plain text string and return a hash packet string
 * that can be saved or compared to an existing hash.
 * @param {string} text is the plain text to be hashed.
 * @param {hashCallback} cb is a callback method.
 */
Safeguard.prototype.hasher = function(text, cb) {
  var safeguard = this;

  // Create a hash packet with the default values.
  var hashPacket = safeguard.createDefaultHashPacket();

  // If the text is invalid (undefined, null, false, 0, or ""), then create a random string to hash.
  if( ! text) {
    text = safeguard.createRandomStringSync(safeguard.config.crypto.plainTextSize)
  }

  // Generate a new salt if one does not exist.
  if( ! hashPacket.salt) {
    hashPacket.salt = safeguard.createRandomStringSync(hashPacket.saltLength/2).toString('hex');
  }

  // Hash the plain text using the hashPacket settings.
  crypto.pbkdf2(text, hashPacket.salt, hashPacket.iterations, hashPacket.keyLength, function(err, hash) {
    if(err) {
      cb(err);
    } else {
      // Add the hash in hex to the hash packet.
      hashPacket.hash = hash.toString('hex');

      // Return the hash packet as a string.
      cb(undefined, safeguard.hashPacketObjectToString(hashPacket));
    }
  });
};

/**
 * Compare a plain text string to a hashed string.
 * @param {string} text is the plain text to compare.
 * @param {string} hashPacketString is the hashed string.
 * @param {hashCompareCallback} cb is a callback method.
 */
Safeguard.prototype.compareToHash = function(text, hashPacketString, cb) {
  // If the plain text is invalid, then return false.
  if( ! text || ! _.isString(text)) {
    cb(undefined, false);
  } else {
    // Create a hash packet object from the string.
    this.hashPacketStringToObject(hashPacketString, function(err, hashPacket) {
      if(err) {
        cb(err);
      } else {
        // Encrypt the plain text using the same parameters as the stored hash.
        crypto.pbkdf2(text, hashPacket.salt, hashPacket.iterations, hashPacket.keyLength, function(err, hash) {
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
Safeguard.prototype.createRandomStringSync = function(length) {
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
 * ******************** Expose the Public API
 * ************************************************** */

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