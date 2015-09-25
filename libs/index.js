/* ************************************************** *
 * ******************** Library Variables
 * ************************************************** */

// Library global variables, to be defined later.
var crypto = require('crypto'),
    seedioLog = require('seedio-log'),
    _ = require('lodash');

// Default configuration object.
var defaultConfig = {
  crypto: {
    defaultPlainTextLength: undefined,
    iterations: 10000, 
    keyLength: 128,
    saltLength: 64
  }
};

// Default seedio-log configuration object.
var defaultLogConfig = {
  error: true,
  databaseLog: false,
  debug: false,
  mongoose: undefined,
  name: 'seedio-security',
  trace: false
}


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

    this.initalizeConfig(config);
    this.setLog(log);
    this.setError(error);

    return this;
  }
};


/* ************************************************** *
 * ******************** Initalize and Set Methods
 * ************************************************** */

/**
 * Initalize safeguard's configuration object to the 
 * default values and apply the settings in the 
 * configuration object.
 * @param {object|undefined} config is a safeguard 
 * configuration object
 */
Safeguard.prototype.initalizeConfig = function(config) {
  if( ! this.config) {
    this.config = JSON.parse(JSON.stringify(defaultConfig));
  }

  if(config) {
    this.setConfig(config);
  }
}

/**
 * Set and apply new configurations for safeguard.
 * Any attribute included in the configuration 
 * object will overwrite the existing attribute.
 *
 * Not passing in any parameters will reset the 
 * configuration object to the default settings.
 *
 * @param {object|undefined} config is a safeguard 
 * configuration object
 */
Safeguard.prototype.setConfig = function(config) {
  if( ! config || ! _.isObject(config)) {
    this.config = JSON.parse(JSON.stringify(defaultConfig));
  } else {
    for(var key in config) {
      for(var subObjectKey in config[key]) {
        this.config[key][subObjectKey] = config[key][subObjectKey];
      }
    }
  }
};

/**
 * Set or configure the safeguard seedio-log object.
 *
 * Passing a value of undefined for both the config
 * and log parameters will reset the log's configurations 
 * to the default values.
 *
 * @param {object|undefined} config is a seedio-log 
 * configuration object.
 * @param {object|undefined} log is a seedio-log instance.
 */
Safeguard.prototype.setLog = function(config, log) {
  if(log) {

    // Set the current log to the new instance.
    this.log = log;
    
    // Apply the configuration object to the logger.
    if(config && _.isObject(config)) {
      for(var key in config) {
        this.log[key] = config[key];
      }
    }
  } else {
    var logConfig = JSON.parse(JSON.stringify(defaultLogConfig));

    // Override any default configurations with the values in 
    // the config parameter.
    if(config && _.isObject(config)) {
      for(var key in config) {
        logConfig[key] = config[key];
      }
    }

    if( ! this.log) {
      this.log = new seedioLog(logConfig);
    } else {
      for(var key in logConfig) {
        this.log[key] = logConfig[key];
      }
    }
  }
};

/**
 * Set or configure the safeguard error object.
 * The error object is used to build and display
 * errors that occur in safeguard.
 *
 * Passing a value of undefined for the error
 * object will reset the error object to the 
 * default. 
 *
 * @param {object|undefined} error is an object
 * with methods related to building error objects.
 */
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
 * ******************** Public API
 * ************************************************** */

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
  if( ! text || ! _.isString(text)) {
    if(safeguard.config.crypto.defaultPlainTextLength) {
      safeguard.log.w('safeguard.hasher():  The text value of "%s" (quotes exclusive) is invalid, defaulting to a random string.', text);
      try {
        text = crypto.randomBytes(safeguard.config.crypto.defaultPlainTextLength);
      } catch(err) {
        return cb(err);
      }
    } else {
      return cb(safeguard.error.build('The text value of "'+text+'" (quotes exclusive) is invalid and cannot be hashed.', 500));
    }
  }

  // Generate a new salt if one does not exist.
  if( ! hashPacket.salt) {
    try {
      hashPacket.salt = crypto.randomBytes(hashPacket.saltLength/2);
      hashPacket.salt = hashPacket.salt.toString('hex');
    } catch(err) {
      return cb(err);
    }
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
        cb(err, false);
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
  if( ! hashPacketObject || ! _.isObject(hashPacketObject)) {
    return undefined;
  } else {
    return hashPacketObject.keyLength  + ","
         + hashPacketObject.iterations + ","
         + hashPacketObject.saltLength + ","
         + hashPacketObject.salt
         + hashPacketObject.hash;
  }
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
 * configuration object.
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