
/* ************************************************** *
 * ******************** Private Variables
 * ************************************************** */

var assert = require("assert"),
    safeguard = require('../../libs/index.js')(),
    fs = require("fs"),
    path = require("path"),
    should = require("should"),
    _ = require("lodash");

var password = "my password string";

var safeguardConfig = {
  crypto: {
    iterations: 10000,
    keyLength: 64,
    saltLength: 64
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


/* ************************************************** *
 * ******************** Private Methods
 * ************************************************** */

var validateHashPacketString = function(hashPacketString, text, cb) {
  // Should be a valid string.
  assert.equal( ! hashPacketString && _.isString(hashPacketString), false);

  // Should contain 4 parts
  var hashPacketStringArray = hashPacketString.split(',');
  assert.equal(hashPacketStringArray.length, 4)

  // Should be converted to a hash packet object without error.
  safeguard.hashPacketStringToObject(hashPacketString, function(err, obj) {
    if(err) {
      cb(err);
    } else {
      // Key Size should be the first and expected value.
      assert.equal(hashPacketStringArray[0], safeguard.config.crypto.keyLength);

      // Iteration should be the second and expected value.
      assert.equal(hashPacketStringArray[1], safeguard.config.crypto.iterations);

      // Salt Size should be third and expected value.
      assert.equal(hashPacketStringArray[2], safeguard.config.crypto.saltLength);
      
      // Salt+Hash should be greater than the expected length of the salt.
      assert.equal( ! hashPacketStringArray[3], false);
      assert.equal(hashPacketStringArray[3].length > hashPacketStringArray[2], true);

      safeguard.compareToHash(text, hashPacketString, function(err, isMatch) {
        if(err) {
          cb(err);
        } else if( ! isMatch) {
          cb(new Error("Text does not match the hashed value."));
        } else {
          cb();
        }
      });
    }
  });
};


/* ************************************************** *
 * ******************** Test Suite
 * ************************************************** */

describe('Safeguard', function() {

  beforeEach(function(done) {
    safeguard.setConfig(safeguardConfig)
    done();
  });

  describe('hasher', function() {
    
    it('should return a valid hash packet as a string', function(done) {
      safeguard.hasher(password, function(err, hashPacketString) {
        if(err) {
          done(err);
        } else {
          validateHashPacketString(hashPacketString, password, done);
        }
      });
    });


    it('should work with variable key size', function(done) {
      var newSize = 128,
        config = JSON.parse(JSON.stringify(safeguardConfig));
      
      // Make sure the new size different, then update the config.
      assert.notEqual(config.crypto.keyLength, newSize);
      config.crypto.keyLength = newSize;
      safeguard.setConfig(config);
      assert.equal(safeguard.config.crypto.keyLength, newSize);

      safeguard.hasher(password, function(err, hashPacketString) {
        if(err) {
          done(err);
        } else {
          validateHashPacketString(hashPacketString, password, done, config.crypto);
        }
      });
    });

    it('should work with variable salt size', function(done) {
      var newSize = 128,
        config = JSON.parse(JSON.stringify(safeguardConfig));
      
      // Make sure the new size different, then update the config.
      assert.notEqual(config.crypto.saltLength, newSize);
      config.crypto.saltLength = newSize;
      safeguard.setConfig(config);
      assert.equal(safeguard.config.crypto.saltLength, newSize);

      safeguard.hasher(password, function(err, hashPacketString) {
        if(err) {
          done(err);
        } else {
          validateHashPacketString(hashPacketString, password, done, config.crypto);
        }
      });
    });

    it('should work with variable iteration size', function(done) {
      var newSize = 50000,
        config = JSON.parse(JSON.stringify(safeguardConfig));
      
      // Make sure the new size different, then update the config.
      assert.notEqual(config.crypto.iterations, newSize);
      config.crypto.iterations = newSize;
      safeguard.setConfig(config);
      assert.equal(safeguard.config.crypto.iterations, newSize);

      safeguard.hasher(password, function(err, hashPacketString) {
        if(err) {
          done(err);
        } else {
          validateHashPacketString(hashPacketString, password, done, config.crypto);
        }
      });
    });

  });
  
});