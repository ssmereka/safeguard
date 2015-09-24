
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
    debug: false,
    mongoose: undefined,
    name: 'seedio-security',
    trace: false
  }
};


/* ************************************************** *
 * ******************** Private Methods
 * ************************************************** */

var validateHashPacketString = function(hashPacketString, text, cb, shouldNotMatch) {
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
        } else if( ! isMatch && ! shouldNotMatch) {
          cb(new Error("Text does not match the hashed value."));
        } else {
          cb();
        }
      });
    }
  });
};

var validateConfigAttributeUpdated = function(attribute, newValue) {
  assert.notEqual(eval('safeguard.config.'+attribute), newValue);
  
  var config = {};
  var split = attribute.split('.');
  if(split.length > 1) {
    config[split[0]] = {};
  }
  
  if(_.isObject(newValue)) {
    eval('config.'+attribute+'='+ JSON.stringify(newValue));
    safeguard.setConfig(config);
    assert.equal(_.isEqual(eval('safeguard.config.'+attribute), newValue), true)
  } else if(_.isString(newValue)) {
    eval('config.'+attribute+'="'+newValue+'"');
    safeguard.setConfig(config);
    assert.equal(eval('safeguard.config.'+attribute), newValue);
  } else {
    eval('config.'+attribute+'='+newValue);
    safeguard.setConfig(config);
    assert.equal(eval('safeguard.config.'+attribute), newValue);
  }
}


/* ************************************************** *
 * ******************** Test Suite
 * ************************************************** */

describe('Safeguard', function() {

  beforeEach(function(done) {
    safeguard.setConfig()
    safeguard.setLog()
    safeguard.setError()
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
          validateHashPacketString(hashPacketString, password, done);
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
          validateHashPacketString(hashPacketString, password, done);
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
          validateHashPacketString(hashPacketString, password, done);
        }
      });
    });

    it('should generate a hash even when text is undefined', function(done) {
      safeguard.hasher(undefined, function(err, hashPacketString) {
        if(err) {
          done(err);
        } else {
          // Validate the hash packet, but the hash values should not match.
          validateHashPacketString(hashPacketString, password, done, true);
        }
      });
    });

    it('should generate a hash even when text is blank', function(done) {
      safeguard.hasher("", function(err, hashPacketString) {
        if(err) {
          done(err);
        } else {
          validateHashPacketString(hashPacketString, password, done, true);
        }
      });
    });

  });
  
  describe('setConfig', function() {

    it('should merge crypto configuration objects', function(done) {
      validateConfigAttributeUpdated('crypto.iterations', 22);
      validateConfigAttributeUpdated('crypto.keyLength', 33);
      validateConfigAttributeUpdated('crypto.saltLength', 5000);
      validateConfigAttributeUpdated('log.error', false);
      validateConfigAttributeUpdated('log.databaseLog', true);
      validateConfigAttributeUpdated('log.debug', true);
      validateConfigAttributeUpdated('log.mongoose', {});
      validateConfigAttributeUpdated('log.name', "Awesome cool cool awesome");
      validateConfigAttributeUpdated('log.trace', true);
      done();
    });

  });

  describe('setLog', function() {

    it('should accept a seedio-log instance', function(done) {
      var log = new (require('seedio-log'))(safeguardConfig.log);
      safeguard.setLog(log);
      assert.deepEqual(log, safeguard.log);
      done();
    });

  });

  describe('setError', function() {

    it('should accept an error instance', function(done) {
      var error =  {
        build: function(message, code) {
          var err = new Error(message);
          return new Error(code + ": " + message);
        }
      };
      safeguard.setError(error);
      assert.deepEqual(error, safeguard.error);
      done();
    });

  });

  describe('hashPacketStringToObject', function() {

    it('should return an error if the hashPacketString is invalid', function(done) {
      var invalidPacketError = "Invalid Hash Packet:  Must be a defined string.  Returning default hash packet.",
        invalidPacketErrorCode = 500;
      
      safeguard.hashPacketStringToObject(undefined, function(err, obj) {
        assert.equal(err.message, invalidPacketError);
        assert.equal(err.status, invalidPacketErrorCode);

        safeguard.hashPacketStringToObject({}, function(err, obj) {
          assert.equal(err.message, invalidPacketError);
          assert.equal(err.status, invalidPacketErrorCode);

          safeguard.hashPacketStringToObject(55, function(err, obj) {
            assert.equal(err.message, invalidPacketError);
            assert.equal(err.status, invalidPacketErrorCode);

            safeguard.hashPacketStringToObject(NaN, function(err, obj) {
              assert.equal(err.message, invalidPacketError);
              assert.equal(err.status, invalidPacketErrorCode);
              
              safeguard.hashPacketStringToObject("", function(err, obj) {
                assert.equal(err.message, invalidPacketError);
                assert.equal(err.status, invalidPacketErrorCode);
                
                safeguard.hashPacketStringToObject(null, function(err, obj) {
                  assert.equal(err.message, invalidPacketError);
                  assert.equal(err.status, invalidPacketErrorCode);
                  
                  done();
                });
              });
            });
          });
        });
      });
    });

    it('should return an error if the hashPacketString has an incorrect number of items', function(done) {
      safeguard.hashPacketStringToObject("a,b,cd", function(err, obj) {
        assert.equal(err.message, "Invalid Hash Packet:  Expected 4 items, but 3 were found.  Returning default hash packet.");
        assert.equal(err.status, 500);

        // More than 4 items is ok because the hash or salt may contain commas.
        safeguard.hashPacketStringToObject("a,b,c,d,e", function(err, obj) {
          assert.equal(err, undefined);

          done();
        });
      });
    });

  });

  describe('compareToHash', function() {

    it('should return false if the text is invalid', function(done) {     
      safeguard.compareToHash(undefined, undefined, function(err, result) {
        assert.equal(err, undefined);
        assert.equal(result, false);

        safeguard.compareToHash({}, undefined, function(err, result) {
          assert.equal(err, undefined);
          assert.equal(result, false);

          safeguard.compareToHash(65461, undefined, function(err, result) {
            assert.equal(err, undefined);
            assert.equal(result, false);

            safeguard.compareToHash(NaN, undefined, function(err, result) {
              assert.equal(err, undefined);
              assert.equal(result, false);
              
              safeguard.compareToHash("", undefined, function(err, result) {
                assert.equal(err, undefined);
                assert.equal(result, false);
                
                safeguard.compareToHash(null, undefined, function(err, result) {
                  assert.equal(err, undefined);
                  assert.equal(result, false);
                  
                  done();
                });
              });
            });
          });
        });
      });
    });

    it('should return false if hashPacketStringToObject errors', function(done) {
      safeguard.compareToHash("abcde", undefined, function(err, result) {
        assert.notEqual(err, undefined);
        assert.equal(result, false);
        done();
      });
    });

  });

});