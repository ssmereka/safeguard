# Safeguard

<a href="https://nodei.co/npm/safeguard/" target="_blank"><img src="https://nodei.co/npm/safeguard.png?downloads=true&downloadRank=true"></a>

<a href="https://travis-ci.org/ssmereka/safeguard" target="_blank"><img src="https://travis-ci.org/ssmereka/safeguard.svg" /></a> <a href="https://david-dm.org/ssmereka/safeguard" target="_blank"><img src="https://david-dm.org/ssmereka/safeguard.svg" /></a> <a href="https://gratipay.com/ScottSmereka/" target="_blank"><img src="http://img.shields.io/gratipay/ScottSmereka.svg" /> <a href="https://codecov.io/github/ssmereka/safeguard?branch=master" target="_blank"><img src="https://codecov.io/github/ssmereka/safeguard/coverage.svg?branch=master" /></a>

Safeguard makes hashing with crypto easier and more convenient.
 
## Easier
Safeguard takes care of the cryptography settings so the API is simple.

```javascript
var safeguard = require('safeguard');

// Hash some text
safeguard.hasher(text, function(err, hash) {
  // Do some things and stuff...
});

// Compare some text to the hash
safeguard.compareToHash(text, hash, function(err, isMatch) {
  // Do some things and stuff...
});
```

## Convenient
The crypto settings and salt are encapsulated within each hash so you don't have to manage them.  Unlike in crypto where you have to define them each time.

```javascript
// Ewww... Yuk... Gross...
crypto.pbkdf2(password, salt, iterations, keySize, function(err, hash) {
  // Do some things and stuff...
}
```

Since every hash string contains the settings used to create it you can change the default crypto settings at anytime without having to worry about tracking the old settings for previously hashed values.


<a href="gettingStarted" />
# Getting Started

Install Safeguard using npm and save it as a dependency in your package.json.

```javascript
npm install safeguard --save
```

You can require Safeguard just like every other node.js module.

```javascript
var safeguard = require('safeguard');
```

# API

## compareToHash
Compare a hash value (created by safeguard) to a plain text string.

| Parameter | Type | Description |
| --------- | ---- | ----------- |
| text | String | The plain text to compare to the hash |
| hash | String | The hash to compare the plain text to |
| cb | Method | A callback method that accepts an error and the boolean result of the comparison |

```javascript
safeguard.compareToHash(text, hash, function(err, isMatch) {
  // Do some things and stuff...
});
```

## hasher
Hash a plain text string.

| Parameter | Type | Description |
| --------- | ---- | ----------- |
| text | String | The plain text to hash |
| cb | Method | A callback method that accepts an error and the hash string value |

```javascript
safeguard.hasher(text, function(err, hash) {
  // Do some things and stuff...
});
```

# Constructor and Setters
You can configure Safeguard with the following attributes by passing them into the constructor or using the setter methods.

## Constructor
The constructor accepts the following parameters:

| Parameter | Type | Description |
| --------- | ---- | ----------- |
| config | Object | Any configuration that will override the default behavior. |
| log | Object | A seedio-log instance. |
| error | Object | An error instance that contains methods to build errors produced by safeguard. |

Example of how you might use each parameter:

```javascript
var config = {
  iterations: 20000,
  keyLength: 256
};

var log = require('seedio-log')({
  databaseLog: true,
  mongoose: require('mongoose'),
  name: 'MyAppName'
});

var error = {
  build: function(message, code) {
    var err = new Error(message);
    err.status = code || 400;
    return err;
  }
}

var safeguard = require(safeguard)(config, log, error);
```

## setLog
Configure or pass in a [seedio-log](https://github.com/livio/seedio-log) reference.  See the [seedio-log](https://github.com/livio/seedio-log) github for documentation.

| Parameter | Type | Description |
| --------- | ---- | ----------- |
| config | Object | Any configuration that will override the default behavior. |
| log | Object | A seedio-log instance. |
| error | Object | An error instance that contains methods to build errors produced by safeguard. |

Example of configuring the default log:

```javascript
var safeguard = require('safeguard');

safeguard.setLog({ error: false });
```

Example of passing in an existing log reference.

```
var safeguard = require('safeguard');

var log = require('seedio-log')({
  databaseLog: true,
  mongoose: require('mongoose'),
  name: 'MyAppName'
});

safeguard.setLog(undefined, log);
```## setError
You can override the default error message building function.  By default all errors contain an HTTP error code in the status attribute.

```javascript
var safeguard = require('safeguard');

var error = {
  build: function(message, code) {
    var err = new Error(message);
    err.status = code || 500;
    return err;
  }
}

safeguard.setError(error);

```

## setConfig
Configure safeguard by overriding the default configuration object.

```javascript
var safeguard = require('safeguard');

safeguard.setConfig({ crypto: { iterations: 20000 } });
```

### Configuration Object
The following attributes can be included in the configuration object to override the default behavior of Safeguard.

| Parameter | Type | Default | Description |
| --------- | ---- | ------- | ----------- |
| crypto | Object | n/a | Settings related to the node.js crypto library. |
| crypto.defaultPlainTextLength | Number | undefined | When defined and an invalid string is hashed using the hasher, a random string of the specified size will be generated. |
| crypto.iterations | Number | 10,000 | Number of times crypto iterates while hashing. |
| crypto.keyLength | Number | 128 | Length of the text's hash value. |
| crypto.saltLength | Number | 64 | Length of the hash's salt. |

**Note:**  Choose iterations to satisfy the formula [v-2^(n-1) > f-p](http://goo.gl/tPVs1M)


## Example Default Config
```javascript
{
  crypto: {
    defaultPlainTextLength: undefined,
    iterations: 10000,
    keyLength: 64,
    saltLength: 64
  }
}
  ```