# Safeguard

<a href="https://nodei.co/npm/safeguard/" target="_blank"><img src="https://nodei.co/npm/safeguard.png?downloads=true&downloadRank=true"></a>

<a href="https://travis-ci.org/ssmereka/safeguard" target="_blank"><img src="https://travis-ci.org/ssmereka/safeguard.svg" /></a> <a href="https://david-dm.org/ssmereka/safeguard" target="_blank"><img src="https://david-dm.org/ssmereka/safeguard.svg" /></a> <a href="https://gratipay.com/ScottSmereka/" target="_blank"><img src="http://img.shields.io/gratipay/ScottSmereka.svg" /> <a href="https://codecov.io/github/ssmereka/safeguard?branch=master" target="_blank"><img src="https://codecov.io/github/ssmereka/safeguard/coverage.svg?branch=master" /></a>

# WAT?
Safeguard makes cryptography easier in node.js by adding helpful functionality and simplifying the already existing [Cryto](https://nodejs.org/api/crypto.html) library.

## Example
Let's compare hashing a password in Cryto vs safeguard.

In Crypto you include several configuration values each time you want to hash a string.  You need to keep track of all of these values individually for each hashed string.  

```javascript
crypto.pbkdf2(password, salt, iterations, keySize, function(err, hash) {
  // Do some things and stuff...
}
```

In Safeguard all of these configurations are preconfigured and stored along with the calculated hash.  No need to worry about keeping track of anything, just store the hash.

```javascript
safeguard.hasher(password, function(err, hash) {
  // Do some things and stuff...
});
```


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
| cb | Method | A callback method that accepts an error and the result of the comparison |

```javascript
security.compareToHash(text, hash, function(err, isMatch) {
  // Do some things and stuff...
});
```

## hasher
Hash a plain text string

| Parameter | Type | Description |
| --------- | ---- | ----------- |
| text | String | The plain text to hash |
| cb | Method | A callback method that accepts an error and the hash value |

```javascript
safeguard.hasher(text, function(err, hash) {
  // Do some things and stuff...
});
```

# Constructor and Setters
You can configure Safeguard with the following attributes by passing them into the constructor or using the setter methods.

## Constructor

| Parameter | Type | Description |
| --------- | ---- | ----------- |
| config | Object |  |
| log | Object |  |
| error | Object |  |

```javascript
var safeguard = require(safeguard)(config, log, error),
```

## setLog
Safeguard uses [seedio-log](https://github.com/livio/seedio-log).

```javascript
safeguard.setLog(require('seedio-log'));
```

## setConfig

## setError
You can override the default error message building function.  By default all errors contain an HTTP error code in the status attribute.

```javascript
var error = {
  build: function(message, code) {
    var err = new Error(message);
    err.status = code || 500;
    return err;
  }
}

safeguard.setError(error);

```

# Configuration Object
The following attributes can be included in the configuration object to override the default behavior of Safeguard.

| Parameter | Type | Default | Description |
| --------- | ---- | ------- | ----------- |
| crypto | Object | n/a | Settings related to the node.js crypto library. |
| crypto.iterations | Object | 10,000 | Number of times crypto iterates while hashing. |
| crypto.keyLength | Object | 128 | Length of the text's hash value. |
| crypto.saltLength | Object | 64 | Length of the hash's salt. |
| log | Object | n/a | Settings related to the logger, [seedio-log](https://github.com/livio/seedio-log) |
| log.error | Boolean | true | When true, error logs are displayed by the logger. |
| log.databaseLog | Boolean | false | When true, logs are sent to the mongoose database. |
| log.debug | Boolean | false | When true, debug logs are displayed by the logger. |
| log.mongoose | Object | undefined | Stores a reference to your current mongoose object. |
| log.name | String | "Safeguard" | Name used in logs by the logger. |
| log.trace | Boolean | false | When true, trace logs are displayed by the logger. |

**Note:**  Choose iterations to satisfy the formula [v-2^(n-1) > f-p](http://goo.gl/tPVs1M)


## Example Default Config
```javascript
{
  crypto: {
    iterations: 10000,
    keyLength: 64,
    saltLength: 64
  },
  log: {
    error: true,
    databaseLog: false,
    debug: false,
    mongoose: undefined,
    name: 'Safeguard',
    trace: false
  }
}
  ```