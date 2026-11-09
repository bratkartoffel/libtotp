# TOTP code (RFC 6238) verification for java

[![Java CI](https://github.com/bratkartoffel/libtotp/actions/workflows/build.yaml/badge.svg)](https://github.com/bratkartoffel/libtotp/actions/workflows/build.yaml)
[![codecov](https://codecov.io/gh/bratkartoffel/libtotp/branch/develop/graph/badge.svg?token=QgUmkgHSMd)](https://codecov.io/gh/bratkartoffel/libtotp)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](http://doge.mit-license.org)
[![Central Version](https://img.shields.io/maven-central/v/eu.fraho.libs/libtotp)](https://mvnrepository.com/artifact/eu.fraho.libs/libtotp)

Providing a simple way to integrate [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) conforming TOTP codes in your
application.

This library was designed to be easy to use, lean (no external dependencies), secure and performant.

# Dependencies

```xml
<!-- https://mvnrepository.com/artifact/eu.fraho.libs/libtotp -->
<dependency>
    <groupId>eu.fraho.libs</groupId>
    <artifactId>libtotp</artifactId>
    <version>1.2.0</version>
</dependency>
```

# Usage

```java
import eu.fraho.libs.totp.*;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public class Example {
    // default settings (sha1, 6 digits, allow clock screw of +- 90 seconds)
    private final Totp totp = new Totp(TotpSettings.DEFAULT);
    // map to cache the last used totp counters, prevent replay attacks
    private final Map<Long, AtomicLong> lastTotpCounters = new HashMap<>();

    public static void main(String[] args) {
        Example testee = new Example();

        // the code to verify
        int code = Integer.parseInt(args.length > 0 ? args[0] : "520489");

        // get the shared secret key
        byte[] secret = "12345678901234567890".getBytes(StandardCharsets.UTF_8);

        // first try => should succeed
        System.out.println("First: " + testee.doLogin(1, secret, code));
        // replay attack if first succeeded
        System.out.println("Second: " + testee.doLogin(1, secret, code));
        // another user => should succeed again
        System.out.println("First: " + testee.doLogin(2, secret, code));
    }

    public boolean doLogin(long userId, byte[] secret, int code) {
        try {
            // use a fixed counter (time window) for this example to work
            // omit the last parameter on production!
            long counter = totp.verifiedCounter(secret, code, 10);
            // code is valid, lets check for replay attack
            AtomicLong lastUsedCounter = lastTotpCounters.computeIfAbsent(userId, k -> new AtomicLong());
            // get the last successfully verified counter
            long value = lastUsedCounter.get();
            // the used code is later than the cached counter => update, all good
            if(counter > value) {
                // atomically update the counter, only return success if the value wasn't updated in the meantime
                return lastUsedCounter.compareAndSet(value, counter);
            }
            // possible replay attack
            System.out.println("Replay attack detected, denying access");
            return false;
        } catch (InvalidCodeException e) {
            // code is invalid!
            System.out.println("Invalid code given, denying access");
            return false;
        }
    }
}
```

## Configuration

The parameters can be configured using the `TotpSettings`. This class is implemented using the builder-Pattern and
provides the following options:

```java
public class Example {
    public static TotpSettings createSettings() {
        TotpSettings.builder()
                .hmac("HmacSHA1")
                .secretLength(20)
                .tokenLength(6)
                .variance(3)
                .build();
    }
}
```

| Setting      | Default  | Reasonable values                | Description                                                                          |
|--------------|----------|----------------------------------|--------------------------------------------------------------------------------------|
| hmac         | HmacSHA1 | HmacSHA1, HmacSHA256, HmacSHA512 | HMAC algorithm to use                                                                |
| secretLength | 20       | &gt; 16                          | Defines the length of newly generated secrets                                        |
| tokenLength  | 6        | 6 - 8                            | Length of the generated codes                                                        |
| variance     | 3        | 0 - 3                            | Defines the allowed clock time differences for verifications, as +- 30 seconds steps |

# Hacking

* This repository uses the git flow layout
* Changes are welcome, but please use pull requests with separate branches
* Github workflow has to pass before merging
* Code coverage should stay about the same level (please write tests for new features!)

# Releasing

Releasing is done with the default gradle tasks:

```bash
# to local repository:
./gradlew publishToMavenLocal
# to central:
./gradlew publish
```
