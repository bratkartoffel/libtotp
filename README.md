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
    <version>1.1.0</version>
</dependency>
```

# Usage

```java
import eu.fraho.libs.totp.*;

import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;

public class Example {
    public static void main(String[] args) {
        // the code to verify
        int code = Integer.parseInt(args[0]);

        // default settings (sha1, 6 digits, allow clock screw of +- 90 seconds)
        Totp testee = new Totp(TotpSettings.DEFAULT);

        // get the shared secret key
        byte[] secret = "sharedSecret".getBytes(StandardCharsets.UTF_8);

        // do the verification using the current time
        if (testee.verifyCode(secret, code)) {
            System.out.println("Now: All ok!");
        } else {
            System.out.println("Now: Wrong code!");
        }

        // do the verification using a specific time
        long timestamp = ZonedDateTime.of(2023, 3, 10, 8, 9, 10, 0, ZoneId.of("Europe/Berlin")).toEpochSecond();
        if (testee.verifyCode(secret, code, timestamp / 30)) {
            System.out.println("Custom time: All ok!");
        } else {
            System.out.println("Custom time: Wrong code!");
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
