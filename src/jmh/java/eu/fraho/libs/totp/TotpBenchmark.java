/*
 * MIT Licence
 * Copyright (c) 2023 Simon Frankenberger
 *
 * Please see LICENCE.md for complete licence text.
 */
package eu.fraho.libs.totp;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

import java.nio.charset.StandardCharsets;

@SuppressWarnings("unused")
public class TotpBenchmark {
    @Benchmark
    public void verifyCode(Blackhole blackhole, Context ctx) {
        blackhole.consume(ctx.testee.verifyCode(ctx.secret, 123456));
    }

    @Benchmark
    public void generateSecret(Blackhole blackhole, Context ctx) {
        blackhole.consume(ctx.testee.generateSecret());
    }

    @State(Scope.Benchmark)
    public static class Context {
        private Totp testee;
        private byte[] secret;

        @Setup
        public void setup() {
            testee = new Totp(TotpSettings.DEFAULT);
            secret = "12345678901234567890".getBytes(StandardCharsets.UTF_8);
        }
    }
}
