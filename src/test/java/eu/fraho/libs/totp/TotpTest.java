package eu.fraho.libs.totp;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;

public class TotpTest {
    private static final byte[] secret1 = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] secret2 = "1234567890abcdef".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] secret256 = "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] secret512 = "1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.US_ASCII);

    @Test
    void testVerifyCode() {
        Totp testee = new Totp(TotpSettings.DEFAULT);
        Assertions.assertFalse(testee.verifyCode(secret1, 287922, 10)); // -4
        Assertions.assertTrue(testee.verifyCode(secret1, 162583, 10)); // -3
        Assertions.assertTrue(testee.verifyCode(secret1, 399871, 10)); // -2
        Assertions.assertTrue(testee.verifyCode(secret1, 520489, 10)); // -1
        Assertions.assertTrue(testee.verifyCode(secret1, 403154, 10)); // 0
        Assertions.assertTrue(testee.verifyCode(secret1, 481090, 10)); // 1
        Assertions.assertTrue(testee.verifyCode(secret1, 868912, 10)); // 2
        Assertions.assertTrue(testee.verifyCode(secret1, 736127, 10)); // 3
        Assertions.assertFalse(testee.verifyCode(secret1, 229903, 10)); // 4
    }

    @Test
    void testVerifyCode2() {
        Totp testee = new Totp(TotpSettings.DEFAULT);
        Assertions.assertFalse(testee.verifyCode(secret2, 475915, 10)); // -4
        Assertions.assertTrue(testee.verifyCode(secret2, 808817, 10)); // -3
        Assertions.assertTrue(testee.verifyCode(secret2, 397776, 10)); // -2
        Assertions.assertTrue(testee.verifyCode(secret2, 989534, 10)); // -1
        Assertions.assertTrue(testee.verifyCode(secret2, 234408, 10)); // 0
        Assertions.assertTrue(testee.verifyCode(secret2, 334030, 10)); // 1
        Assertions.assertTrue(testee.verifyCode(secret2, 664443, 10)); // 2
        Assertions.assertTrue(testee.verifyCode(secret2, 606751, 10)); // 3
        Assertions.assertFalse(testee.verifyCode(secret2, 593219, 10)); // 4
    }

    @Test
    void testVerifyCodeVariance2() {
        Totp testee = new Totp(TotpSettings.builder().variance(2).build());
        Assertions.assertFalse(testee.verifyCode(secret1, 162583, 10)); // -3
        Assertions.assertTrue(testee.verifyCode(secret1, 399871, 10)); // -2
        Assertions.assertTrue(testee.verifyCode(secret1, 520489, 10)); // -1
        Assertions.assertTrue(testee.verifyCode(secret1, 403154, 10)); // 0
        Assertions.assertTrue(testee.verifyCode(secret1, 481090, 10)); // 1
        Assertions.assertTrue(testee.verifyCode(secret1, 868912, 10)); // 2
        Assertions.assertFalse(testee.verifyCode(secret1, 736127, 10)); // 3
    }

    @Test
    void testVerifyCodeLength8() {
        Totp testee = new Totp(TotpSettings.builder().tokenLength(8).build());
        Assertions.assertTrue(testee.verifyCode(secret1, 82162583, 10)); // -3
        Assertions.assertTrue(testee.verifyCode(secret1, 73399871, 10)); // -2
        Assertions.assertTrue(testee.verifyCode(secret1, 45520489, 10)); // -1
        Assertions.assertTrue(testee.verifyCode(secret1, 72403154, 10)); // 0
        Assertions.assertTrue(testee.verifyCode(secret1, 43481090, 10)); // 1
        Assertions.assertTrue(testee.verifyCode(secret1, 47868912, 10)); // 2
        Assertions.assertTrue(testee.verifyCode(secret1, 33736127, 10)); // 3
    }

    @Test
    void testVerifyCodeHmacSha256() {
        Totp testee = new Totp(TotpSettings.builder().hmac("HmacSHA256").build());
        Assertions.assertTrue(testee.verifyCode(secret1, 579288, 10)); // -3
        Assertions.assertTrue(testee.verifyCode(secret1, 895912, 10)); // -2
        Assertions.assertTrue(testee.verifyCode(secret1, 184989, 10)); // -1
        Assertions.assertTrue(testee.verifyCode(secret1, 586609, 10)); // 0
        Assertions.assertTrue(testee.verifyCode(secret1, 771515, 10)); // 1
        Assertions.assertTrue(testee.verifyCode(secret1, 360470, 10)); // 2
        Assertions.assertTrue(testee.verifyCode(secret1, 916449, 10)); // 3
    }

    @ParameterizedTest
    // see https://www.rfc-editor.org/rfc/rfc6238#appendix-B
    @CsvSource({
            "         59, 94287082, 46119246, 90693936",
            " 1111111109,  7081804, 68084774, 25091201",
            " 1111111111, 14050471, 67062674, 99943326",
            " 1234567890, 89005924, 91819424, 93441116",
            " 2000000000, 69279037, 90698825, 38618901",
            "20000000000, 65353130, 77737706, 47863826",
    })
    void testRfc6238Vectors(long clock, int code1, int code256, int code512) {
        Totp testeeSha1 = new Totp(TotpSettings.builder().tokenLength(8).variance(0).hmac("HmacSHA1").build());
        Totp testeeSha256 = new Totp(TotpSettings.builder().tokenLength(8).variance(0).hmac("HmacSHA256").build());
        Totp testeeSha512 = new Totp(TotpSettings.builder().tokenLength(8).variance(0).hmac("HmacSHA512").build());

        long counter = clock / 30;
        Assertions.assertTrue(testeeSha1.verifyCode(secret1, code1, counter), testeeSha1.getSettings().getHmac());
        Assertions.assertTrue(testeeSha256.verifyCode(secret256, code256, counter), testeeSha256.getSettings().getHmac());
        Assertions.assertTrue(testeeSha512.verifyCode(secret512, code512, counter), testeeSha512.getSettings().getHmac());
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 16, 20, 64})
    void testGenerateSecret(int length) {
        Totp testee = new Totp(TotpSettings.builder().secretLength(length).build());
        Assertions.assertEquals(length, testee.generateSecret().length);
    }
}
