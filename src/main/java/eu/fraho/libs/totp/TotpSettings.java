/*
 * MIT Licence
 * Copyright (c) 2023 Simon Frankenberger
 *
 * Please see LICENCE.md for complete licence text.
 */
package eu.fraho.libs.totp;

import lombok.Builder;
import lombok.Value;
import org.intellij.lang.annotations.MagicConstant;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

@Builder
@Value
public class TotpSettings {
    public static final TotpSettings DEFAULT = TotpSettings.builder().build();

    @Builder.Default
    @Range(from = 0, to = 3)
    int variance = 3;

    @Builder.Default
    @Range(from = 16, to = 32)
    int secretLength = 20;

    @Builder.Default
    @NotNull
    @MagicConstant(stringValues = {"HmacSHA1", "HmacSHA256", "HmacSHA2512"})
    String hmac = "HmacSHA1";

    @Builder.Default
    @Range(from = 6, to = 8)
    int tokenLength = 6;
}
