/*
 * MIT Licence
 * Copyright (c) 2023 Simon Frankenberger
 *
 * Please see LICENCE.md for complete licence text.
 */
package eu.fraho.libs.totp;

import lombok.Builder;
import lombok.Value;
import org.jetbrains.annotations.NotNull;

@Builder
@Value
public class TotpSettings {
    public static final TotpSettings DEFAULT = TotpSettings.builder().build();

    @Builder.Default
    int variance = 3;

    @Builder.Default
    int secretLength = 20;

    @Builder.Default
    @NotNull
    String hmac = "HmacSHA1";

    @Builder.Default
    int tokenLength = 6;
}
