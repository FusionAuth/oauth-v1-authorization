package io.fusionauth.oauth1;

/*
 * Copyright (c) 2019-2021, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Daniel DeGroff
 */
public class OAuth1AuthorizationHeaderBuilder {
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    // https://tools.ietf.org/html/rfc3986#section-2.3
    private static final Set<Character> UnreservedChars = new HashSet<>(Arrays.asList(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            '-', '_', '.', '~'));

    private String consumerSecret;
    private String method;
    private String signingKey;
    private String tokenSecret;
    private String url;
    private final Map<String, String> parameters = new LinkedHashMap<>();
    private final Map<String, String> queryParametersMap = new LinkedHashMap<>();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /***
     * Replaces any character not specifically unreserved to an equivalent percent sequence.
     *
     * @param s the string to encode
     * @return and encoded string
     */
    public static String encodeURIComponent(String s) {
        StringBuilder o = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            if (isSafe(b)) {
                o.append((char) b);
            } else {
                o.append('%');
                o.append(HEX[((b & 0xF0) >> 4)]);
                o.append(HEX[(b & 0x0F)]);
            }
        }
        return o.toString();
    }

    private static boolean isSafe(byte b) {
        return UnreservedChars.contains((char) b);
    }

    public String build() {
        // For testing purposes, only add the timestamp if it has not yet been added
        if (!parameters.containsKey("oauth_timestamp")) {
            parameters.put("oauth_timestamp", "" + Instant.now().getEpochSecond());
        }

        // Boiler plate parameters
        parameters.put("oauth_nonce", nonceGenerator());
        parameters.put("oauth_signature_method", "HMAC-SHA1");
        parameters.put("oauth_version", "1.0");

        Map<String, String> parametersCopy = new LinkedHashMap<>(parameters);
        parametersCopy.putAll(queryParametersMap);

        // Build the parameter string after sorting the keys in lexicographic order per the OAuth v1 spec.
        String parameterString = parametersCopy.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> encodeURIComponent(e.getKey()) + "=" + encodeURIComponent(e.getValue()))
                .collect(Collectors.joining("&"));

        // Build the signature base string
        String signatureBaseString = method.toUpperCase() + "&" + encodeURIComponent(url) + "&" + encodeURIComponent(parameterString);

        // If the signing key was not provided, build it by encoding the consumer secret + the token secret
        if (signingKey == null) {
            signingKey = encodeURIComponent(consumerSecret) + "&" + (tokenSecret == null ? "" : encodeURIComponent(tokenSecret));
        }

        // Sign the Signature Base String
        String signature = generateSignature(signingKey, signatureBaseString);

        // Add the signature to be included in the header
        parameters.put("oauth_signature", signature);

        // Build the authorization header value using the order in which the parameters were added
        return "OAuth " + parameters.entrySet().stream()
                .map(e -> encodeURIComponent(e.getKey()) + "=\"" + encodeURIComponent(e.getValue()) + "\"")
                .collect(Collectors.joining(", "));
    }

    public String generateSignature(String secret, String message) {
        try {
            byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(bytes, "HmacSHA1"));
            byte[] result = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(result);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Set the Consumer Secret
     *
     * @param consumerSecret the Consumer Secret
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withConsumerSecret(String consumerSecret) {
        this.consumerSecret = consumerSecret;
        return this;
    }

    /**
     * Set the requested HTTP method
     *
     * @param method the HTTP method you are requesting
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withMethod(String method) {
        this.method = method;
        return this;
    }

    /**
     * Add a parameter to be included when building the signature.
     *
     * @param name  the parameter name
     * @param value the parameter value
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withParameter(String name, String value) {
        parameters.put(name, value);
        return this;
    }

    /**
     * Adds a query parameter to the OAuth1 authorization header.
     *
     * @param queryParameter the query parameter in "name=value" format.
     * @return the current instance for method chaining.
     */
    public OAuth1AuthorizationHeaderBuilder withURLQueryParameter(String queryParameter) {
        if (queryParameter == null || queryParameter.isEmpty()) return this;

        String[] parameterParts = queryParameter.split("=", 2);
        String key = parameterParts[0];
        String value = parameterParts.length > 1 ? parameterParts[1] : "";

        this.queryParametersMap.put(key, value);

        return this;
    }

    /**
     * Set the OAuth Token Secret
     *
     * @param tokenSecret the OAuth Token Secret
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
        return this;
    }

    /**
     * Set the requested URL in the builder.
     *
     * @param url the URL you are requesting
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withURL(String url) {
        if (url.contains("?")) {
            handleQueryParam(url);
        } else {
            this.url = url;
        }

        return this;
    }

    /**
     * Extracts query parameters from the URL and assigns them to the respective fields.
     *
     * @param url the URL to process
     */
    private void handleQueryParam(String url) {
        int queryIndex = url.indexOf("?");
        if (queryIndex == -1) return;

        this.url = url.substring(0, queryIndex);
        String queryParam = url.substring(queryIndex + 1);

        if (queryParam.isEmpty()) return;

        for (String paramToken : queryParam.split("&")) this.withURLQueryParameter(paramToken);
    }

    public static String nonceGenerator() {
        StringBuilder randomDigits = new StringBuilder(15);

        for (int i = 0; i < 15; i++) {
            randomDigits.append(SECURE_RANDOM.nextInt(10));
        }

        return DigestUtils.md5Hex(randomDigits.toString());
    }
}