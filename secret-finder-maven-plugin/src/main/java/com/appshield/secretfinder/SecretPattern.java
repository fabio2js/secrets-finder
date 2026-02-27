package com.appshield.secretfinder;

import java.util.regex.Pattern;

public enum SecretPattern {
    HARDCODED_PASSWORD(
            "HARDCODED_PASSWORD",
            "Hardcoded password assignment",
            Severity.CRITICAL,
            Pattern.compile("(?i)\\b(password|passwd|pwd)\\b\\s*[:=]\\s*(['\"]?)[^'\"\\s#;]+\\2")
    ),
    API_KEY_GENERIC(
            "API_KEY_GENERIC",
            "Potential API/secret key assignment",
            Severity.HIGH,
            Pattern.compile("(?i)\\b[a-z0-9._-]*(api[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|private[_-]?key)[a-z0-9._-]*\\b\\s*[:=]\\s*(['\"]?)[^'\"\\s#;]+\\2")
    ),
    JWT_TOKEN(
            "JWT_TOKEN",
            "JWT token detected",
            Severity.HIGH,
            Pattern.compile("\\beyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b")
    ),
    AWS_ACCESS_KEY_ID(
            "AWS_ACCESS_KEY_ID",
            "AWS access key id detected",
            Severity.HIGH,
            Pattern.compile("\\bAKIA[0-9A-Z]{16}\\b")
    ),
    GITHUB_TOKEN(
            "GITHUB_TOKEN",
            "GitHub personal access token detected",
            Severity.HIGH,
            Pattern.compile("\\bghp_[A-Za-z0-9]{36}\\b")
    ),
    PRIVATE_KEY_BLOCK(
            "PRIVATE_KEY_BLOCK",
            "Private key block marker detected",
            Severity.CRITICAL,
            Pattern.compile("-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----")
    );

    public enum Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW
    }

    private final String id;
    private final String description;
    private final Severity severity;
    private final Pattern regex;

    SecretPattern(String id, String description, Severity severity, Pattern regex) {
        this.id = id;
        this.description = description;
        this.severity = severity;
        this.regex = regex;
    }

    public String getId() {
        return id;
    }

    public String getDescription() {
        return description;
    }

    public Severity getSeverity() {
        return severity;
    }

    public Pattern getRegex() {
        return regex;
    }
}