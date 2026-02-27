package com.appshield.secretfinder;

public final class Finding {
    private final String relativePath;
    private final int line;
    private final int column;
    private final String patternId;
    private final String description;
    private final SecretPattern.Severity severity;
    private final String snippet;

    public Finding(String relativePath,
                   int line,
                   int column,
                   String patternId,
                   String description,
                   SecretPattern.Severity severity,
                   String snippet) {
        this.relativePath = relativePath;
        this.line = line;
        this.column = column;
        this.patternId = patternId;
        this.description = description;
        this.severity = severity;
        this.snippet = snippet;
    }

    public String getRelativePath() {
        return relativePath;
    }

    public int getLine() {
        return line;
    }

    public int getColumn() {
        return column;
    }

    public String getPatternId() {
        return patternId;
    }

    public String getDescription() {
        return description;
    }

    public SecretPattern.Severity getSeverity() {
        return severity;
    }

    public String getSnippet() {
        return snippet;
    }
}