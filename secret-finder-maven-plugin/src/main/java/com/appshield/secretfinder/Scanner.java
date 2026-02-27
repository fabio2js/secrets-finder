package com.appshield.secretfinder;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Scanner {
    private static final int MAX_SNIPPET_LENGTH = 240;

    private final Path baseDir;
    private final List<String> includes;
    private final List<String> excludes;
    private final long maxFileBytes;
    private final int maxFindings;

    public Scanner(Path baseDir, List<String> includes, List<String> excludes, long maxFileBytes, int maxFindings) {
        this.baseDir = baseDir;
        this.includes = includes;
        this.excludes = excludes;
        this.maxFileBytes = maxFileBytes;
        this.maxFindings = maxFindings;
    }

    public List<Finding> scan() throws IOException {
        List<Finding> findings = new ArrayList<Finding>();
        FileWalker walker = new FileWalker(baseDir, includes, excludes, maxFileBytes);
        List<Path> files = walker.walk();
        for (Path file : files) {
            if (findings.size() >= maxFindings) {
                break;
            }
            scanFile(file, findings);
        }
        return findings;
    }

    private void scanFile(Path file, List<Finding> findings) {
        String relativePath = FileWalker.normalizePath(baseDir.relativize(file));
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                for (SecretPattern secretPattern : SecretPattern.values()) {
                    if (findings.size() >= maxFindings) {
                        return;
                    }
                    Matcher matcher = secretPattern.getRegex().matcher(line);
                    while (matcher.find()) {
                        if (findings.size() >= maxFindings) {
                            return;
                        }
                        String rawMatch = matcher.group();
                        int column = matcher.start() + 1;
                        String snippet = sanitizeSnippet(line, rawMatch);
                        findings.add(new Finding(
                                relativePath,
                                lineNumber,
                                column,
                                secretPattern.getId(),
                                secretPattern.getDescription(),
                                secretPattern.getSeverity(),
                                snippet
                        ));
                    }
                }
            }
        } catch (IOException ignored) {
        }
    }

    private String sanitizeSnippet(String line, String matchedValue) {
        String sanitized = line.trim();
        if (sanitized.length() > MAX_SNIPPET_LENGTH) {
            sanitized = sanitized.substring(0, MAX_SNIPPET_LENGTH) + "...";
        }

        sanitized = sanitizeKeyValueAssignments(sanitized);
        sanitized = sanitizeBearerTokens(sanitized);

        if (matchedValue != null && !matchedValue.isEmpty()) {
            sanitized = sanitized.replaceAll(Pattern.quote(matchedValue), "<redacted>");
        }

        return sanitized;
    }

    private String sanitizeKeyValueAssignments(String line) {
        return line.replaceAll(
                "(?i)\\b([a-z0-9._-]*(password|passwd|pwd|api[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|private[_-]?key|token)[a-z0-9._-]*)\\b\\s*([:=])\\s*(['\"]?)[^'\"\\s#;]+\\4",
            "$1$3<redacted>"
        );
    }

    private String sanitizeBearerTokens(String line) {
        return line.replaceAll("(?i)\\b(Bearer)\\s+[A-Za-z0-9._\\-]+", "$1 <redacted>");
    }
}