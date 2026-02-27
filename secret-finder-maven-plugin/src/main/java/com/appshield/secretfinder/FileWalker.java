package com.appshield.secretfinder;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class FileWalker {
    private static final Set<String> TEXT_EXTENSIONS = new HashSet<String>(Arrays.asList(
            ".java", ".xml", ".yml", ".yaml", ".properties", ".env", ".json", ".md",
            ".txt", ".conf", ".cfg", ".ps1", ".bat"
    ));

    private static final Set<String> BINARY_EXTENSIONS = new HashSet<String>(Arrays.asList(
            ".class", ".jar", ".exe", ".dll", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
            ".zip", ".tar", ".gz", ".7z", ".rar", ".pdf", ".war", ".ear"
    ));

    private final Path baseDir;
    private final List<Pattern> includePatterns;
    private final List<Pattern> excludePatterns;
    private final long maxFileBytes;

    public FileWalker(Path baseDir, List<String> includes, List<String> excludes, long maxFileBytes) {
        this.baseDir = baseDir;
        this.includePatterns = compileGlobPatterns(includes);
        this.excludePatterns = compileGlobPatterns(excludes);
        this.maxFileBytes = maxFileBytes;
    }

    public List<Path> walk() throws IOException {
        final List<Path> files = new ArrayList<Path>();
        Files.walkFileTree(baseDir, new FileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (dir.equals(baseDir)) {
                    return FileVisitResult.CONTINUE;
                }
                String rel = normalizePath(baseDir.relativize(dir));
                if (isExcluded(rel)) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (!attrs.isRegularFile()) {
                    return FileVisitResult.CONTINUE;
                }
                String rel = normalizePath(baseDir.relativize(file));
                if (isExcluded(rel) || !isIncluded(rel) || !isLikelyText(rel)) {
                    return FileVisitResult.CONTINUE;
                }
                try {
                    if (Files.size(file) > maxFileBytes) {
                        return FileVisitResult.CONTINUE;
                    }
                } catch (IOException ignored) {
                    return FileVisitResult.CONTINUE;
                }
                files.add(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
        return files;
    }

    private boolean isLikelyText(String relativePath) {
        String lower = relativePath.toLowerCase(Locale.ROOT);
        int idx = lower.lastIndexOf('.');
        if (idx < 0) {
            return false;
        }
        String ext = lower.substring(idx);
        if (BINARY_EXTENSIONS.contains(ext)) {
            return false;
        }
        return TEXT_EXTENSIONS.contains(ext);
    }

    private boolean isIncluded(String relativePath) {
        if (includePatterns.isEmpty()) {
            return true;
        }
        for (Pattern pattern : includePatterns) {
            if (pattern.matcher(relativePath).matches()) {
                return true;
            }
        }
        return false;
    }

    private boolean isExcluded(String relativePath) {
        for (Pattern pattern : excludePatterns) {
            if (pattern.matcher(relativePath).matches()) {
                return true;
            }
        }
        return false;
    }

    private static List<Pattern> compileGlobPatterns(List<String> globs) {
        List<Pattern> patterns = new ArrayList<Pattern>();
        if (globs == null) {
            return patterns;
        }
        for (String glob : globs) {
            if (glob == null || glob.trim().isEmpty()) {
                continue;
            }
            patterns.add(Pattern.compile(globToRegex(glob.trim())));
        }
        return patterns;
    }

    static String globToRegex(String glob) {
        String normalized = glob.replace('\\', '/');
        StringBuilder regex = new StringBuilder();
        regex.append('^');
        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            if (c == '*') {
                if (i + 1 < normalized.length() && normalized.charAt(i + 1) == '*') {
                    boolean slashAfterDoubleStar = i + 2 < normalized.length() && normalized.charAt(i + 2) == '/';
                    if (slashAfterDoubleStar) {
                        regex.append("(?:.*/)?");
                        i += 2;
                    } else {
                        regex.append(".*");
                        i++;
                    }
                } else {
                    regex.append("[^/]*");
                }
                continue;
            }
            if (c == '?') {
                regex.append('.');
                continue;
            }
            if (".[]{}()+-^$|".indexOf(c) >= 0) {
                regex.append('\\');
            }
            regex.append(c);
        }
        regex.append('$');
        return regex.toString();
    }

    static String normalizePath(Path path) {
        return path.toString().replace('\\', '/');
    }
}