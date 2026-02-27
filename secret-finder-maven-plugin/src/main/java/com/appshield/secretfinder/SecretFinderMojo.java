package com.appshield.secretfinder;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

@Mojo(name = "scan", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class SecretFinderMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project.basedir}", readonly = true, required = true)
    private File baseDir;

        @Parameter(property = "secretFinder.includes")
        private String[] includes = new String[]{"**/*"};

    @Parameter(property = "secretFinder.excludes")
        private String[] excludes = new String[]{
            "**/target/**",
            "**/.git/**",
            "**/.idea/**",
            "**/.vscode/**"
        };

    @Parameter(property = "secretFinder.maxFileBytes", defaultValue = "2097152")
    private long maxFileBytes;

    @Parameter(property = "secretFinder.maxFindings", defaultValue = "200")
    private int maxFindings;

    @Parameter(property = "secretFinder.failOnFindings", defaultValue = "false")
    private boolean failOnFindings;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (baseDir == null || !baseDir.exists() || !baseDir.isDirectory()) {
            throw new MojoExecutionException("Base directory does not exist or is not a directory: " + baseDir);
        }

        List<String> includePatterns = Arrays.asList(includes);
        List<String> excludePatterns = Arrays.asList(excludes);

        Path basePath = baseDir.toPath();
        Scanner scanner = new Scanner(basePath, includePatterns, excludePatterns, maxFileBytes, maxFindings);
        List<Finding> findings;

        try {
            findings = scanner.scan();
        } catch (IOException e) {
            throw new MojoExecutionException("Failed while scanning project files", e);
        }

        new ReportPrinter(getLog()).print(basePath.toAbsolutePath().toString(), findings);

        if (failOnFindings && !findings.isEmpty()) {
            throw new MojoFailureException("Secret findings detected: " + findings.size());
        }
    }
}