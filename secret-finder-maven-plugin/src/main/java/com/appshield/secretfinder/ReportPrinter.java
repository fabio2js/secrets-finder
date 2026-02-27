package com.appshield.secretfinder;

import org.apache.maven.plugin.logging.Log;

import java.util.List;

public final class ReportPrinter {
    private final Log log;

    public ReportPrinter(Log log) {
        this.log = log;
    }

    public void print(String baseDir, List<Finding> findings) {
        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;

        for (Finding finding : findings) {
            SecretPattern.Severity severity = finding.getSeverity();
            if (severity == SecretPattern.Severity.CRITICAL) {
                critical++;
            } else if (severity == SecretPattern.Severity.HIGH) {
                high++;
            } else if (severity == SecretPattern.Severity.MEDIUM) {
                medium++;
            } else if (severity == SecretPattern.Severity.LOW) {
                low++;
            }
        }

        log.info("Secret Finder Report");
        log.info("Base dir: " + baseDir);
        log.info("Findings: " + findings.size());
        log.info("Critical: " + critical + " High: " + high + " Medium: " + medium + " Low: " + low);

        if (findings.isEmpty()) {
            log.info("No secrets found.");
            return;
        }

        for (int i = 0; i < findings.size(); i++) {
            Finding finding = findings.get(i);
            int index = i + 1;
            log.info("[" + index + "] " + finding.getSeverity() + " " + finding.getPatternId());
            log.info("File: " + finding.getRelativePath() + ":" + finding.getLine() + ":" + finding.getColumn());
            log.info("Desc: " + finding.getDescription());
            log.info("Snip: " + finding.getSnippet());
        }
    }
}