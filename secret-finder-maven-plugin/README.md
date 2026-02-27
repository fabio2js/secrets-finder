## Secret Finder Maven Plugin

### Build and install locally

From the repository root:

```bash
mvn -pl secret-finder-maven-plugin -DskipTests install
```

Or directly from the module:

```bash
mvn -f secret-finder-maven-plugin/pom.xml -DskipTests install
```

### Configure in a consumer `pom.xml`

```xml
<build>
  <plugins>
    <plugin>
      <groupId>com.appshield</groupId>
      <artifactId>secret-finder-maven-plugin</artifactId>
      <version>1.0.0-SNAPSHOT</version>
      <executions>
        <execution>
          <goals>
            <goal>scan</goal>
          </goals>
        </execution>
      </executions>
      <configuration>
        <includes>
          <include>**/*</include>
        </includes>
        <excludes>
          <exclude>**/target/**</exclude>
          <exclude>**/.git/**</exclude>
          <exclude>**/.idea/**</exclude>
          <exclude>**/.vscode/**</exclude>
        </excludes>
        <maxFileBytes>2097152</maxFileBytes>
        <maxFindings>200</maxFindings>
        <failOnFindings>false</failOnFindings>
      </configuration>
    </plugin>
  </plugins>
</build>
```

The plugin runs during `verify` by default.

### Example output

```text
Secret Finder Report
Base dir: C:/work/sample-app
Findings: 2
Critical: 1 High: 1 Medium: 0 Low: 0

[1] CRITICAL HARDCODED_PASSWORD
File: src/main/resources/application.properties:12:18
Desc: Hardcoded password assignment
Snip: password=<redacted>

[2] HIGH AWS_ACCESS_KEY_ID
File: src/main/resources/config.yml:8:14
Desc: AWS access key id detected
Snip: aws.accessKeyId=<redacted>
```

When no findings are detected, the plugin prints:

```text
No secrets found.
```