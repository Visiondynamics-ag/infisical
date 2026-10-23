{
  "SchemaVersion": 2,
  "ArtifactType": "container_image",
  "ArtifactName": {{ env "INFISICAL_SCAN_IMAGE" | mustToJson }},
  "Metadata": {"RepoDigests": [{{ env "INFISICAL_SCAN_REPO_DIGEST" | mustToJson }}]},
  "Results": [
  {{- range $i, $result := . }}{{ if $i }},{{ end }}
    {"Target": {{ $result.Target | mustToJson }}, "Class": {{ $result.Class | mustToJson }}, "Type": {{ $result.Type | mustToJson }},
     "Vulnerabilities": {{ if $result.Vulnerabilities }}{{ $result.Vulnerabilities | mustToJson }}{{ else }}[]{{ end }},
     "Secrets": [{{ range $j, $secret := $result.Secrets }}{{ if $j }},{{ end }}{"RuleID": {{ $secret.RuleID | mustToJson }}, "Category": {{ $secret.Category | mustToJson }}, "Severity": {{ $secret.Severity | mustToJson }}}{{ end }}]}
  {{- end }}
  ]
}
