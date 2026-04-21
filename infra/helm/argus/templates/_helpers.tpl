{{/*
ARGUS Helm helpers
==================
Standard chart helpers (name / fullname / labels) plus ARGUS-specific helpers
for image-with-digest resolution and the Cosign verify-init container.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "argus.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec).
*/}}
{{- define "argus.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label.
*/}}
{{- define "argus.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels (Helm + Kubernetes recommended set + commonLabels overlay).
*/}}
{{- define "argus.labels" -}}
helm.sh/chart: {{ include "argus.chart" . }}
{{ include "argus.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: argus
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Selector labels — these are stable across releases and used in deployments
matchLabels / pod template labels.
*/}}
{{- define "argus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "argus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Service account name.
*/}}
{{- define "argus.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "argus.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image-with-digest helper.
Resolves to "<repository>@<digest>" — refusing to render if the digest is the
all-zero placeholder when the chart is being installed in PRODUCTION
(`config.environment == "production"`). In dev / staging / lint contexts the
placeholder is allowed so `helm lint` can run before the supply-chain
pipeline injects the real digest.
Usage: {{ include "argus.imageRef" (dict "image" .Values.image.backend "root" $) }}
*/}}
{{- define "argus.imageRef" -}}
{{- $img := .image -}}
{{- $root := .root -}}
{{- if not $img.digest -}}
{{- fail (printf "image.digest is required for %s" $img.repository) -}}
{{- end -}}
{{- if and $root (eq (default "" $root.Values.config.environment) "production") -}}
{{- if eq $img.digest "sha256:0000000000000000000000000000000000000000000000000000000000000000" -}}
{{- fail (printf "image.digest for %s is the placeholder value — production deploy MUST inject the real @sha256 digest" $img.repository) -}}
{{- end -}}
{{- end -}}
{{- printf "%s@%s" $img.repository $img.digest -}}
{{- end -}}

{{/*
Production INVARIANT — refuses to render if cosign.verify.enabled is false in
the production environment. This is the chart-side seatbelt for the supply
chain story.
Usage: {{ include "argus.cosignAssertProd" . }}
*/}}
{{- define "argus.cosignAssertProd" -}}
{{- if eq (default "" .Values.config.environment) "production" -}}
{{- if not .Values.cosign.verify.enabled -}}
{{- fail "cosign.verify.enabled MUST be true in production overlay (ARG-045 invariant)" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Cosign verify-init container.
Emits an init-container spec that verifies the given image (referenced via
"argus.imageRef") with sigstore (Fulcio + Rekor) keyless OIDC.
Usage:
  initContainers:
    {{- include "argus.cosignVerifyInit" (dict "root" $ "image" .Values.image.backend "name" "verify-backend") | nindent 8 }}
*/}}
{{- define "argus.cosignVerifyInit" -}}
{{- $root := .root -}}
{{- $img  := .image -}}
{{- $name := .name -}}
{{- if $root.Values.cosign.verify.enabled }}
- name: {{ $name }}
  image: {{ printf "%s:%s" $root.Values.cosign.verify.image.repository $root.Values.cosign.verify.image.tag }}
  imagePullPolicy: {{ $root.Values.cosign.verify.image.pullPolicy }}
  securityContext:
    {{- toYaml $root.Values.containerSecurityContext | nindent 4 }}
  env:
    - name: COSIGN_EXPERIMENTAL
      value: "1"
  command: ["cosign"]
  args:
    - verify
    {{- if $root.Values.cosign.verify.keyless.enabled }}
    - --certificate-identity-regexp={{ $root.Values.cosign.verify.keyless.certificateIdentityRegexp }}
    - --certificate-oidc-issuer={{ $root.Values.cosign.verify.keyless.certificateOidcIssuer }}
    {{- else if $root.Values.cosign.verify.keyed.enabled }}
    - --key=/etc/cosign/cosign.pub
    {{- end }}
    {{- range $arg := $root.Values.cosign.verify.extraArgs }}
    - {{ $arg }}
    {{- end }}
    - {{ include "argus.imageRef" (dict "image" $img "root" $root) }}
  volumeMounts:
    - name: tmp
      mountPath: /tmp
    {{- if and $root.Values.cosign.verify.keyed.enabled $root.Values.cosign.verify.keyed.publicKeyConfigMap }}
    - name: cosign-pub
      mountPath: /etc/cosign
      readOnly: true
    {{- end }}
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 128Mi
{{- end }}
{{- end -}}

{{/*
Standard volumes block — emits the writable tmpfs needed because every
container runs with readOnlyRootFilesystem=true.
Usage:
  volumes:
    {{- include "argus.standardVolumes" . | nindent 8 }}
*/}}
{{- define "argus.standardVolumes" -}}
- name: tmp
  emptyDir:
    sizeLimit: 256Mi
- name: cache
  emptyDir:
    sizeLimit: 512Mi
{{- if and .Values.cosign.verify.keyed.enabled .Values.cosign.verify.keyed.publicKeyConfigMap }}
- name: cosign-pub
  configMap:
    name: {{ .Values.cosign.verify.keyed.publicKeyConfigMap }}
{{- end }}
{{- end -}}

{{/*
Standard volumeMounts — paired with argus.standardVolumes.
*/}}
{{- define "argus.standardVolumeMounts" -}}
- name: tmp
  mountPath: /tmp
- name: cache
  mountPath: /var/cache/argus
{{- end -}}

{{/*
Image pull secrets aggregator — merges global + per-chart secrets.
*/}}
{{- define "argus.imagePullSecrets" -}}
{{- $secrets := list -}}
{{- range .Values.global.imagePullSecrets -}}
  {{- $secrets = append $secrets . -}}
{{- end -}}
{{- range .Values.imagePullSecrets -}}
  {{- $secrets = append $secrets . -}}
{{- end -}}
{{- if $secrets }}
imagePullSecrets:
{{- range $s := $secrets }}
  - name: {{ $s }}
{{- end }}
{{- end -}}
{{- end -}}
