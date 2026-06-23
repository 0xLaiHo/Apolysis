{{- define "apolysis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "apolysis.fullname" -}}
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

{{- define "apolysis.tenantId" -}}
{{- regexReplaceAll "[^a-z0-9.-]" (lower (required "tenant.id is required" .Values.tenant.id)) "-" | trimAll "-" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "apolysis.namespace" -}}
{{- default .Release.Namespace .Values.namespace.name -}}
{{- end -}}

{{- define "apolysis.labels" -}}
app.kubernetes.io/name: {{ include "apolysis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: apolysis
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
apolysis.dev/tenant-id: {{ include "apolysis.tenantId" . | quote }}
{{- end -}}

{{- define "apolysis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "apolysis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
apolysis.dev/tenant-id: {{ include "apolysis.tenantId" . | quote }}
{{- end -}}

{{- define "apolysis.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
{{- end -}}
