# SPDX-License-Identifier: Apache-2.0

FROM gcr.io/distroless/cc-debian12:nonroot

COPY apolysis-kubernetes-source /usr/local/bin/apolysis-kubernetes-source

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/apolysis-kubernetes-source"]
