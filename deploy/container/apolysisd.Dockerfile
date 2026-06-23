# SPDX-License-Identifier: Apache-2.0

FROM archlinux:base

COPY apolysisd /usr/local/bin/apolysisd
COPY apolysisd-health /usr/local/bin/apolysisd-health
COPY crictl /usr/local/bin/crictl
COPY apolysis_observer.bpf.o /usr/local/lib/apolysis/apolysis_observer.bpf.o

RUN chmod 0755 /usr/local/bin/apolysisd /usr/local/bin/apolysisd-health /usr/local/bin/crictl \
    && chmod 0644 /usr/local/lib/apolysis/apolysis_observer.bpf.o

ENTRYPOINT ["/usr/local/bin/apolysisd"]
