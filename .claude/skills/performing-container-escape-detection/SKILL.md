---
name: performing-container-escape-detection
description: >-
  Audits container and pod configuration for escape-enabling misconfiguration using the
  Kubernetes Python client - privileged flags, dangerous capability grants, host path mounts,
  shared namespaces, and CVE-2022-0492 style cgroup abuse. Use when sweeping a cluster for
  workloads that could break out, producing a posture report, or checking configuration before
  enforcement is switched on. Keywords: privileged, hostPath, hostPID, capabilities,
  CVE-2022-0492, cgroup, kubernetes python client, posture audit. Do not use for runtime
  syscall-based detection - use detecting-container-escape-attempts.

  '
domain: cybersecurity
subdomain: container-security
tags:
- container-security
- container-escape
- privileged-container
- namespace-analysis
- linux-capabilities
- threat-detection
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
mitre_attack:
- T1610
- T1611
- T1609
- T1525
---

# Performing Container Escape Detection


## When to Use

- When conducting security assessments that involve performing container escape detection
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Familiarity with container security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Audit Kubernetes pods for container escape vectors including privileged mode,
dangerous capabilities, host namespace sharing, and writable hostPath mounts.

```python
from kubernetes import client, config
config.load_kube_config()
v1 = client.CoreV1Api()

pods = v1.list_pod_for_all_namespaces()
for pod in pods.items:
    for container in pod.spec.containers:
        sc = container.security_context
        if sc and sc.privileged:
            print(f"PRIVILEGED: {pod.metadata.namespace}/{pod.metadata.name}")
```

Key escape vectors:
1. Privileged containers (full host access)
2. CAP_SYS_ADMIN capability
3. Host PID/Network/IPC namespace sharing
4. Writable hostPath mounts to / or /etc
5. Docker socket mount (/var/run/docker.sock)

## Examples

```python
# Check for docker socket mounts
for vol in pod.spec.volumes or []:
    if vol.host_path and "docker.sock" in (vol.host_path.path or ""):
        print(f"Docker socket exposed: {pod.metadata.name}")
```
