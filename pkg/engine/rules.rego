package k8s

import future.keywords

# 1. privileged container
deny contains {"allowed": false, "rule_id": "PRIVILEGED", "message": "Privileged container is not allowed"} {
    input.container.securityContext.privileged == true
}

# 2. runAsNonRoot should be true (fail if missing or false)
deny contains {"allowed": false, "rule_id": "RUN_AS_NON_ROOT", "message": "runAsNonRoot should be true"} {
    not input.container.securityContext.runAsNonRoot == true
}

# 3. readOnlyRootFilesystem should be true (fail if missing or false)
deny contains {"allowed": false, "rule_id": "READONLY_ROOT", "message": "readOnlyRootFilesystem should be true"} {
    not input.container.securityContext.readOnlyRootFilesystem == true
}

# 4. memory limits missing
deny contains {"allowed": false, "rule_id": "NO_MEMORY_LIMITS", "message": "Memory limits missing"} {
    not input.container.resources.limits.memory
}

# 5. image tag latest or missing tag
deny contains {"allowed": false, "rule_id": "LATEST_TAG", "message": "Avoid using 'latest' tag or implicit tag, specify a fixed version"} {
    img := input.container.image
    endswith(img, ":latest")
}
deny contains {"allowed": false, "rule_id": "LATEST_TAG", "message": "Avoid using 'latest' tag or implicit tag, specify a fixed version"} {
    img := input.container.image
    not contains(img, ":")
}