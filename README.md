# User Controller for Kubernetes

This repository contains a Go-based application for managing Kubernetes user roles, namespaces, and certificates through GitOps principles. The application watches a Git repository for state changes and applies those changes to the Kubernetes cluster.

## Features
- **GitOps Integration**: The controller syncs user states from a Git repository.
- **RBAC Management**: Automatically creates and updates Kubernetes ClusterRoles, RoleBindings, and namespaces based on the Git state.
- **Certificate Management**: Issues and manages user certificates for Kubernetes API access.
- **Periodic Synchronization**: Regularly pulls updates from the Git repository and reconciles the cluster state.

## Prerequisites
- Kubernetes cluster (1.30.1 or compatible)
- Configured `kubectl` context for the target cluster
- Git repository containing the user state YAML file (`users-state.yaml`)
- Go environment (1.20+)

## Installation

### Clone the Repository
```bash
git clone <repository-url>
cd <repository>
```

### Environment Variables
Set the following environment variables:

- `GIT_REPO_URL`: URL of the Git repository containing the user state.
- `GIT_REPO_PATH`: Local path where the repository will be cloned.
- `CERT_DIR`: Directory where user certificates will be stored.

Example:
```bash
export GIT_REPO_URL=https://github.com/example/user-state-repo.git
export GIT_REPO_PATH=/tmp/git-repo
export CERT_DIR=/tmp/certs
```

### Build and Run
Build and run the controller:
```bash
go build -o user-controller
./user-controller
```

## Deploying the Controller

The following manifest file can be used to deploy the controller in a Kubernetes cluster:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: user-controller
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: user-controller
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles", "rolebindings"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests", "certificatesigningrequests/approval", "certificatesigningrequests/status"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["bind", "escalate"] 
- apiGroups: ["certificates.k8s.io"]
  resources: ["signers"]
  resourceNames: ["kubernetes.io/kube-apiserver-client"]
  verbs: ["approve"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: user-controller
subjects:
- kind: ServiceAccount
  name: user-controller
  namespace: default
roleRef:
    kind: ClusterRole
    name: user-controller
    apiGroup: rbac.authorization.k8s.io

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-controller
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: user-controller
  template:
    metadata:
      labels:
        app: user-controller
    spec:
      serviceAccountName: user-controller
      containers:
      - name: controller
        image: aboogie/rbac-controller:latest # Replace with your image
        env:
        - name: GIT_REPO_URL
          value: "https://github.com/aboogie24/k8s-rbac-config.git"
        - name: GIT_REPO_PATH
          value: "/repo"
        - name: CERT_DIR
          value: "/certs"
        volumeMounts:
        - name: repo-volume
          mountPath: /repo
        - name: cert-volume
          mountPath: /certs
      volumes:
      - name: repo-volume
        emptyDir: {}
      - name: cert-volume
        emptyDir: {}

---

apiVersion: v1
kind: ConfigMap
metadata:
  name: user-controller-trigger
  namespace: default
  labels:
    app: user-controller
data:
  lastCommit: "initial"  # This will be updated by the controller

---

apiVersion: v1
kind: Secret
metadata:
  name: user-controller
  namespace: default
  annotations:
    kubernetes.io/service-account.name: user-controller
type: kubernetes.io/service-account-token
```

## Configuration

### User State File
The `users-state.yaml` file in the Git repository should follow this structure:

```yaml
roles:
  admin:
    rules:
      - apiGroups: [""]
        resources: ["pods"]
        verbs: ["get", "list", "watch"]

users:
  - username: johndoe
    email: johndoe@example.com
    role: admin
    namespaces:
      - dev
```

### Trigger ConfigMap
A Kubernetes ConfigMap named `user-controller-trigger` in the `default` namespace is used to trigger reconciliations. Ensure it exists:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: user-controller-trigger
  namespace: default
```

## Components

### Main Application
The main entry point initializes logging, configures the controller, and starts periodic Git synchronization.

### UserController
Responsible for:
- Loading user state from the Git repository
- Reconciling Kubernetes ClusterRoles, RoleBindings, and namespaces
- Managing user certificates

### Reconciliation
- Watches for changes in the Git repository and applies updates to the cluster.
- Uses a ConfigMap (`user-controller-trigger`) to initiate reconciliation.

## Usage
1. Update the `users-state.yaml` file in the Git repository.
2. Push changes to the repository.
3. The controller will automatically pull updates and reconcile the cluster state.

## Troubleshooting

### Common Issues
- **Git Clone Failure**: Ensure the repository URL and credentials are correct.
- **Permission Denied**: Verify that the Kubernetes service account has sufficient permissions.
- **Certificate Errors**: Check the `CERT_DIR` path and ensure it is writable.

### Logs
View logs for debugging:
```bash
kubectl logs -l app=user-controller
```

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributions
Contributions are welcome! Feel free to open issues or submit pull requests.

