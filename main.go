package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"net/http"

	"github.com/go-git/go-git/v5"
	clientT "github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"gopkg.in/yaml.v2"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// UserState and other types remain the same as in your original code
type UserState struct {
	Roles      map[string]Role      `yaml:"roles"`
	Namespaces map[string]Namespace `yaml:"namespaces"`
	Users      []User               `yaml:"users"`
}

type Role struct {
	Rules []rbacv1.PolicyRule `yaml:"rules"`
}

type Namespace struct {
	Description string `yaml:"description"`
}

type User struct {
	Username   string   `yaml:"username"`
	Email      string   `yaml:"email"`
	Role       string   `yaml:"role"`
	Namespaces []string `yaml:"namespaces"`
}

// UserController reconciles user states
type UserController struct {
	client.Client
	Scheme       *runtime.Scheme
	repoURL      string
	repoPath     string
	usersState   string 
	certDir      string
	lastCommit   string
	lastPullTime time.Time
	certClient   *kubernetes.Clientset
}

func main() {
	// Set up logging
	opts := zap.Options{
		Development: true,
	}

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	log := ctrl.Log.WithName("Main")
	// Get environment Vars
	repoURL := os.Getenv("GIT_REPO_URL")
	repoPath := os.Getenv("GIT_REPO_PATH")
	certDir := os.Getenv("CERT_DIR")
	usersState := os.Getenv("USER_STATE_LOCATION")

	log.Info("RepoURL: %v  ...  RepoPath: %v", repoURL, repoPath)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)         // Register ConfigMap and other core types
	_ = rbacv1.AddToScheme(scheme)         // Register RBAC types
	_ = certificatesv1.AddToScheme(scheme) // Register Certificate type

	// Set up controller manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		fmt.Printf("Unable to start manager: %v\n", err)
		os.Exit(1)
	}

	// Clone repository if it doesn't
	fmt.Printf("RepoPath: %v", repoPath)
	fmt.Printf("RepoURL: %v", repoURL)
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		// Create custom HTTP client that skips TLS verification
		customClient := &http.Client{
		  	Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		// Install the custom Client for HTTP(s) URLs
		clientT.InstallProtocol("https", githttp.NewClient(customClient))
		clientT.InstallProtocol("http", githttp.NewClient(customClient))
		
		g, err := git.PlainClone(repoPath, false, &git.CloneOptions{
			URL: repoURL,
		})
		if err != nil {
			fmt.Printf("Failed to clone repository: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%v", g)
	}

	config, err := rest.InClusterConfig()

	certClient, err := kubernetes.NewForConfig(config)

	// Create and register controller
	controller := &UserController{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		certClient: certClient,
		repoPath:   repoPath,
		usersState: usersState,
		certDir:    certDir,
		repoURL:    repoURL,
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "user-controller-trigger",
				Namespace: "default",
			},
			Immutable:  new(bool),
			Data:       map[string]string{},
			BinaryData: map[string][]byte{},
		}). // We'll use a ConfigMap as our trigger
		Complete(controller); err != nil {
		fmt.Printf("Unable to create controller: %v\n", err)
		os.Exit(1)
	}

	// Start periodic Git pull
	errChan := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		log.Info("Starting Git Puller")

		if err := controller.startGitPuller(ctx); err != nil {
			errChan <- err
		}

	}()

	go func() {
		log.Info("Starting Git Puller Monitor")
		for err := range errChan {
			if err != nil {
				log.Error(err, "Git puller error")
			}
		}
	}()

	// Start manager
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fmt.Printf("Problem running manager: %v\n", err)
		os.Exit(1)
	}
}

// Reconcile handles the reconciliation loop
func (c *UserController) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := log.FromContext(ctx)

	// Skip if this isn't our trigger ConfigMap
	if req.Name != "user-controller-trigger" || req.Namespace != "default" {
		log.Info("Skipping reconciliation for non-trigger ConfigMap",
			"configmap", req.Name,
			"namespace", req.Namespace)
		return reconcile.Result{}, nil
	}

	// Get the ConfigMap that triggered reconciliation
	configMap := &corev1.ConfigMap{}
	if err := c.Get(ctx, req.NamespacedName, configMap); err != nil {
		if errors.IsNotFound(err) {
			// ConfigMap was deleted
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	// Load state from Git
	state, err := c.loadState()
	if err != nil && state != nil {
		log.Error(err, "Failed to load state")
		return reconcile.Result{RequeueAfter: time.Minute}, err
	}

	// Reconcile roles
	if err := c.reconcileRoles(ctx, state.Roles); err != nil {
		log.Error(err, "Failed to reconcile roles")
		return reconcile.Result{}, err
	}

	// // Reconcile users
	if err := c.reconcileUsers(ctx, state.Users); err != nil {
		log.Error(err, "Failed to reconcile users")
		return reconcile.Result{}, err
	}
	result := reconcile.Result{RequeueAfter: time.Minute}
	log.Info("Scheduling next reconciliation",
		"requeue_after_seconds", result.RequeueAfter.Seconds(),
		"requeue_after_minutes", result.RequeueAfter.Minutes())

	return result, nil
}

func (c *UserController) loadState() (*UserState, error) {
	statePath := filepath.Join(c.repoPath, c.usersState)
	log := ctrl.Log.WithName("loadState")

	log.Info("Attempting to load state file", "path", statePath)

	if _, err := os.Stat(statePath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("state file does not exist at %s", statePath)
		}
		return nil, fmt.Errorf("error checking state file at %s: %w", statePath, err)
	}

	data, err := os.ReadFile(fmt.Sprintf("%s/%s", c.repoPath, c.usersState))
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %s %w", statePath, err)
	}

	log.Info("Successfully read state file", "size", len(data))

	var state UserState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}
	log.Info("Successfully loaded state",
		"roles", len(state.Roles),
		"namespaces", len(state.Namespaces),
		"users", len(state.Users))

	return &state, nil
}

func (c *UserController) reconcileRoles(ctx context.Context, roles map[string]Role) error {
	log := ctrl.Log.WithName("ClusterRoles")
	for roleName, roleSpec := range roles {
		log.Info("Creating/Updating Role",
			"roleName", roleName,
			"rules", roleSpec.Rules)

		role := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: roleName,
			},
			Rules: roleSpec.Rules,
		}

		log.Info("Creating Role")
		if roleBytes, err := yaml.Marshal(role); err == nil {
			log.Info("Role struture",
				"roleName", roleName,
				"roleYAML", string(roleBytes))
		}
		// Try to create first
		err := c.Client.Create(ctx, role)
		if err != nil {
			if !errors.IsAlreadyExists(err) {
				// If error is NOT AlreadyExists, return the error
				log.Error(err, "failed to create role")
				return fmt.Errorf("failed to create role %s: %w", roleName, err)
			}

			// If role exists, try to update it
			log.Info("Role exist...Updating Role:",
				"RoleName", roleName)
			if err := c.Client.Update(ctx, role); err != nil {
				return fmt.Errorf("failed to update role %s: %w", roleName, err)
			}
		}
	}

	return nil
}

func (c *UserController) reconcileUsers(ctx context.Context, users []User) error {
	log := ctrl.Log.WithName("Users")
	for _, user := range users {
		// First, check if certificates already exist for this user
		certPath := filepath.Join(c.certDir, fmt.Sprintf("%s.crt", user.Username))
		// keyPath := filepath.Join(c.certDir, fmt.Sprintf("%s.key", user.Username))

		certExists, err := PathExists(certPath)
		if err != nil {
			return fmt.Errorf("failed to check cert path for user %s: %w", user.Username, err)
		}

		if !certExists {
			// Generate certificate
			log.Info("Generating Cert for user:",
				"userName", user.Username)
			if err := c.generateUserCert(ctx, user); err != nil {
				return fmt.Errorf("failed to generate certificate for user %s: %w", user.Username, err)
			}
		}

		log.Info("Generating Role binding for that user")
		// Create role bindings
		for _, namespace := range user.Namespaces {
			binding := &rbacv1.RoleBinding{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      user.Username,
					Namespace: namespace,
				},
				Subjects: []rbacv1.Subject{},
				RoleRef:  rbacv1.RoleRef{},
			}
			binding.Name = fmt.Sprintf("%s-%s", user.Username, user.Role)
			binding.Namespace = namespace
			binding.Subjects = []rbacv1.Subject{{
				Kind:     "User",
				Name:     user.Email,
				APIGroup: "rbac.authorization.k8s.io",
			}}
			binding.RoleRef = rbacv1.RoleRef{
				Kind:     "ClusterRole",
				Name:     user.Role,
				APIGroup: "rbac.authorization.k8s.io",
			}

			log.Info("Creating Role binding")
			if err := c.Client.Create(ctx, binding); err != nil {
				if client.IgnoreAlreadyExists(err) != nil {
					return fmt.Errorf("failed to create role binding: %w", err)
				}
				if err := c.Client.Update(ctx, binding); err != nil {
					return fmt.Errorf("failed to update role binding: %w", err)
				}
			}
		}
	}
	return nil
}

func PathExists(path string) (exists bool, err error) {
	_, err = os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err // Return error for other cases (permission denied, etc.)
}

func (c *UserController) generateUserCert(ctx context.Context, user User) error {
	log := ctrl.Log.WithName("Cert")
	log.Info("Joining Cert Path")

	// Create user private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error(err, "Failed generating privatekey")
		return err
	}
	log.Info("Creating CSR template")
	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   user.Email,
			Organization: []string{"system:authenicated"},
		},
		DNSNames:           []string{user.Username},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privatekey)
	if err != nil {
		log.Error(err, "failed to Create CSR Rewquest")
		return err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	log.Info("Submitting CSR to K8s")
	// Submit CSR to k8s API
	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%d", user.Username, time.Now().Unix()),
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:           csrPEM,
			SignerName:        "kubernetes.io/kube-apiserver-client",
			ExpirationSeconds: pointer.Int32(86400 * 365),
			Usages:            []certificatesv1.KeyUsage{certificatesv1.UsageClientAuth, certificatesv1.UsageDigitalSignature, certificatesv1.UsageKeyEncipherment},
			Username:          user.Email,
			UID:               "",
			Groups:            []string{"system:authenticated"},
			Extra:             map[string]certificatesv1.ExtraValue{},
		},
	}

	log.Info("Creating CSR", "name", csr.Name, "user", user.Username)
	if err := c.Client.Create(ctx, csr); err != nil {
		log.Error(err, "failed to create CSR")
		return fmt.Errorf("failed to create CSR: %w", err)
	}
	// Wait for CSR to be ready
	log.Info("Waiting for CSR to be available")
	poller := wait.ConditionWithContextFunc(func(condCtx context.Context) (bool, error) {
		if err := c.Client.Get(condCtx, types.NamespacedName{
			Name: csr.Name,
		}, csr); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})

	err = wait.PollUntilContextTimeout(ctx, time.Second, time.Second*10, true, poller)
	if err != nil {
		return fmt.Errorf("failed waiting for CSR to be available: %w", err)
	}

	log.Info("Getting latest CSR version")
	latestCSR := &certificatesv1.CertificateSigningRequest{}
	if err := c.Client.Get(ctx, types.NamespacedName{Name: csr.Name}, latestCSR); err != nil {
		log.Error(err, "failed to get latest CSR")
		return fmt.Errorf("failed to get latest CSR: %w", err)
	}

	// Add the approval condition
	log.Info("Auto-approving CSR", "name", csr.Name)
	approvalCondition := certificatesv1.CertificateSigningRequestCondition{
		Type:               certificatesv1.CertificateApproved,
		Status:             corev1.ConditionTrue,
		Reason:             "AutoApproved",
		Message:            fmt.Sprintf("Auto-approved by rbac-controller for user %s", user.Username),
		LastTransitionTime: metav1.Now(),
		LastUpdateTime:     metav1.Now(),
	}

	log.Info("ApprovalCondtion Created")
	csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{approvalCondition}

	conditionsJSON, err := json.Marshal(latestCSR.Status.Conditions)
	if err != nil {
		log.Error(err, "failed to marshel conditions for logging")
	} else {
		log.Info("CSR Conditions",
			"name", latestCSR.Name,
			"conditions", string(conditionsJSON))
	}

	log.Info("Updating CSR status with approval")
	// patch := client.MergeFrom(originalCSR)

	_, err = c.certClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
	if err != nil {
		log.Error(err, "Failed to approve CSR")
		return fmt.Errorf("Failed to approve CSR: %w", err)
	}
	// if err := c.Client.Status().Patch(ctx, latestCSR, patch); err != nil {
	// 	log.Error(err, "Failed to approve CSR",
	// 		"name", latestCSR.Name,
	// 		"conditions", string(conditionsJSON))
	// 	return fmt.Errorf("failed to approve CSR: %w", err)
	// }

	log.Info("Waiting for Certificated to be issued")
	var cert []byte
	for i := 0; i < 10; i++ {
		if err := c.Client.Get(ctx, client.ObjectKey{Name: csr.Name}, csr); err != nil {
			return fmt.Errorf("failed to get CSR %w", err)
		}
		if csr.Status.Certificate != nil {
			cert = csr.Status.Certificate
			break
		}
		time.Sleep(time.Second)
	}
	if cert == nil {
		return fmt.Errorf("timeout waiting for certificate to be issued")
	}

	// Save private key and certificate on local container

	certPath := filepath.Join(c.certDir, fmt.Sprintf("%s.crt", user.Username))
	keyPath := filepath.Join(c.certDir, fmt.Sprintf("%s.key", user.Username))

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	if err := os.WriteFile(certPath, cert, 0600); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	// Create kubeconfig and store in secrets
	if err := c.generateKubeConfig(ctx, user.Username, certPath, keyPath); err != nil {
		return fmt.Errorf("failed to generate Kube config")
	}

	log.Info("Successfully generated certificate",
		"user", user.Username,
		"keyPath", keyPath,
		"cerPath", certPath)

	return nil

}

func cloneOrPullRepo(url, path string) (*git.Repository, error) {
	log := ctrl.Log.WithName("git")
	log.Info("Attempting git operation", "url", url, "path", path)

	_, err := os.Getwd()
	if err != nil {
		log.Error(err, "Failed to get current directory")
		return nil, err
	}

	if err := os.Chdir(path); err != nil {
		log.Error(err, "Failed to get current directory")
	}

	// Check if path exist and is not empty
	if dir, err := os.Open(path); err == nil {
		defer dir.Close()
		if _, err := dir.Readdir(1); err == nil {
			log.Info("Repository exists, attempting to pull")
			repo, err := git.PlainOpen(path)
			if err != nil {
				return nil, fmt.Errorf("failed to open repo: %w", err)
			}

			w, err := repo.Worktree()
			if err != nil {
				return nil, fmt.Errorf("failed to get worktree: %w", err)
			}

			err = w.Pull(&git.PullOptions{})
			if err != nil && err != git.NoErrAlreadyUpToDate {
				return nil, fmt.Errorf("failed to pull: %w", err)
			}
			return repo, nil
		}
	}

	log.Info("Directory doesn't exist, attempting to clone")
	_, err = git.PlainClone(path, false, &git.CloneOptions{
		URL:             url,
		InsecureSkipTLS: false,
		Progress:        os.Stdout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to clone: %w", err)
	}

	return nil, nil
}

func (c *UserController) isGitPullerHealthy() bool {
	return c.lastPullTime.Add(time.Minute).After(time.Now())
}

func (c *UserController) startGitPuller(ctx context.Context) error {
	log := ctrl.Log.WithName("gitPUller")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	log.Info("Pulling from git")
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			log.Info(c.repoURL)
			repo, err := cloneOrPullRepo(c.repoURL, c.repoPath)
			if err != nil {
				log.Error(err, "Failed to pull repository")
				return err
			}

			c.lastPullTime = time.Now()
			log.Info("Successfully pulled repository", "lastPull", c.lastPullTime)

			head, err := repo.Head()
			if err != nil {
				log.Error(err, "Failed to get head")
				return err
			}
			newCommit := head.Hash().String()
			if newCommit != c.lastCommit {
				log.Info("New commit")
				c.lastCommit = newCommit
				// Trigger reconciliation by updating a ConfigMap
				cm := &corev1.ConfigMap{}
				cm.Name = "user-controller-trigger"
				cm.Namespace = "default"
				cm.Data = map[string]string{"lastCommit": newCommit}

				if err := c.Client.Create(ctx, cm); err != nil {
					if client.IgnoreAlreadyExists(err) != nil {
						continue
					}
					if err := c.Client.Update(ctx, cm); err != nil {
						continue
					}
				}
			}
		}
	}
}

func (c *UserController) generateKubeConfig(ctx context.Context, username string, certPath string, keyPath string) error {
	// Read the certificate and key files
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key: %w", err)
	}

	// Get cluster CA cert
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get cluster config: %w", err)
	}

	// Create kubeconfig structure
	kubeConfig := clientcmdapi.Config{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters: map[string]*clientcmdapi.Cluster{
			"kubernetes": {
				Server:                   config.Host,
				CertificateAuthorityData: config.CAData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			username: {
				ClientCertificateData: cert,
				ClientKeyData:         key,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			username: {
				Cluster:  "kubernetes",
				AuthInfo: username,
			},
		},
		CurrentContext: username,
	}

	if err := c.saveUserKubeconfig(ctx, username, &kubeConfig); err != nil {
		return fmt.Errorf("failed to save kubeconfig: %w", err)
	}

	// Save the kubeconfig
	kubeconfigPath := filepath.Join(c.certDir, fmt.Sprintf("%s-kubeconfig", username))
	return clientcmd.WriteToFile(kubeConfig, kubeconfigPath)
}

func (c *UserController) saveUserKubeconfig(ctx context.Context, username string, kubeconfig *clientcmdapi.Config) error {
	// Convert kubeconfig to YAML
	kubeconfigYAML, err := clientcmd.Write(*kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to marshal kubeconfig: %w", err)
	}

	// Create a secret containing the kubeconfig
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("user-kubeconfig-%s", username),
			Namespace: "default",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "user-controller",
				"user.kubernetes.io/username":  username,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"kubeconfig": kubeconfigYAML,
		},
	}

	// Create or update the secret
	if err := c.Client.Create(ctx, secret); err != nil {
		if errors.IsAlreadyExists(err) {
			return c.Update(ctx, secret)
		}
		return err
	}

	return nil
}
