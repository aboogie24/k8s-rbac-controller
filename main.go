package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	Scheme     *runtime.Scheme
	repoPath   string
	certDir    string
	lastCommit string
}

func main() {
	// Set up logging
	opts := zap.Options{
		Development: true,
	}

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	// Get environment Vars
	repoURL := os.Getenv("GIT_REPO_URL")
	repoPath := os.Getenv("GIT_REPO_PATH")
	certDir := os.Getenv("CERT_DIR")

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme) // Register ConfigMap and other core types
	_ = rbacv1.AddToScheme(scheme) // Register RBAC types
	//_ = certificatesv1.AddToScheme(scheme) // Register Certificate type

	// Set up controller manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		fmt.Printf("Unable to start manager: %v\n", err)
		os.Exit(1)
	}

	// Clone repository if it doesn't exist
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		_, err = git.PlainClone(repoPath, false, &git.CloneOptions{
			URL: repoURL,
		})
		if err != nil {
			fmt.Printf("Failed to clone repository: %v\n", err)
			os.Exit(1)
		}
	}

	// Create and register controller
	controller := &UserController{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		repoPath: repoPath,
		certDir:  certDir,
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}). // We'll use a ConfigMap as our trigger
		Complete(controller); err != nil {
		fmt.Printf("Unable to create controller: %v\n", err)
		os.Exit(1)
	}

	// Start periodic Git pull
	go controller.startGitPuller(context.Background())

	// Start manager
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fmt.Printf("Problem running manager: %v\n", err)
		os.Exit(1)
	}
}

// Reconcile handles the reconciliation loop
func (c *UserController) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := log.FromContext(ctx)

	// Load state from Git
	state, err := c.loadState()
	if err != nil {
		log.Error(err, "Failed to load state")
		return reconcile.Result{}, err
	}

	// Reconcile roles
	if err := c.reconcileRoles(ctx, state.Roles); err != nil {
		log.Error(err, "Failed to reconcile roles")
		return reconcile.Result{}, err
	}

	// Reconcile users
	if err := c.reconcileUsers(ctx, state.Users); err != nil {
		log.Error(err, "Failed to reconcile users")
		return reconcile.Result{}, err
	}

	return reconcile.Result{RequeueAfter: time.Minute}, nil
}

func (c *UserController) loadState() (*UserState, error) {
	data, err := os.ReadFile(fmt.Sprintf("%s/users-state.yaml", c.repoPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var state UserState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	return &state, nil
}

func (c *UserController) reconcileRoles(ctx context.Context, roles map[string]Role) error {
	for roleName, roleSpec := range roles {
		role := &rbacv1.ClusterRole{}
		role.Name = roleName
		role.Rules = roleSpec.Rules

		if err := c.Client.Create(ctx, role); err != nil {
			if client.IgnoreAlreadyExists(err) != nil {
				return fmt.Errorf("failed to create role %s: %w", roleName, err)
			}
			if err := c.Client.Update(ctx, role); err != nil {
				return fmt.Errorf("failed to update role %s: %w", roleName, err)
			}
		}
	}
	return nil
}

func (c *UserController) reconcileUsers(ctx context.Context, users []User) error {
	for _, user := range users {
		// Generate certificate
		if err := c.generateUserCert(user); err != nil {
			return fmt.Errorf("failed to generate certificate for user %s: %w", user.Username, err)
		}

		// Create role bindings
		for _, namespace := range user.Namespaces {
			binding := &rbacv1.RoleBinding{}
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

func (c *UserController) generateUserCert(user User) error {
	certPath := filepath.Join(c.certDir, fmt.Sprintf("%s.crt", user.Username))
	//keyPath := filepath.Join(c.certDir, fmt.Sprintf("%s.key", user.Username))

	// Create user certificate and save the certificate on local drive
	err := signUserCertificate(user.Username, user.Email)
	if err != nil {
		return err
	}

	// Verify certificate
	_, err = PathExists(certPath)
	if err != nil {
		return err
	}

	_, err = isCertificateValid(certPath)
	if err != nil {
		return err
	}

	return nil
}

func (c *UserController) startGitPuller(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			repo, err := git.PlainOpen(c.repoPath)
			if err != nil {
				continue
			}

			worktree, err := repo.Worktree()
			if err != nil {
				continue
			}

			err = worktree.Pull(&git.PullOptions{})
			if err != nil && err != git.NoErrAlreadyUpToDate {
				continue
			}

			head, err := repo.Head()
			if err != nil {
				continue
			}

			newCommit := head.Hash().String()
			if newCommit != c.lastCommit {
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
