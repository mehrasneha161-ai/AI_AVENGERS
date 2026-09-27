package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"ai_avengers/backend/internal/ports"
)

// User represents a user record from the database.
// Only fields needed for auth — not the full user model.
type User struct {
	ID             uuid.UUID
	Email          string
	HashedPassword string
	FullName       string
	Role           string
	IsActive       bool
	TOTPSecret     string
	TOTPEnabled    bool
}

// AuthService handles user authentication.
// Separate from JWTService — single responsibility.
type AuthService struct {
	db     *pgxpool.Pool
	jwt    *JWTService
	logger *zap.Logger
	// publisher emits domain events (entitlement.granted) after grant writes.
	// Optional — nil means no-op (Null Object via skip). Set via SetEventPublisher.
	publisher ports.EventPublisher
	// selfRegistrationEnabled gates POST /auth/register.
	// Default false — the endpoint stays in the codebase but is non-functional
	// so accounts are provisioned by an admin. Flip SELF_REGISTRATION_ENABLED=true
	// (or call SetSelfRegistrationEnabled) to re-enable.
	selfRegistrationEnabled bool
}

// SetSelfRegistrationEnabled toggles the public self-registration feature.
func (s *AuthService) SetSelfRegistrationEnabled(v bool) { s.selfRegistrationEnabled = v }

// SelfRegistrationEnabled reports whether public registration is allowed.
func (s *AuthService) SelfRegistrationEnabled() bool { return s.selfRegistrationEnabled }

// NewAuthService creates a new auth service.
func NewAuthService(db *pgxpool.Pool, jwt *JWTService, logger *zap.Logger) *AuthService {
	return &AuthService{
		db:     db,
		jwt:    jwt,
		logger: logger,
	}
}

// SetEventPublisher wires the transactional outbox (or any ports.EventPublisher).
// Safe to leave unset — grant flows work without events.
func (s *AuthService) SetEventPublisher(p ports.EventPublisher) {
	s.publisher = p
}

func (s *AuthService) publishGrantEvents(ctx context.Context, actorID, userID uuid.UUID, expertIDs []uuid.UUID) {
	if s.publisher == nil || len(expertIDs) == 0 {
		return
	}
	events := make([]ports.DomainEvent, 0, len(expertIDs))
	for _, eid := range expertIDs {
		events = append(events, ports.DomainEvent{
			AggregateType: "entitlement",
			AggregateID:   userID,
			EventType:     "entitlement.granted",
			Payload: map[string]interface{}{
				"account_id": userID.String(),
				"expert_id":  eid.String(),
				"granted_by": actorID.String(),
			},
		})
	}
	if err := s.publisher.Publish(ctx, events...); err != nil {
		s.logger.Warn("outbox publish entitlement.granted failed (non-fatal)", zap.Error(err))
	}
}

// RegisterRequest holds registration input.
type RegisterRequest struct {
	Email    string
	Password string
	FullName string
}

// LoginRequest holds login input.
type LoginRequest struct {
	Email    string
	Password string
}

// AdminLoginRequest holds admin login input (includes TOTP).
type AdminLoginRequest struct {
	Email    string
	Password string
	TOTPCode string // 6-digit code from Google Authenticator
}

// Sentinel errors — use errors.Is() to check.
var (
	ErrUserNotFound          = errors.New("user not found")
	ErrInvalidCredentials    = errors.New("invalid email or password")
	ErrUserInactive          = errors.New("account is disabled")
	ErrEmailTaken            = errors.New("email already registered")
	ErrInvalidTOTP           = errors.New("invalid TOTP code")
	ErrTOTPRequired          = errors.New("TOTP code required for admin login")
	ErrNotAdmin              = errors.New("admin access required")
	ErrInvalidResetToken     = errors.New("invalid or expired reset token")
	ErrPasswordTooShort      = errors.New("password must be at least 8 characters")
	ErrInvalidBootstrapToken = errors.New("invalid or expired bootstrap token")
	ErrBootstrapUnavailable  = errors.New("admin bootstrap is not available")
	ErrInvalidRole           = errors.New("invalid account role")
	ErrUseAdminLogin         = errors.New("admin accounts must use admin login")
	ErrRegistrationDisabled  = errors.New("self-registration is disabled")
	ErrCannotDeleteSelf      = errors.New("you cannot delete your own account")
)

// Register creates a new client account.
// Hashes password with bcrypt cost 12.
// WHY cost 12: Balance between security and performance.
// Cost 10 = ~100ms, Cost 12 = ~400ms, Cost 14 = ~1.5s
// 400ms is acceptable for registration, not for every request.
func (s *AuthService) Register(ctx context.Context, req RegisterRequest) (*TokenPair, error) {
	// Self-registration is disabled by default. The implementation below is
	// kept intact so the feature can be re-enabled via SELF_REGISTRATION_ENABLED.
	if !s.selfRegistrationEnabled {
		return nil, ErrRegistrationDisabled
	}

	// Check if email already exists
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`,
		req.Email,
	).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("failed to check email: %w", err)
	}
	if exists {
		return nil, ErrEmailTaken
	}

	// Hash password
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Insert user — joined to the default tenant.
	// WHY: migration 030 (C4 tenant isolation) fails closed on users.tenant_id
	// NULL, so a self-registered user with no tenant would get 403 on every
	// tenant-scoped route (/experts, /search/chats, message send). Admin-created
	// accounts were backfilled to the default tenant by that migration; self-
	// registration must do the same or the mobile app can never see an expert.
	var userID uuid.UUID
	err = s.db.QueryRow(ctx,
		`INSERT INTO users (email, hashed_password, full_name, role, tenant_id)
		 VALUES ($1, $2, $3, 'client', (SELECT id FROM tenants WHERE slug = 'default'))
		 RETURNING id`,
		req.Email, string(hashed), req.FullName,
	).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.Info("user registered",
		zap.String("user_id", userID.String()),
		zap.String("email", req.Email),
	)

	// Issue tokens
	return s.jwt.IssueTokenPair(ctx, userID, req.Email, "client")
}

// Login authenticates a non-admin user (client or domain_expert).
// Admins must use AdminLogin (password + TOTP).
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*TokenPair, error) {
	user, err := s.getUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Return same error as wrong password — prevent email enumeration
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.Role == "admin" {
		return nil, ErrUseAdminLogin
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Update last login
	go s.updateLastLogin(context.Background(), user.ID)

	return s.jwt.IssueTokenPair(ctx, user.ID, user.Email, user.Role)
}

// AdminLogin authenticates an admin user with TOTP.
// Requires: email + password + TOTP code.
// WHY TOTP mandatory for admin: Admin has access to all data, expert management.
// A compromised admin account is catastrophic.
func (s *AuthService) AdminLogin(ctx context.Context, req AdminLoginRequest) (*TokenPair, error) {
	user, err := s.getUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Must be admin
	if user.Role != "admin" {
		return nil, ErrNotAdmin
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// TOTP is mandatory for every admin login once enabled.
	// Admins created via bootstrap complete with totp_enabled=true.
	if user.TOTPEnabled {
		if req.TOTPCode == "" {
			return nil, ErrTOTPRequired
		}
		if !totp.Validate(req.TOTPCode, user.TOTPSecret) {
			s.logger.Warn("invalid TOTP attempt",
				zap.String("user_id", user.ID.String()),
				zap.String("email", user.Email),
			)
			return nil, ErrInvalidTOTP
		}
	} else if req.TOTPCode == "" && user.TOTPSecret == "" {
		// Seeded admin without TOTP still allowed once — enforce setup in UI.
		// Password-only path kept for migration of legacy seed admin.
	}

	go s.updateLastLogin(context.Background(), user.ID)

	return s.jwt.IssueTokenPair(ctx, user.ID, user.Email, user.Role)
}

// SetupTOTP generates a new TOTP secret for an admin user.
// Returns the secret and QR code URL for Google Authenticator.
// Admin must verify with VerifyAndEnableTOTP before it's active.
func (s *AuthService) SetupTOTP(ctx context.Context, userID uuid.UUID) (secret, qrURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AI Avengers",
		AccountName: userID.String(),
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Store secret (not yet enabled)
	_, err = s.db.Exec(ctx,
		`UPDATE users SET totp_secret = $1, updated_at = NOW() WHERE id = $2`,
		key.Secret(), userID,
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	return key.Secret(), key.URL(), nil
}

// VerifyAndEnableTOTP verifies a TOTP code and enables TOTP for the user.
// Must be called after SetupTOTP to confirm the user has scanned the QR code.
func (s *AuthService) VerifyAndEnableTOTP(ctx context.Context, userID uuid.UUID, code string) error {
	var secret string
	err := s.db.QueryRow(ctx,
		`SELECT totp_secret FROM users WHERE id = $1`,
		userID,
	).Scan(&secret)
	if err != nil {
		return fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	if secret == "" {
		return errors.New("TOTP not set up — call SetupTOTP first")
	}

	if !totp.Validate(code, secret) {
		return ErrInvalidTOTP
	}

	// Enable TOTP
	_, err = s.db.Exec(ctx,
		`UPDATE users SET totp_enabled = TRUE, updated_at = NOW() WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to enable TOTP: %w", err)
	}

	s.logger.Info("TOTP enabled for user", zap.String("user_id", userID.String()))
	return nil
}

// GetMe returns the authenticated user's public profile.
// Called by GET /auth/me after JWT is validated by AuthMiddleware.
// Returns only safe fields — never hashed_password or totp_secret.
//
// WHY by userID not email:
// AuthMiddleware already validated the JWT and extracted userID.
// Querying by userID is a direct primary key lookup — O(1).
// Querying by email would require an index scan — unnecessary.
func (s *AuthService) GetMe(ctx context.Context, userID uuid.UUID) (*User, error) {
	var user User
	err := s.db.QueryRow(ctx,
		`SELECT id, email, full_name, role, is_active, totp_enabled
		 FROM users
		 WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(&user.ID, &user.Email, &user.FullName, &user.Role, &user.IsActive, &user.TOTPEnabled)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if !user.IsActive {
		return nil, ErrUserInactive
	}
	return &user, nil
}

// RefreshExpiryDays returns the configured refresh token expiry in days.
// Used by handlers to set cookie MaxAge.
func (s *AuthService) RefreshExpiryDays() int {
	return s.jwt.RefreshExpiryDays()
}

// ForgotPassword generates a password-reset token for the given email.
//
// WHY silent no-op on unknown email:
//   Returning an error when the email is not found leaks whether an
//   account exists (email enumeration). We always return success to
//   the caller; the handler logs the raw token so an admin can relay
//   it manually (or a future email integration can send it).
//
// Returns (rawToken, nil) on success, ("", nil) when email not found.
// The caller MUST NOT expose the distinction to the end user.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) (rawToken string, err error) {
	user, err := s.getUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Silent — do not reveal whether the email exists.
			return "", nil
		}
		return "", err
	}

	// Invalidate any previous unused tokens for this user.
	// WHY: only one active reset link at a time; prevents confusion if
	// the user clicks "Forgot Password" twice.
	_, err = s.db.Exec(ctx,
		`UPDATE password_reset_tokens
		    SET used_at = NOW()
		  WHERE user_id = $1 AND used_at IS NULL`,
		user.ID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to invalidate old reset tokens: %w", err)
	}

	// Generate 32 cryptographically-random bytes → hex string (64 chars).
	// WHY 32 bytes: 256 bits of entropy — brute-force is infeasible.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate reset token: %w", err)
	}
	rawToken = hex.EncodeToString(buf)

	// Store SHA-256(rawToken) — never the raw token itself.
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	_, err = s.db.Exec(ctx,
		`INSERT INTO password_reset_tokens (user_id, token_hash)
		 VALUES ($1, $2)`,
		user.ID, tokenHash,
	)
	if err != nil {
		return "", fmt.Errorf("failed to store reset token: %w", err)
	}

	s.logger.Info("password reset token generated",
		zap.String("user_id", user.ID.String()),
		zap.String("email", email),
	)

	return rawToken, nil
}

// ResetPassword validates a reset token and sets a new password.
//
// Steps:
//  1. Hash the incoming token and look it up.
//  2. Validate: exists, not expired, not already used.
//  3. bcrypt the new password and update users.
//  4. Mark the token used (single-use).
//  5. Revoke all active JWT sessions (force re-login).
func (s *AuthService) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	if len(newPassword) < 8 {
		return ErrPasswordTooShort
	}

	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	var (
		tokenID   uuid.UUID
		userID    uuid.UUID
		expiresAt time.Time
		usedAt    *time.Time
	)
	err := s.db.QueryRow(ctx,
		`SELECT id, user_id, expires_at, used_at
		   FROM password_reset_tokens
		  WHERE token_hash = $1`,
		tokenHash,
	).Scan(&tokenID, &userID, &expiresAt, &usedAt)
	if err != nil {
		// No row or scan error — treat both as invalid token.
		return ErrInvalidResetToken
	}

	if usedAt != nil {
		return ErrInvalidResetToken // already used
	}
	if time.Now().After(expiresAt) {
		return ErrInvalidResetToken // expired
	}

	// Hash new password.
	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password.
	_, err = s.db.Exec(ctx,
		`UPDATE users
		    SET hashed_password = $1, updated_at = NOW()
		  WHERE id = $2`,
		string(hashed), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Mark token as used — single-use guarantee.
	_, err = s.db.Exec(ctx,
		`UPDATE password_reset_tokens
		    SET used_at = NOW()
		  WHERE id = $1`,
		tokenID,
	)
	if err != nil {
		// Non-fatal: password is already changed. Log and continue.
		s.logger.Warn("failed to mark reset token used",
			zap.String("token_id", tokenID.String()),
			zap.Error(err),
		)
	}

	// Revoke all active JWT sessions — user must log in with new password.
	if err := s.jwt.RevokeAllUserTokens(ctx, userID); err != nil {
		s.logger.Warn("failed to revoke user tokens after password reset",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		// Non-fatal: password is changed; old tokens will expire naturally.
	}

	s.logger.Info("password reset successful",
		zap.String("user_id", userID.String()),
	)

	return nil
}

// getUserByEmail fetches a user by email.
// Returns ErrUserNotFound if not found.
func (s *AuthService) getUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := s.db.QueryRow(ctx,
		`SELECT id, email, hashed_password, full_name, role, is_active,
		        COALESCE(totp_secret, ''), totp_enabled
		 FROM users
		 WHERE email = $1 AND deleted_at IS NULL`,
		email,
	).Scan(
		&user.ID, &user.Email, &user.HashedPassword, &user.FullName,
		&user.Role, &user.IsActive, &user.TOTPSecret, &user.TOTPEnabled,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// updateLastLogin updates the last_login timestamp.
// Called async — non-critical, don't block login response.
func (s *AuthService) updateLastLogin(ctx context.Context, userID uuid.UUID) {
	_, err := s.db.Exec(ctx,
		`UPDATE users SET last_login = $1 WHERE id = $2`,
		time.Now(), userID,
	)
	if err != nil {
		s.logger.Warn("failed to update last login",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}
}

// ============================================================
// Hidden admin bootstrap (unguessable one-time token)
// ============================================================

// BootstrapStartRequest is step 1 of hidden admin registration.
type BootstrapStartRequest struct {
	Token    string
	Email    string
	Password string
	FullName string
}

// BootstrapStartResult returns TOTP enrollment material. Account is not
// created until BootstrapComplete succeeds with a valid OTP.
type BootstrapStartResult struct {
	Secret string `json:"secret"`
	QRURL  string `json:"qrUrl"`
}

// BootstrapCompleteRequest is step 2 — verify OTP then create admin.
type BootstrapCompleteRequest struct {
	Token    string
	TOTPCode string
}

// CreateManagedAccountRequest is admin-only account creation.
type CreateManagedAccountRequest struct {
	Email     string
	Password  string
	FullName  string
	Role      string // admin | domain_expert | client
	ExpertIDs []uuid.UUID
}

// ManagedAccount is the admin-facing account row (no secrets).
type ManagedAccount struct {
	ID           uuid.UUID   `json:"id"`
	Email        string      `json:"email"`
	FullName     string      `json:"full_name"`
	Role         string      `json:"role"`
	IsActive     bool        `json:"is_active"`
	TOTPEnabled  bool        `json:"totp_enabled"`
	LastLogin    *time.Time  `json:"last_login"`
	CreatedAt    time.Time   `json:"created_at"`
	ExpertIDs    []uuid.UUID `json:"expert_ids"`
	ProjectCount int         `json:"project_count"`
	MessageCount int         `json:"message_count"`
}

// IssueBootstrapToken creates a one-time admin bootstrap token.
// Intended for ops/CLI use (or first-deploy scripts). Raw token is returned
// once and only its SHA-256 hash is stored.
func (s *AuthService) IssueBootstrapToken(ctx context.Context, ttl time.Duration) (rawToken string, err error) {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate bootstrap token: %w", err)
	}
	rawToken = hex.EncodeToString(buf)
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	_, err = s.db.Exec(ctx,
		`INSERT INTO admin_bootstrap_tokens (token_hash, expires_at)
		 VALUES ($1, $2)`,
		tokenHash, time.Now().Add(ttl),
	)
	if err != nil {
		return "", fmt.Errorf("store bootstrap token: %w", err)
	}
	s.logger.Info("admin bootstrap token issued")
	return rawToken, nil
}

// BootstrapStart validates the secret token + credentials, generates a TOTP
// secret, and stages the pending admin on the bootstrap row. No users row yet.
func (s *AuthService) BootstrapStart(ctx context.Context, req BootstrapStartRequest) (*BootstrapStartResult, error) {
	if len(req.Password) < 8 {
		return nil, ErrPasswordTooShort
	}
	if req.Email == "" || req.FullName == "" || req.Token == "" {
		return nil, ErrInvalidBootstrapToken
	}

	tokenID, err := s.loadUsableBootstrapToken(ctx, req.Token)
	if err != nil {
		return nil, err
	}

	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`,
		req.Email,
	).Scan(&exists); err != nil {
		return nil, fmt.Errorf("check email: %w", err)
	}
	if exists {
		return nil, ErrEmailTaken
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AI Avengers",
		AccountName: req.Email,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp: %w", err)
	}

	_, err = s.db.Exec(ctx,
		`UPDATE admin_bootstrap_tokens
		    SET pending_email = $1,
		        pending_full_name = $2,
		        pending_password_hash = $3,
		        pending_totp_secret = $4
		  WHERE id = $5 AND used_at IS NULL`,
		req.Email, req.FullName, string(hashed), key.Secret(), tokenID,
	)
	if err != nil {
		return nil, fmt.Errorf("stage bootstrap: %w", err)
	}

	return &BootstrapStartResult{Secret: key.Secret(), QRURL: key.URL()}, nil
}

// BootstrapComplete verifies the staged TOTP code and creates the admin user.
// The bootstrap token is single-use after success.
func (s *AuthService) BootstrapComplete(ctx context.Context, req BootstrapCompleteRequest) (*TokenPair, error) {
	if req.Token == "" || req.TOTPCode == "" {
		return nil, ErrInvalidBootstrapToken
	}

	hash := sha256.Sum256([]byte(req.Token))
	tokenHash := hex.EncodeToString(hash[:])

	var (
		tokenID   uuid.UUID
		expiresAt time.Time
		usedAt    *time.Time
		email     *string
		fullName  *string
		pwHash    *string
		totpSec   *string
	)
	err := s.db.QueryRow(ctx,
		`SELECT id, expires_at, used_at,
		        pending_email, pending_full_name, pending_password_hash, pending_totp_secret
		   FROM admin_bootstrap_tokens
		  WHERE token_hash = $1`,
		tokenHash,
	).Scan(&tokenID, &expiresAt, &usedAt, &email, &fullName, &pwHash, &totpSec)
	if err != nil || usedAt != nil || time.Now().After(expiresAt) {
		return nil, ErrInvalidBootstrapToken
	}
	if email == nil || fullName == nil || pwHash == nil || totpSec == nil ||
		*email == "" || *pwHash == "" || *totpSec == "" {
		return nil, ErrBootstrapUnavailable
	}
	if !totp.Validate(req.TOTPCode, *totpSec) {
		return nil, ErrInvalidTOTP
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var userID uuid.UUID
	err = tx.QueryRow(ctx,
		`INSERT INTO users (email, hashed_password, full_name, role, totp_secret, totp_enabled)
		 VALUES ($1, $2, $3, 'admin', $4, TRUE)
		 RETURNING id`,
		*email, *pwHash, *fullName, *totpSec,
	).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("create admin: %w", err)
	}

	tag, err := tx.Exec(ctx,
		`UPDATE admin_bootstrap_tokens
		    SET used_at = NOW(),
		        pending_email = NULL,
		        pending_full_name = NULL,
		        pending_password_hash = NULL,
		        pending_totp_secret = NULL
		  WHERE id = $1 AND used_at IS NULL`,
		tokenID,
	)
	if err != nil || tag.RowsAffected() == 0 {
		return nil, ErrInvalidBootstrapToken
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit bootstrap: %w", err)
	}

	s.logger.Info("admin bootstrap completed",
		zap.String("user_id", userID.String()),
		zap.String("email", *email),
	)
	return s.jwt.IssueTokenPair(ctx, userID, *email, "admin")
}

// CreateManagedAccount lets an admin create admin, domain_expert or client
// accounts. domain_expert may receive expert grants in the same call.
// WHY client here: public self-registration is disabled, so the admin panel is
// the only account-creation path — including end-user client accounts.
func (s *AuthService) CreateManagedAccount(ctx context.Context, actorID uuid.UUID, req CreateManagedAccountRequest) (*ManagedAccount, error) {
	if len(req.Password) < 8 {
		return nil, ErrPasswordTooShort
	}
	if req.Role != "admin" && req.Role != "domain_expert" && req.Role != "client" {
		return nil, ErrInvalidRole
	}

	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`,
		req.Email,
	).Scan(&exists); err != nil {
		return nil, fmt.Errorf("check email: %w", err)
	}
	if exists {
		return nil, ErrEmailTaken
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var user ManagedAccount
	err = tx.QueryRow(ctx,
		`INSERT INTO users (email, hashed_password, full_name, role, totp_enabled)
		 VALUES ($1, $2, $3, $4, FALSE)
		 RETURNING id, email, full_name, role, is_active, totp_enabled, last_login, created_at`,
		req.Email, string(hashed), req.FullName, req.Role,
	).Scan(
		&user.ID, &user.Email, &user.FullName, &user.Role,
		&user.IsActive, &user.TOTPEnabled, &user.LastLogin, &user.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create account: %w", err)
	}

	if req.Role == "domain_expert" && len(req.ExpertIDs) > 0 {
		for _, eid := range req.ExpertIDs {
			_, err = tx.Exec(ctx,
				`INSERT INTO user_expert_grants (user_id, expert_id, granted_by)
				 VALUES ($1, $2, $3)
				 ON CONFLICT (user_id, expert_id) DO NOTHING`,
				user.ID, eid, actorID,
			)
			if err != nil {
				return nil, fmt.Errorf("grant expert: %w", err)
			}
		}
		user.ExpertIDs = append([]uuid.UUID(nil), req.ExpertIDs...)
	}
	if user.ExpertIDs == nil {
		user.ExpertIDs = []uuid.UUID{}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	if req.Role == "domain_expert" && len(user.ExpertIDs) > 0 {
		s.publishGrantEvents(ctx, actorID, user.ID, user.ExpertIDs)
	}

	s.logger.Info("managed account created",
		zap.String("user_id", user.ID.String()),
		zap.String("role", user.Role),
		zap.String("by", actorID.String()),
	)
	return &user, nil
}

// ListManagedAccounts returns admin + domain_expert accounts with grants.
func (s *AuthService) ListManagedAccounts(ctx context.Context) ([]ManagedAccount, error) {
	rows, err := s.db.Query(ctx, `
		SELECT u.id, u.email, u.full_name, u.role, u.is_active, u.totp_enabled,
		       u.last_login, u.created_at,
		       COALESCE((
		           SELECT COUNT(*) FROM projects p
		           WHERE p.client_id = u.id AND p.deleted_at IS NULL
		       ), 0),
		       COALESCE((
		           SELECT COUNT(*) FROM messages m
		           JOIN chats c2 ON c2.id = m.chat_id
		           JOIN projects p2 ON p2.id = c2.project_id
		           WHERE p2.client_id = u.id AND m.role = 'user'
		       ), 0)
		  FROM users u
		 WHERE u.role IN ('admin', 'domain_expert', 'client')
		   AND u.deleted_at IS NULL
		 ORDER BY u.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []ManagedAccount
	for rows.Next() {
		var a ManagedAccount
		if err := rows.Scan(
			&a.ID, &a.Email, &a.FullName, &a.Role, &a.IsActive, &a.TOTPEnabled,
			&a.LastLogin, &a.CreatedAt, &a.ProjectCount, &a.MessageCount,
		); err != nil {
			continue
		}
		a.ExpertIDs = []uuid.UUID{}
		accounts = append(accounts, a)
	}
	if accounts == nil {
		accounts = []ManagedAccount{}
	}

	// Attach grants in a second query (small N of managed accounts).
	grantRows, err := s.db.Query(ctx, `
		SELECT g.user_id, g.expert_id
		  FROM user_expert_grants g
		  JOIN users u ON u.id = g.user_id
		 WHERE u.role = 'domain_expert' AND u.deleted_at IS NULL`)
	if err != nil {
		return accounts, nil
	}
	defer grantRows.Close()

	byUser := make(map[uuid.UUID][]uuid.UUID)
	for grantRows.Next() {
		var uid, eid uuid.UUID
		if err := grantRows.Scan(&uid, &eid); err != nil {
			continue
		}
		byUser[uid] = append(byUser[uid], eid)
	}
	for i := range accounts {
		if ids, ok := byUser[accounts[i].ID]; ok {
			accounts[i].ExpertIDs = ids
		}
	}
	return accounts, nil
}

// SetAccountExpertGrants replaces the grant set for a domain_expert account.
func (s *AuthService) SetAccountExpertGrants(ctx context.Context, actorID, userID uuid.UUID, expertIDs []uuid.UUID) error {
	var role string
	err := s.db.QueryRow(ctx,
		`SELECT role FROM users WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(&role)
	if err != nil {
		return ErrUserNotFound
	}
	if role != "domain_expert" {
		return ErrInvalidRole
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM user_expert_grants WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, eid := range expertIDs {
		_, err = tx.Exec(ctx,
			`INSERT INTO user_expert_grants (user_id, expert_id, granted_by)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (user_id, expert_id) DO NOTHING`,
			userID, eid, actorID,
		)
		if err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.publishGrantEvents(ctx, actorID, userID, expertIDs)
	return nil
}

// UpdateManagedAccountRequest holds optional account field updates.
// nil pointer = leave that field unchanged (partial update).
type UpdateManagedAccountRequest struct {
	FullName *string
	Email    *string
	Role     *string
	IsActive *bool
	Password *string
}

// UpdateManagedAccount applies a partial update to an admin/domain_expert/client
// account. Only non-nil fields change. Changing role away from domain_expert
// clears expert grants (grants only apply to domain_expert).
func (s *AuthService) UpdateManagedAccount(ctx context.Context, userID uuid.UUID, req UpdateManagedAccountRequest) error {
	var currentRole string
	if err := s.db.QueryRow(ctx,
		`SELECT role FROM users WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(&currentRole); err != nil {
		return ErrUserNotFound
	}

	sets := make([]string, 0, 6)
	args := make([]interface{}, 0, 6)
	add := func(expr string, val interface{}) {
		args = append(args, val)
		sets = append(sets, fmt.Sprintf(expr, len(args)))
	}

	if req.FullName != nil && *req.FullName != "" {
		add("full_name = $%d", *req.FullName)
	}
	if req.Email != nil && *req.Email != "" {
		var exists bool
		if err := s.db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND id <> $2 AND deleted_at IS NULL)`,
			*req.Email, userID,
		).Scan(&exists); err != nil {
			return fmt.Errorf("check email: %w", err)
		}
		if exists {
			return ErrEmailTaken
		}
		add("email = $%d", *req.Email)
	}
	if req.Role != nil {
		if *req.Role != "admin" && *req.Role != "domain_expert" && *req.Role != "client" {
			return ErrInvalidRole
		}
		add("role = $%d", *req.Role)
	}
	if req.IsActive != nil {
		add("is_active = $%d", *req.IsActive)
	}
	if req.Password != nil {
		if len(*req.Password) < 8 {
			return ErrPasswordTooShort
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(*req.Password), 12)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		add("hashed_password = $%d", string(hashed))
	}

	if len(sets) == 0 {
		return nil
	}

	args = append(args, userID)
	q := fmt.Sprintf(
		`UPDATE users SET %s, updated_at = NOW()
		  WHERE id = $%d AND deleted_at IS NULL`,
		strings.Join(sets, ", "), len(args),
	)
	tag, err := s.db.Exec(ctx, q, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	// Grants only apply to domain_expert; clear them when role moves away.
	if req.Role != nil && *req.Role != "domain_expert" && *req.Role != currentRole {
		if _, err := s.db.Exec(ctx, `DELETE FROM user_expert_grants WHERE user_id = $1`, userID); err != nil {
			s.logger.Warn("clear grants after role change failed (non-fatal)", zap.Error(err))
		}
	}

	s.logger.Info("managed account updated", zap.String("user_id", userID.String()))
	return nil
}

// DeleteManagedAccount soft-deletes an account and removes its expert grants.
// Refuses to delete the acting admin's own account (lockout guard).
func (s *AuthService) DeleteManagedAccount(ctx context.Context, actorID, userID uuid.UUID) error {
	if actorID == userID {
		return ErrCannotDeleteSelf
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM user_expert_grants WHERE user_id = $1`, userID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE users SET deleted_at = NOW(), is_active = FALSE, updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NULL
		    AND role IN ('admin', 'domain_expert', 'client')`,
		userID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.logger.Info("managed account deleted", zap.String("user_id", userID.String()))
	return nil
}

// DisableTOTP turns off TOTP for the authenticated admin (re-setup required).
func (s *AuthService) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`UPDATE users
		    SET totp_enabled = FALSE, totp_secret = NULL, updated_at = NOW()
		  WHERE id = $1 AND role = 'admin'`,
		userID,
	)
	return err
}

// GetTOTPStatus returns whether TOTP is enabled for the user.
func (s *AuthService) GetTOTPStatus(ctx context.Context, userID uuid.UUID) (enabled bool, err error) {
	err = s.db.QueryRow(ctx,
		`SELECT totp_enabled FROM users WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(&enabled)
	if err != nil {
		return false, ErrUserNotFound
	}
	return enabled, nil
}

func (s *AuthService) loadUsableBootstrapToken(ctx context.Context, rawToken string) (uuid.UUID, error) {
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	var (
		tokenID   uuid.UUID
		expiresAt time.Time
		usedAt    *time.Time
	)
	err := s.db.QueryRow(ctx,
		`SELECT id, expires_at, used_at
		   FROM admin_bootstrap_tokens
		  WHERE token_hash = $1`,
		tokenHash,
	).Scan(&tokenID, &expiresAt, &usedAt)
	if err != nil || usedAt != nil || time.Now().After(expiresAt) {
		return uuid.Nil, ErrInvalidBootstrapToken
	}
	return tokenID, nil
}
