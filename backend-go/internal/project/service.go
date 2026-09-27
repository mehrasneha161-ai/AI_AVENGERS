package project

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"ai_avengers/backend/internal/auth"
	"ai_avengers/backend/internal/response"
)

// Project is the full project record.
type Project struct {
	ID               uuid.UUID  `json:"id"`
	ClientID         uuid.UUID  `json:"client_id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Status           string     `json:"status"`
	RepoURL          string     `json:"repo_url,omitempty"`
	RepoProvider     string     `json:"repo_provider,omitempty"`
	RepoBranch       string     `json:"repo_branch,omitempty"`
	RepoConnected    bool       `json:"repo_connected"`
	TechStack        map[string]interface{} `json:"tech_stack"`
	ArchitectureType string     `json:"architecture_type,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Experts          []ProjectExpert `json:"experts"`
}

// ProjectExpert is an expert assigned to a project.
type ProjectExpert struct {
	ExpertID   uuid.UUID `json:"expert_id"`
	ExpertName string    `json:"expert_name"`
	Domain     string    `json:"domain"`
	AddedAt    time.Time `json:"added_at"`
	IsActive   bool      `json:"is_active"`
}

// CreateProjectRequest holds input for creating a project.
type CreateProjectRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=500"`
	Description string `json:"description"`
}

// UpdateProjectRequest holds input for updating a project.
type UpdateProjectRequest struct {
	Name             *string                 `json:"name"`
	Description      *string                 `json:"description"`
	ArchitectureType *string                 `json:"architecture_type"`
	TechStack        *map[string]interface{} `json:"tech_stack"`
	// Status: 'active' to enable, 'archived' to disable.
	// 'archived' moves project to passive section in UI.
	// 'active' restores it to active section.
	Status           *string `json:"status"`
}

// Service handles project business logic.
type Service struct {
	db     *pgxpool.Pool
	logger *zap.Logger
}

// NewService creates a new project service.
func NewService(db *pgxpool.Pool, logger *zap.Logger) *Service {
	return &Service{db: db, logger: logger}
}

// Create creates a new project for a client.
func (s *Service) Create(ctx context.Context, clientID uuid.UUID, req CreateProjectRequest) (*Project, error) {
	var p Project
	err := s.db.QueryRow(ctx,
		`INSERT INTO projects (client_id, name, description, tenant_id)
		 VALUES ($1, $2, $3,
		         COALESCE((SELECT tenant_id FROM users WHERE id = $1),
		                  (SELECT id FROM tenants WHERE slug = 'default')))
		 RETURNING id, client_id, name, COALESCE(description,''), status,
		           COALESCE(repo_url,''), COALESCE(repo_provider,''),
		           COALESCE(repo_branch,'main'), repo_connected, created_at, updated_at`,
		clientID, req.Name, req.Description,
	).Scan(
		&p.ID, &p.ClientID, &p.Name, &p.Description, &p.Status,
		&p.RepoURL, &p.RepoProvider, &p.RepoBranch, &p.RepoConnected,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create project failed: %w", err)
	}
	s.logger.Info("project created",
		zap.String("project_id", p.ID.String()),
		zap.String("client_id", clientID.String()),
	)
	return &p, nil
}

// List returns all active projects for a client.
func (s *Service) List(ctx context.Context, clientID uuid.UUID) ([]Project, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, client_id, name, COALESCE(description,''), status,
		        COALESCE(repo_url,''), COALESCE(repo_provider,''),
		        COALESCE(repo_branch,'main'), repo_connected,
		        COALESCE(tech_stack, '{}'), COALESCE(architecture_type,''),
		        created_at, updated_at
		 FROM projects
		 WHERE client_id=$1 AND deleted_at IS NULL
		 ORDER BY updated_at DESC`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("list projects failed: %w", err)
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(
			&p.ID, &p.ClientID, &p.Name, &p.Description, &p.Status,
			&p.RepoURL, &p.RepoProvider, &p.RepoBranch, &p.RepoConnected,
			&p.TechStack, &p.ArchitectureType, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			continue
		}
		p.Experts = []ProjectExpert{}
		projects = append(projects, p)
	}
	if projects == nil {
		projects = []Project{}
	}

	// Batch-load real experts for every listed project in a single
	// query (project_id = ANY(...)), instead of N+1 per-project calls -
	// List() previously never loaded Experts at all (only GetByID did).
	if len(projects) > 0 {
		ids := make([]uuid.UUID, len(projects))
		for i, p := range projects {
			ids[i] = p.ID
		}
		expertRows, err := s.db.Query(ctx,
			`SELECT pe.project_id, pe.expert_id, e.name, e.domain, pe.added_at, pe.is_active
			 FROM project_experts pe
			 JOIN experts e ON e.id = pe.expert_id
			 WHERE pe.project_id = ANY($1) AND pe.is_active = TRUE
			 ORDER BY pe.added_at ASC`,
			ids,
		)
		if err != nil {
			s.logger.Warn("batch load project experts failed", zap.Error(err))
		} else {
			defer expertRows.Close()
			byProject := make(map[uuid.UUID][]ProjectExpert)
			for expertRows.Next() {
				var projectID uuid.UUID
				var e ProjectExpert
				if err := expertRows.Scan(&projectID, &e.ExpertID, &e.ExpertName, &e.Domain, &e.AddedAt, &e.IsActive); err != nil {
					continue
				}
				byProject[projectID] = append(byProject[projectID], e)
			}
			for i := range projects {
				if experts, ok := byProject[projects[i].ID]; ok {
					projects[i].Experts = experts
				}
			}
		}
	}

	return projects, nil
}

// GetByID returns a project with its experts.
// Verifies the project belongs to the requesting client.
func (s *Service) GetByID(ctx context.Context, projectID, clientID uuid.UUID) (*Project, error) {
	var p Project
	err := s.db.QueryRow(ctx,
		`SELECT id, client_id, name, COALESCE(description,''), status,
		        COALESCE(repo_url,''), COALESCE(repo_provider,''),
		        COALESCE(repo_branch,'main'), repo_connected,
		        COALESCE(tech_stack, '{}'), COALESCE(architecture_type,''),
		        created_at, updated_at
		 FROM projects
		 WHERE id=$1 AND client_id=$2 AND deleted_at IS NULL`,
		projectID, clientID,
	).Scan(
		&p.ID, &p.ClientID, &p.Name, &p.Description, &p.Status,
		&p.RepoURL, &p.RepoProvider, &p.RepoBranch, &p.RepoConnected,
		&p.TechStack, &p.ArchitectureType, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, ErrNotFound
	}

	// Load experts - error is now logged and defaulted, never silently
	// discarded (a discarded error here previously left Experts nil,
	// which the omitempty tag then hid from the wire entirely).
	experts, err := s.GetExperts(ctx, projectID)
	if err != nil {
		s.logger.Warn("get project experts failed",
			zap.String("project_id", projectID.String()),
			zap.Error(err),
		)
		experts = []ProjectExpert{}
	}
	p.Experts = experts
	return &p, nil
}

// Update updates project fields.
func (s *Service) Update(ctx context.Context, projectID, clientID uuid.UUID, req UpdateProjectRequest) error {
	// Verify ownership
	var exists bool
	s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND client_id=$2 AND deleted_at IS NULL)`,
		projectID, clientID,
	).Scan(&exists)
	if !exists {
		return ErrNotFound
	}

	if req.Name != nil {
		_, _ = s.db.Exec(ctx,
			`UPDATE projects SET name=$1, updated_at=NOW() WHERE id=$2`,
			*req.Name, projectID)
	}
	if req.Description != nil {
		_, _ = s.db.Exec(ctx,
			`UPDATE projects SET description=$1, updated_at=NOW() WHERE id=$2`,
			*req.Description, projectID)
	}
	if req.ArchitectureType != nil {
		_, _ = s.db.Exec(ctx,
			`UPDATE projects SET architecture_type=$1, updated_at=NOW() WHERE id=$2`,
			*req.ArchitectureType, projectID)
	}
	if req.TechStack != nil {
		_, _ = s.db.Exec(ctx,
			`UPDATE projects SET tech_stack=$1, updated_at=NOW() WHERE id=$2`,
			*req.TechStack, projectID)
	}
	if req.Status != nil {
		// Only allow valid status transitions: active <-> archived
		if *req.Status == "active" || *req.Status == "archived" {
			_, _ = s.db.Exec(ctx,
				`UPDATE projects SET status=$1, updated_at=NOW() WHERE id=$2`,
				*req.Status, projectID)
		}
	}
	return nil
}

// SoftDelete marks a project as deleted.
func (s *Service) SoftDelete(ctx context.Context, projectID, clientID uuid.UUID) error {
	result, err := s.db.Exec(ctx,
		`UPDATE projects SET deleted_at=NOW() WHERE id=$1 AND client_id=$2 AND deleted_at IS NULL`,
		projectID, clientID,
	)
	if err != nil {
		return fmt.Errorf("delete failed: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ErrExpertForbidden is returned when a domain_expert lacks a grant.
var ErrExpertForbidden = errors.New("expert not assigned to this account")

// AddExpert adds an expert to a project.
func (s *Service) AddExpert(ctx context.Context, projectID, clientID, expertID uuid.UUID, role string) error {
	// Verify project ownership
	var exists bool
	s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND client_id=$2 AND deleted_at IS NULL)`,
		projectID, clientID,
	).Scan(&exists)
	if !exists {
		return ErrNotFound
	}

	// Verify expert is active
	var expertActive bool
	s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM experts WHERE id=$1 AND is_active=TRUE AND deleted_at IS NULL)`,
		expertID,
	).Scan(&expertActive)
	if !expertActive {
		return ErrExpertNotFound
	}

	if err := auth.MustHaveExpertAccess(ctx, s.db, clientID, role, []uuid.UUID{expertID}); err != nil {
		return ErrExpertForbidden
	}

	_, err := s.db.Exec(ctx,
		`INSERT INTO project_experts (project_id, expert_id)
		 VALUES ($1, $2)
		 ON CONFLICT (project_id, expert_id) DO UPDATE SET is_active=TRUE`,
		projectID, expertID,
	)
	return err
}

// RemoveExpert removes an expert from a project.
func (s *Service) RemoveExpert(ctx context.Context, projectID, clientID, expertID uuid.UUID) error {
	var exists bool
	s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND client_id=$2 AND deleted_at IS NULL)`,
		projectID, clientID,
	).Scan(&exists)
	if !exists {
		return ErrNotFound
	}
	_, err := s.db.Exec(ctx,
		`UPDATE project_experts SET is_active=FALSE WHERE project_id=$1 AND expert_id=$2`,
		projectID, expertID,
	)
	return err
}

// GetExperts returns active experts for a project.
func (s *Service) GetExperts(ctx context.Context, projectID uuid.UUID) ([]ProjectExpert, error) {
	rows, err := s.db.Query(ctx,
		`SELECT pe.expert_id, e.name, e.domain, pe.added_at, pe.is_active
		 FROM project_experts pe
		 JOIN experts e ON e.id = pe.expert_id
		 WHERE pe.project_id=$1 AND pe.is_active=TRUE
		 ORDER BY pe.added_at ASC`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var experts []ProjectExpert
	for rows.Next() {
		var e ProjectExpert
		if err := rows.Scan(&e.ExpertID, &e.ExpertName, &e.Domain, &e.AddedAt, &e.IsActive); err != nil {
			continue
		}
		experts = append(experts, e)
	}
	if experts == nil {
		experts = []ProjectExpert{}
	}
	return experts, nil
}

// Sentinel errors
var (
	ErrNotFound      = errors.New("project not found")
	ErrExpertNotFound = errors.New("expert not found or inactive")
)

// Handler handles HTTP requests for projects.
type Handler struct {
	svc    *Service
	logger *zap.Logger
}

// NewHandler creates a new project handler.
func NewHandler(svc *Service, logger *zap.Logger) *Handler {
	return &Handler{svc: svc, logger: logger}
}

// Create POST /projects
func (h *Handler) Create(c *gin.Context) {
	clientID := c.MustGet("user_id").(uuid.UUID)
	var req CreateProjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "INVALID_INPUT", err.Error())
		return
	}
	p, err := h.svc.Create(c.Request.Context(), clientID, req)
	if err != nil {
		h.logger.Error("create project failed", zap.Error(err))
		response.InternalError(c)
		return
	}
	response.Created(c, p)
}

// List GET /projects
func (h *Handler) List(c *gin.Context) {
	clientID := c.MustGet("user_id").(uuid.UUID)
	projects, err := h.svc.List(c.Request.Context(), clientID)
	if err != nil {
		h.logger.Error("list projects failed", zap.Error(err))
		response.InternalError(c)
		return
	}
	response.OK(c, projects)
}

// GetByID GET /projects/:id
func (h *Handler) GetByID(c *gin.Context) {
	clientID := c.MustGet("user_id").(uuid.UUID)
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "INVALID_ID", "invalid project ID")
		return
	}
	p, err := h.svc.GetByID(c.Request.Context(), projectID, clientID)
	if err != nil {
		response.NotFound(c, "project")
		return
	}
	response.OK(c, p)
}

// Update PATCH /projects/:id
func (h *Handler) Update(c *gin.Context) {
	clientID := c.MustGet("user_id").(uuid.UUID)
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "INVALID_ID", "invalid project ID")
		return
	}
	var req UpdateProjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "INVALID_INPUT", err.Error())
		return
	}
	if err := h.svc.Update(c.Request.Context(), projectID, clientID, req); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.NotFound(c, "project")
			return
		}
		response.InternalError(c)
		return
	}
	response.OK(c, map[string]string{"status": "updated"})
}

// Delete DELETE /projects/:id
func (h *Handler) Delete(c *gin.Context) {
	clientID := c.MustGet("user_id").(uuid.UUID)
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "INVALID_ID", "invalid project ID")
		return
	}
	if err := h.svc.SoftDelete(c.Request.Context(), projectID, clientID); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.NotFound(c, "project")
			return
		}
		response.InternalError(c)
		return
	}
	response.OK(c, map[string]string{"status": "deleted"})
}

// AddExpert POST /projects/:id/experts
func (h *Handler) AddExpert(c *gin.Context) {
	clientID := c.MustGet("user_id").(uuid.UUID)
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "INVALID_ID", "invalid project ID")
		return
	}
	var req struct {
		ExpertID string `json:"expert_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "INVALID_INPUT", err.Error())
		return
	}
	expertID, err := uuid.Parse(req.ExpertID)
	if err != nil {
		response.BadRequest(c, "INVALID_ID", "invalid expert ID")
		return
	}
	role, _ := c.Get("role")
	roleStr, _ := role.(string)
	if err := h.svc.AddExpert(c.Request.Context(), projectID, clientID, expertID, roleStr); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.NotFound(c, "project")
			return
		}
		if errors.Is(err, ErrExpertNotFound) {
			response.NotFound(c, "expert")
			return
		}
		if errors.Is(err, ErrExpertForbidden) {
			response.Forbidden(c, err.Error())
			return
		}
		response.InternalError(c)
		return
	}
	response.OK(c, map[string]string{"status": "expert added"})
}

// RemoveExpert DELETE /projects/:id/experts/:expertId
func (h *Handler) RemoveExpert(c *gin.Context) {
	clientID := c.MustGet("user_id").(uuid.UUID)
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "INVALID_ID", "invalid project ID")
		return
	}
	expertID, err := uuid.Parse(c.Param("expertId"))
	if err != nil {
		response.BadRequest(c, "INVALID_ID", "invalid expert ID")
		return
	}
	if err := h.svc.RemoveExpert(c.Request.Context(), projectID, clientID, expertID); err != nil {
		response.InternalError(c)
		return
	}
	response.OK(c, map[string]string{"status": "expert removed"})
}

// CreateChat POST /projects/:id/chats
func (h *Handler) CreateChat(c *gin.Context) {
	clientID := c.MustGet("user_id").(uuid.UUID)
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "INVALID_ID", "invalid project ID")
		return
	}
	var req struct {
		Title string `json:"title" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "INVALID_INPUT", err.Error())
		return
	}

	// Verify project ownership
	var exists bool
	h.svc.db.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND client_id=$2 AND deleted_at IS NULL)`,
		projectID, clientID,
	).Scan(&exists)
	if !exists {
		response.NotFound(c, "project")
		return
	}

	var chatID uuid.UUID
	var createdAt time.Time
	err = h.svc.db.QueryRow(c.Request.Context(),
		`INSERT INTO chats (project_id, client_id, title)
		 VALUES ($1, $2, $3)
		 RETURNING id, created_at`,
		projectID, clientID, req.Title,
	).Scan(&chatID, &createdAt)
	if err != nil {
		h.logger.Error("create chat failed", zap.Error(err))
		response.InternalError(c)
		return
	}
	response.Created(c, map[string]interface{}{
		"id": chatID, "project_id": projectID,
		"title": req.Title, "created_at": createdAt,
	})
}

// ListChats GET /projects/:id/chats
func (h *Handler) ListChats(c *gin.Context) {
	clientID := c.MustGet("user_id").(uuid.UUID)
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "INVALID_ID", "invalid project ID")
		return
	}
	rows, err := h.svc.db.Query(c.Request.Context(),
		`SELECT id, title, message_count, is_archived, created_at, updated_at
		 FROM chats
		 WHERE project_id=$1 AND client_id=$2 AND is_archived=FALSE
		 ORDER BY updated_at DESC`,
		projectID, clientID,
	)
	if err != nil {
		response.InternalError(c)
		return
	}
	defer rows.Close()

	type chatItem struct {
		ID           uuid.UUID `json:"id"`
		Title        string    `json:"title"`
		MessageCount int       `json:"message_count"`
		IsArchived   bool      `json:"is_archived"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
	}
	var chats []chatItem
	for rows.Next() {
		var ch chatItem
		if err := rows.Scan(&ch.ID, &ch.Title, &ch.MessageCount, &ch.IsArchived, &ch.CreatedAt, &ch.UpdatedAt); err != nil {
			continue
		}
		chats = append(chats, ch)
	}
	if chats == nil {
		chats = []chatItem{}
	}
	response.OK(c, chats)
}
