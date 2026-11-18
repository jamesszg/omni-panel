package controller

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/jamesszg/omni-panel/internal/database/model"
	"github.com/jamesszg/omni-panel/internal/template"
	"github.com/jamesszg/omni-panel/internal/web/service"
	"github.com/jamesszg/omni-panel/internal/web/service/panel"
	"github.com/jamesszg/omni-panel/internal/web/session"
)

// GatewayController exposes the :443 L4/L7 gateway status, built-in template
// catalog, constraint validation, one-click stack bootstrap, and authoritative client links.
type GatewayController struct {
	gatewayService service.GatewayService
}

// NewGatewayController registers gateway routes under /panel/api/gateway.
func NewGatewayController(g *gin.RouterGroup) *GatewayController {
	c := &GatewayController{}
	c.initRouter(g)
	return c
}

func (c *GatewayController) initRouter(g *gin.RouterGroup) {
	g.GET("/status", c.getStatus)
	g.GET("/templates", c.getTemplates)
	g.POST("/validate", c.validateInbound)
	g.POST("/bootstrap", c.bootstrapStack)
	g.GET("/clientLinks/:id", c.getClientLinks)
}

func (c *GatewayController) getStatus(ctx *gin.Context) {
	status, err := c.gatewayService.GetStatus()
	if err != nil {
		jsonMsg(ctx, "obtain gateway status", err)
		return
	}
	jsonObj(ctx, status, nil)
}

func (c *GatewayController) getTemplates(ctx *gin.Context) {
	jsonObj(ctx, template.GetBuiltInTemplates(), nil)
}

func (c *GatewayController) validateInbound(ctx *gin.Context) {
	var ib model.Inbound
	if err := ctx.ShouldBind(&ib); err != nil {
		jsonMsg(ctx, "validate inbound", err)
		return
	}
	res := c.gatewayService.ValidateCandidateInbound(&ib)
	jsonObj(ctx, res, nil)
}

func (c *GatewayController) bootstrapStack(ctx *gin.Context) {
	var req service.BootstrapRequest
	if strings.Contains(strings.ToLower(ctx.ContentType()), "json") {
		if err := ctx.ShouldBindJSON(&req); err != nil {
			jsonMsg(ctx, "bootstrap gateway", err)
			return
		}
	} else {
		if err := ctx.ShouldBind(&req); err != nil {
			jsonMsg(ctx, "bootstrap gateway", err)
			return
		}
	}
	if user := session.GetLoginUser(ctx); user != nil && user.Id > 0 {
		req.UserId = user.Id
	}
	res, err := c.gatewayService.Bootstrap443Stack(resolveHost(ctx), req)
	if err != nil {
		jsonMsg(ctx, "bootstrap gateway", err)
		return
	}
	if res != nil && res.RestartPanelNeeded {
		_ = (&panel.PanelService{}).RestartPanel(3 * time.Second)
	}
	jsonObj(ctx, res, nil)
}

func (c *GatewayController) getClientLinks(ctx *gin.Context) {
	id, err := strconv.Atoi(ctx.Param("id"))
	if err != nil || id <= 0 {
		jsonMsg(ctx, "get client links", err)
		return
	}
	email := ctx.Query("email")
	bundles, err := c.gatewayService.GetClientShareBundles(resolveHost(ctx), id, email)
	if err != nil {
		jsonMsg(ctx, "get client links", err)
		return
	}
	jsonObj(ctx, bundles, nil)
}
