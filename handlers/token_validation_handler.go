package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"user_service/auth"
	"user_service/models"

	"github.com/gin-gonic/gin"
)

// Validates and returns the token
func (h *UserHandler) ValidateToken(c *gin.Context) (*auth.CustomClaims, error) {
	url := c.Request.URL.String()
	request := models.AuthRequest{}
	if err := c.ShouldBindHeader(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Missing 'Authorization' header",
			"instance": url,
		})
		return nil, err
	}
	token, err := extractBearerToken(request.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   fmt.Sprint("Error: ", err.Error()),
			"instance": url,
		})
		return nil, err
	}
	tokenClaims, err := h.service.ValidateToken(token)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return nil, err
	}
	return tokenClaims, nil
}

func (h *UserHandler) ValidateRefreshToken(c *gin.Context) (*auth.RefreshClaims, error) {
	url := c.Request.URL.String()
	request := models.AuthRequest{}
	if err := c.ShouldBindHeader(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Missing 'Authorization' header",
			"instance": url,
		})
		return nil, err
	}
	token, err := extractBearerToken(request.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   fmt.Sprint("Error: ", err.Error()),
			"instance": url,
		})
		return nil, err
	}
	tokenClaims, err := h.service.ValidateRefreshToken(token)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return nil, err
	}
	return tokenClaims, nil
}

func extractBearerToken(authHeader string) (string, error) {
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", fmt.Errorf("expected Bearer authorization header")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	return token, nil
}
