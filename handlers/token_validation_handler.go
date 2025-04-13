package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"user_service/models"

	"github.com/gin-gonic/gin"
)

func (h *UserHandler) ValidateToken(c *gin.Context) error {
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
		return err
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
		return err
	}
	err = h.service.ValidateToken(token)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return err
	}
	return nil
}

func extractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("missing JWT token")
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", fmt.Errorf("expected Bearer authorization header")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	return token, nil
}
