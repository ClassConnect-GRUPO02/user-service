package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"user_service/models"
	"user_service/service"
	"user_service/utils"

	"github.com/gin-gonic/gin"
	expo "github.com/oliveroneill/exponent-server-sdk-golang/sdk"
)

type UserHandler struct {
	service *service.Service
}

func NewUserHandler(service *service.Service) *UserHandler {
	handler := UserHandler{
		service: service,
	}
	return &handler
}

// @Summary      Crea un nuevo usuario
// @Description  Crea un nuevo usuario con email y contraseña
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        user  body      models.User  true  "Datos del usuario"
// @Success      201   {object}  models.User
// @Failure      400   {object}  models.Error
// @Router       /users [post]
func (h *UserHandler) CreateUser(c *gin.Context) {
	user := models.User{}
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	err := h.service.CreateUser(user)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	pin, err := h.service.IssueVerificationPinForEmail(user.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	err = h.service.SendEmailVerificationPin(user.Email, pin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.InternalServerError())
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"description": "Verification PIN sent to the provided email",
		"email":       user.Email,
		"name":        user.Name,
		"duration":    h.service.VerificationPinDurationInMinutes(),
	})
}

// VerifyUserEmail godoc
// @Summary      Verifica el email de un usuario
// @Description  Verifica que el usuario haya ingresado correctamente el PIN enviado por correo
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        request  body      models.EmailVerificationRequest  true  "Email y PIN de verificación"
// @Success      200      {object}  map[string]interface{}
// @Failure      400      {object}  models.Error  "Campos faltantes"
// @Failure      401      {object}  models.Error  "PIN inválido, consumido o expirado"
// @Router       /users/verify [post]
func (h *UserHandler) VerifyUserEmail(c *gin.Context) {
	request := models.EmailVerificationRequest{}
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	err := h.service.VerifyUserEmail(request.Email, request.Pin)
	if err != nil {
		switch err.Error() {
		case service.InvalidPinError:
			c.JSON(http.StatusUnauthorized, models.InvalidPinError(request.Pin, c.Request.URL.Path))
		case service.ConsumedPinError:
			c.JSON(http.StatusUnauthorized, models.InvalidPinError(request.Pin, c.Request.URL.Path))
		case service.ExpiredPinError:
			c.JSON(http.StatusUnauthorized, models.ExpiredPinError(request.Pin, c.Request.URL.Path))
		case service.InternalServerError:
			c.JSON(http.StatusUnauthorized, models.InternalServerError())
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"description": "Email verified successfully",
		"email":       request.Email,
	})
}

// RequestNewPin godoc
// @Summary      Solicita un nuevo PIN de verificación
// @Description  Envía un nuevo PIN de verificación al correo electrónico del usuario
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        request  body      models.RequestNewVerificationPin  true  "Email del usuario"
// @Success      200      {object}  map[string]interface{}  "PIN enviado correctamente"
// @Failure      500      {object}  models.Error  "Error interno"
// @Router       /users/request-new-pin [post]
func (h *UserHandler) RequestNewPin(c *gin.Context) {
	request := models.RequestNewVerificationPin{}
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	pin, err := h.service.IssueVerificationPinForEmail(request.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	err = h.service.SendEmailVerificationPin(request.Email, pin)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"description": "Verification PIN sent to email",
		"email":       request.Email,
	})
}

// HandleLogin godoc
// @Summary      Inicia sesión de usuario
// @Description  Valida las credenciales del usuario y retorna un token de acceso y refresh
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      models.LoginRequest       true  "Credenciales de login"
// @Success      202      {object}  map[string]interface{}    "Login exitoso, devuelve tokens"
// @Failure      400      {object}  models.Error  "Campos faltantes o ID inválido"
// @Failure      401      {object}  models.Error  "Credenciales inválidas"
// @Failure      404      {object}  models.Error  "Usuario no encontrado"
// @Failure      500      {object}  models.Error  "Error interno del servidor"
// @Router       /login [post]
func (h *UserHandler) HandleLogin(c *gin.Context) {
	loginRequest := models.LoginRequest{}
	if err := c.ShouldBind(&loginRequest); err != nil {
		log.Print("POST /login Error: Bad request")
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	err := h.service.LoginUser(loginRequest)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	userId, err := h.service.GetUserIdByEmail(loginRequest.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	id, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(userId, c.Request.URL.Path))
		return
	}
	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(userId))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	token, err := h.service.IssueToken(userId, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	refreshToken, err := h.service.IssueRefreshToken(userId)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"description":  "User logged in successfully",
		"id":           userId,
		"token":        token,
		"refreshToken": refreshToken,
	})
}

// HandleBiometricLogin godoc
// @Summary      Inicia sesión usando login biométrico
// @Description  Valida el refresh token previamente emitido para permitir login biométrico sin credenciales
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      models.BiometricLoginRequest  true  "Refresh token para login biométrico"
// @Success      202      {object}  map[string]interface{}        "Login exitoso, devuelve nuevo token"
// @Failure      400      {object}  models.Error      "Campos faltantes"
// @Failure      401      {object}  models.Error      "Token inválido o expirado"
// @Failure      403      {object}  models.Error      "Usuario bloqueado"
// @Failure      404      {object}  models.Error      "Usuario no encontrado"
// @Failure      500      {object}  models.Error      "Error interno del servidor"
// @Router       /biometric-login [post]
func (h *UserHandler) HandleBiometricLogin(c *gin.Context) {
	loginRequest := models.BiometricLoginRequest{}
	if err := c.ShouldBind(&loginRequest); err != nil {
		log.Printf("%s Error: %s", c.Request.URL.Path, err)
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	refreshToken, err := h.service.ValidateRefreshToken(loginRequest.RefreshToken)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	userId := refreshToken.Id
	user, err := h.service.GetUser(userId)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	userIsBlocked, err := h.service.UserIsBlocked(user.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if userIsBlocked {
		c.JSON(http.StatusForbidden, models.UserBlockedError())
		return
	}

	userType := user.UserType
	token, err := h.service.IssueToken(userId, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"description": "User logged in successfully",
		"id":          userId,
		"token":       token,
	})
}

// GetUsers godoc
// @Summary      Obtiene todos los usuarios
// @Description  Devuelve una lista de usuarios. Si el requester es un administrador, se incluye información adicional.
// @Tags         users
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "Lista de usuarios (con info extendida si es admin)"
// @Failure      401  {object}  models.Error  "Token inválido o faltante"
// @Failure      500  {object}  models.Error  "Error interno del servidor"
// @Router       /users [get]
func (h *UserHandler) GetUsers(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	// If the sender is the admin, then return the full user info,
	// which contains information such as registration date, whether the user
	// is blocked, etc.
	if token.UserType == "admin" {
		users, err := h.service.GetUsersFullInfo()
		if err, ok := err.(*models.Error); ok {
			c.JSON(err.Status, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"users": users,
		})
		return
	}
	users, err := h.service.GetUsers()
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

// GetUser godoc
// @Summary      Obtiene un usuario por ID
// @Description  Devuelve la información de un usuario. Si el usuario autenticado solicita su propia información, se incluyen campos privados. De lo contrario, solo se devuelven los datos públicos.
// @Tags         users
// @Security     BearerAuth
// @Produce      json
// @Param        id   path      string  true  "ID del usuario"
// @Success      200  {object}  models.UserPublicInfo  "Información del usuario (completa o pública)"
// @Failure      401  {object}  models.Error  "Token inválido o faltante"
// @Failure      404  {object}  models.Error  "Usuario no encontrado"
// @Failure      500  {object}  models.Error  "Error interno del servidor"
// @Router       /user/{id} [get]
func (h *UserHandler) GetUser(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	id := c.Param("id")
	// Retrieve the user by its id
	user, err := h.service.GetUser(id)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	// Get the ID of the sender from the JWT token
	idSender := token.Id

	// If the id of the sender is the same as the target, then
	// the user is retrieving its own info, so we respond with
	// the full information (public and private fields)
	if idSender == id {
		c.JSON(http.StatusOK, gin.H{
			"user": user,
		})
		return
	}
	// Otherwise, respond only with the public fields
	// (omit the private ones like the location)
	c.JSON(http.StatusOK, gin.H{
		"user": models.UserPublicInfo{
			Id:       user.Id,
			Name:     user.Name,
			Email:    user.Email,
			UserType: user.UserType,
		},
	})
}

// EditUser godoc
// @Summary      Edita la información de un usuario
// @Description  Permite a un usuario autenticado modificar su propia información personal
// @Tags         users
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id       path      string                   true  "ID del usuario a editar"
// @Param        request  body      models.EditUserRequest   true  "Datos del usuario a actualizar"
// @Success      200      {object}  map[string]string        "Usuario actualizado exitosamente"
// @Failure      400      {object}  models.Error "ID inválido o datos faltantes"
// @Failure      401      {object}  models.Error "Token inválido o no coincide con el ID"
// @Failure      404      {object}  models.Error "Usuario no encontrado"
// @Failure      500      {object}  models.Error "Error interno del servidor"
// @Router       /user/{id} [put]
func (h *UserHandler) EditUser(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	editUserRequest := models.EditUserRequest{}
	idString := c.Param("id")
	if err := c.ShouldBind(&editUserRequest); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	// Check the sender of the request is the actual user
	if token.Id != idString {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	err = h.service.EditUser(id, editUserRequest)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "User updated successfully",
	})
}

// ResetPassword godoc
// @Summary      Restablece la contraseña de un usuario
// @Description  Permite al usuario autenticado cambiar su contraseña utilizando un token válido
// @Tags         users
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        request  body      models.ResetPasswordRequest  true  "Nueva contraseña del usuario"
// @Success      200      {object}  map[string]string            "Contraseña actualizada exitosamente"
// @Failure      400      {object}  models.Error                 "Datos inválidos o campos faltantes"
// @Failure      401      {object}  models.Error                 "Token expirado o inválido"
// @Failure      404      {object}  models.Error                 "Usuario no encontrado"
// @Failure      500      {object}  models.Error                 "Error interno del servidor"
// @Router       /users/reset-password [put]
func (h *UserHandler) ResetPassword(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if h.service.ResetPasswordTokenHasExpired(token.IssuedAt) {
		c.JSON(http.StatusUnauthorized, models.ExpiredTokenError(c.Request.URL.Path))
		return
	}
	resetPasswordRequest := models.ResetPasswordRequest{}
	if err := c.ShouldBind(&resetPasswordRequest); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	id, err := strconv.ParseInt(token.Id, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(token.Id, c.Request.URL.Path))
		return
	}

	err = h.service.ResetPassword(id, resetPasswordRequest.NewPassword)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"description": "Password reset successfully",
	})
}

// ForgotPassword godoc
// @Summary      Solicita recuperación de contraseña
// @Description  Envía un email con un enlace para restablecer la contraseña del usuario
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        request  body      models.ForgotPasswordRequest  true  "Email del usuario que solicita el reset"
// @Success      200      {object}  map[string]string             "Email enviado exitosamente"
// @Failure      400      {object}  models.Error                  "Campos faltantes o inválidos"
// @Failure      404      {object}  models.Error                  "Usuario no encontrado"
// @Failure      500      {object}  models.Error                  "Error al enviar el email"
// @Router       /users/forgot-password [post]
func (h *UserHandler) ForgotPassword(c *gin.Context) {
	forgotPasswordRequest := models.ForgotPasswordRequest{}
	if err := c.ShouldBind(&forgotPasswordRequest); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	email := forgotPasswordRequest.Email
	userId, err := h.service.GetUserIdByEmail(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	token, err := h.service.IssueToken(userId, "")
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	resetPasswordUrl := fmt.Sprintf("https://classconnect-reset.netlify.app/?token=%s", token)
	tokenDuration := h.service.ResetPasswordTokenDurationInMinutes()
	emailSubject := "ClassConnect - Recuperación de contraseña"
	emailBody := utils.GetResetPasswordMessage(email, resetPasswordUrl, tokenDuration)
	err = h.service.SendEmail(email, emailSubject, emailBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.InternalServerError())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "Email sent successfully",
	})
}

func (h *UserHandler) EmailExists(c *gin.Context) {
	email := c.Param("email")
	emailExists, err := h.service.IsEmailRegistered(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if !emailExists {
		c.JSON(http.StatusOK, gin.H{
			"exists": false,
		})
		return
	}
	userId, err := h.service.GetUserIdByEmail(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	id, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(userId, c.Request.URL.Path))
		return
	}
	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(userId))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	token, err := h.service.IssueToken(userId, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"exists": true,
		"token":  token,
		"id":     id,
	})
}

// HandleAdminLogin godoc
// @Summary      Inicio de sesión para administradores
// @Description  Valida las credenciales del administrador y retorna un token de acceso
// @Tags         admins
// @Accept       json
// @Produce      json
// @Param        request  body      models.LoginRequest  true  "Credenciales de login del administrador"
// @Success      202      {object}  map[string]interface{}  "Login exitoso, devuelve token"
// @Failure      400      {object}  models.Error        "Campos faltantes o inválidos"
// @Failure      401      {object}  models.Error        "Credenciales inválidas"
// @Failure      500      {object}  models.Error        "Error interno del servidor"
// @Router       /admin-login [post]
func (h *UserHandler) HandleAdminLogin(c *gin.Context) {
	loginRequest := models.LoginRequest{}
	if err := c.ShouldBind(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	err := h.service.LoginAdmin(loginRequest)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	adminId, err := h.service.GetAdminIdByEmail(loginRequest.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	token, err := h.service.IssueToken(adminId, "admin")
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"description": "Admin logged in successfully",
		"id":          adminId,
		"token":       token,
	})
}

// CreateAdmin godoc
// @Summary      Crea un nuevo administrador
// @Description  Permite a un administrador autenticado registrar otro administrador
// @Tags         admins
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        request  body      models.CreateAdminRequest  true  "Datos del nuevo administrador"
// @Success      201      {object}  map[string]interface{}    "Administrador creado exitosamente"
// @Failure      400      {object}  models.Error              "Campos faltantes o inválidos"
// @Failure      401      {object}  models.Error              "Token inválido o no autorizado"
// @Failure      500      {object}  models.Error              "Error interno del servidor"
// @Router       /admins [post]
func (h *UserHandler) CreateAdmin(c *gin.Context) {
	admin := models.CreateAdminRequest{}
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if token.UserType != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	if err := c.ShouldBind(&admin); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	err = h.service.CreateAdmin(admin)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"description": "Admin registered successfully",
		"email":       admin.Email,
		"name":        admin.Name,
	})
}

// BlockUser godoc
// @Summary      Bloquea a un usuario
// @Description  Permite a un administrador bloquear a un usuario específico por ID
// @Tags         users
// @Security     BearerAuth
// @Produce      json
// @Param        id    path      string         true  "ID del usuario a bloquear"
// @Success      200   {object}  map[string]interface{}  "Usuario bloqueado exitosamente"
// @Failure      400   {object}  models.Error           "ID inválido"
// @Failure      401   {object}  models.Error           "Token inválido o no autorizado"
// @Failure      500   {object}  models.Error           "Error interno del servidor"
// @Router       /user/{id}/block [put]
func (h *UserHandler) BlockUser(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if token.UserType != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	err = h.service.BlockUser(id)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "User blocked successfully",
		"id":          idString,
		"blocked":     true,
	})
}

// UnblockUser godoc
// @Summary      Desbloquea a un usuario
// @Description  Permite a un administrador desbloquear a un usuario específico por ID
// @Tags         users
// @Security     BearerAuth
// @Produce      json
// @Param        id    path      string         true  "ID del usuario a desbloquear"
// @Success      200   {object}  map[string]interface{}  "Usuario desbloqueado exitosamente"
// @Failure      400   {object}  models.Error           "ID inválido"
// @Failure      401   {object}  models.Error           "Token inválido o no autorizado"
// @Failure      500   {object}  models.Error           "Error interno del servidor"
// @Router       /user/{id}/unblock [put]
func (h *UserHandler) UnblockUser(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if token.UserType != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	err = h.service.UnblockUser(id)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "User unblocked successfully",
		"id":          idString,
		"blocked":     false,
	})
}

// SetUserType godoc
// @Summary      Cambia el tipo de usuario
// @Description  Permite a un administrador actualizar el tipo (rol) de un usuario específico
// @Tags         users
// @Security     BearerAuth
// @Produce      json
// @Param        id       path      string         true  "ID del usuario"
// @Param        type     path      string         true  "Nuevo tipo de usuario"
// @Success      200      {object}  map[string]interface{}  "Tipo de usuario actualizado exitosamente"
// @Failure      400      {object}  models.Error           "ID inválido"
// @Failure      401      {object}  models.Error           "Token inválido o no autorizado"
// @Failure      500      {object}  models.Error           "Error interno del servidor"
// @Router       /user/{id}/type/{type} [put]
func (h *UserHandler) SetUserType(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if token.UserType != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	idString := c.Param("id")
	userType := c.Param("type")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	err = h.service.SetUserType(id, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "User type updated successfully",
		"id":          idString,
		"userType":    userType,
	})
}

// AddPushToken godoc
// @Summary      Agrega un push token para notificaciones
// @Description  Permite a un usuario autenticado registrar un token push para recibir notificaciones
// @Tags         users
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id       path      string                  true  "ID del usuario"
// @Param        request  body      models.AddPushTokenRequest  true  "Token push a registrar"
// @Success      200      {object}  map[string]interface{}   "Token push registrado exitosamente"
// @Failure      400      {object}  models.Error             "ID inválido o campos faltantes"
// @Failure      401      {object}  models.Error             "Token inválido o usuario no autorizado"
// @Failure      500      {object}  models.Error             "Error interno del servidor"
// @Router       /users/{id}/push-token [post]
func (h *UserHandler) AddPushToken(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	request := models.AddPushTokenRequest{}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}

	if token.Id != idString {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}

	if err := c.ShouldBind(&request); err != nil {
		log.Printf("POST /users/%s/push-token Error: Bad request", idString)
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	_, err = expo.NewExponentPushToken(request.PushToken)
	if err != nil {
		err = models.InvalidExpoToken(id, request.PushToken)
		c.JSON(http.StatusUnauthorized, err)
		return
	}

	err = h.service.SetUserPushToken(id, request.PushToken)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"description": "User push token set successfully",
		"id":          idString,
		"token":       request.PushToken,
	})
}

// NotifyUser godoc
// @Summary      Envía una notificación a un usuario
// @Description  Programa el envío de una notificación push y/o email según las preferencias del usuario
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id       path      string                 true  "ID del usuario receptor"
// @Param        request  body      models.NotifyUserRequest  true  "Datos de la notificación (título, cuerpo, tipo)"
// @Success      200      {object}  map[string]interface{}  "Notificación programada correctamente"
// @Failure      400      {object}  models.Error            "ID inválido o campos faltantes o tipo de notificación inválido"
// @Failure      404      {object}  models.Error            "Token push no encontrado para el usuario"
// @Failure      500      {object}  models.Error            "Error interno del servidor"
// @Router       /users/{id}/notifications [post]
func (h *UserHandler) NotifyUser(c *gin.Context) {
	request := models.NotifyUserRequest{}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}

	if err := c.ShouldBind(&request); err != nil {
		log.Printf("POST /users/%s/notifications Error: Bad request", idString)
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	userData, err := h.service.GetUser(idString)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	pushToken, err := h.service.GetUserPushToken(id)
	if err != nil {
		if err.Error() == service.MissingExpoPushToken {
			c.JSON(http.StatusNotFound, models.MissingExpoPushToken(idString, c.Request.URL.Path))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}

	notificationType := request.NotificationType
	userType := models.UserType(strings.ToLower(userData.UserType))

	pushEnabled, emailEnabled, notificationPreference, err := h.service.GetUserNotificationPreferences(id, userType, notificationType)
	if err != nil {
		switch err.Error() {
		case service.InternalServerError:
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		case service.InvalidNotificationType:
			c.JSON(http.StatusBadRequest, models.BadRequestInvalidNotificationType(notificationType, c.Request.URL.Path))
		case service.InvalidUserType:
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	sendPushNotification := false
	sendEmailNotification := false

	switch notificationPreference {
	case models.Push:
		sendPushNotification = true
	case models.Email:
		sendEmailNotification = true
	case models.PushAndEmail:
		sendPushNotification = true
		sendEmailNotification = true
	}

	if sendEmailNotification && emailEnabled {
		err = h.service.SendEmail(userData.Email, request.Title, request.Body)
		if err != nil {
			log.Printf("Failed to send email to %s. Error: %s", userData.Email, err)
		}
	}
	if sendPushNotification && pushEnabled {
		err = h.service.SendPushNotification(pushToken, request.Title, request.Body)
		if err != nil {
			log.Printf("Failed to send notification to %s. Error: %s", pushToken, err)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "Notification scheduled",
		"id":          idString,
		"email":       userData.Email,
	})
}

// SetUserNotificationSettings godoc
// @Summary      Actualiza la configuración de notificaciones del usuario
// @Description  Permite a un usuario autenticado modificar sus preferencias de notificación según su tipo (Student o Teacher)
// @Tags         users
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id       path      string      true  "ID del usuario"
// @Param        request  body      interface{} true  "Configuración de notificaciones específica para Student o Teacher"
// @Success      200      {object}  map[string]interface{}  "Configuración de notificaciones actualizada exitosamente"
// @Failure      400      {object}  models.Error           "ID inválido o campos faltantes"
// @Failure      401      {object}  models.Error           "Token inválido o no autorizado"
// @Failure      404      {object}  models.Error           "Usuario no encontrado"
// @Failure      500      {object}  models.Error           "Error interno del servidor"
// @Router       /users/{id}/notification-settings [put]
func (h *UserHandler) SetUserNotificationSettings(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	if token.Id != idString {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}

	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(idString))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	if models.UserType(userType) == models.Student {
		notificationSettings := models.StudentNotificationSettingsRequest{}
		if err := c.ShouldBind(&notificationSettings); err != nil {
			log.Printf("POST %s Error: %s", c.Request.URL.Path, err)
			c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
			return
		}
		err := h.service.SetStudentNotificationSettings(id, notificationSettings)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
			return
		}
	} else if models.UserType(userType) == models.Teacher {
		notificationSettings := models.TeacherNotificationSettingsRequest{}
		if err := c.ShouldBind(&notificationSettings); err != nil {
			log.Printf("POST %s Error: %s", c.Request.URL.Path, err)
			c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
			return
		}
		err := h.service.SetTeacherNotificationSettings(id, notificationSettings)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "Notification settings updated successfully",
		"id":          id,
	})
}

// GetUserNotificationSettings godoc
// @Summary      Obtiene la configuración de notificaciones de un usuario
// @Description  Devuelve las preferencias de notificación según el tipo de usuario (Student o Teacher)
// @Tags         users
// @Security     BearerAuth
// @Produce      json
// @Param        id    path      string    true  "ID del usuario"
// @Success      200   {object}  interface{}  "Configuración de notificaciones específica del usuario"
// @Failure      400   {object}  models.Error "ID inválido"
// @Failure      401   {object}  models.Error "Token inválido o no autorizado"
// @Failure      404   {object}  models.Error "Usuario no encontrado"
// @Failure      500   {object}  models.Error "Error interno del servidor"
// @Router       /users/{id}/notification-settings [get]

func (h *UserHandler) GetUserNotificationSettings(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	if token.Id != idString {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(idString))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	if models.UserType(userType) == models.Student {
		notificationSettings, err := h.service.GetStudentNotificationSettings(id)
		if err != nil {
			if err.Error() == service.UserNotFoundError {
				c.JSON(http.StatusNotFound, models.UserNotFoundError(idString))
			} else {
				c.JSON(http.StatusInternalServerError, models.InternalServerError())
			}
			return
		}
		c.JSON(http.StatusOK, notificationSettings)
	} else if models.UserType(userType) == models.Teacher {
		notificationSettings, err := h.service.GetTeacherNotificationSettings(id)
		if err != nil {
			if err.Error() == service.UserNotFoundError {
				c.JSON(http.StatusNotFound, models.UserNotFoundError(idString))
			} else {
				c.JSON(http.StatusInternalServerError, models.InternalServerError())
			}
			return
		}
		c.JSON(http.StatusOK, notificationSettings)
	}
}

// HandleGoogleAuth godoc
// @Summary      Autenticación con Google
// @Description  Valida el IdToken de Google, verifica que el email esté registrado y vinculado, y emite tokens JWT
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      models.GoogleAuthRequest  true  "Token de identificación de Google"
// @Success      202      {object}  map[string]interface{}    "Login exitoso, con token y refresh token"
// @Failure      400      {object}  models.Error              "Campos inválidos o token Google no verificado"
// @Failure      401      {object}  models.Error              "Email no vinculado a cuenta Google"
// @Failure      404      {object}  models.Error              "Email no registrado o usuario no encontrado"
// @Failure      500      {object}  models.Error              "Error interno del servidor"
// @Router       /auth/google [post]

func (h *UserHandler) HandleGoogleAuth(c *gin.Context) {
	request := models.GoogleAuthRequest{}
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	email, err := h.service.ValidateIdTokenAndGetEmail(request.IdToken)
	if err != nil {
		log.Printf("failed to verify Google id token. Error: %s", err)
		c.JSON(http.StatusBadRequest, models.FailedToVerifyFirebaseToken(c.Request.URL.Path, err.Error()))
		return
	}
	isEmailRegistered, err := h.service.IsEmailRegistered(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if !isEmailRegistered {
		c.JSON(http.StatusNotFound, models.EmailNotFoundError(email))
		return
	}
	isEmailLinkedToGoogleAccount, err := h.service.IsEmailLinkedToGoogleAccount(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	if !isEmailLinkedToGoogleAccount {
		c.JSON(http.StatusUnauthorized, models.GoogleEmailNotLinked(email))
		return
	}

	userId, err := h.service.GetUserIdByEmail(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	id, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(userId, c.Request.URL.Path))
		return
	}
	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(userId))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	token, err := h.service.IssueToken(userId, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	refreshToken, err := h.service.IssueRefreshToken(userId)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"description":  "User logged in successfully",
		"id":           userId,
		"token":        token,
		"refreshToken": refreshToken,
	})
}

// LinkGoogleEmail godoc
// @Summary      Vincula un email Google a una cuenta existente
// @Description  Valida el IdToken de Google, verifica que el email esté registrado y no vinculado previamente, y luego vincula la cuenta
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      models.GoogleAuthRequest  true  "Token de identificación de Google"
// @Success      200      {object}  map[string]string         "Email Google vinculado exitosamente"
// @Failure      400      {object}  models.Error              "Campos inválidos o fallo al verificar token Firebase"
// @Failure      401      {object}  models.Error              "Email no registrado"
// @Failure      409      {object}  models.Error              "Email Google ya vinculado"
// @Failure      500      {object}  models.Error              "Error interno del servidor"
// @Router       /auth/link-gmail [post]
func (h *UserHandler) LinkGoogleEmail(c *gin.Context) {
	request := models.GoogleAuthRequest{}
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	email, err := h.service.ValidateIdTokenAndGetEmail(request.IdToken)
	if err != nil {
		log.Printf("failed to verify Firebase id token. Error: %s", err)
		c.JSON(http.StatusBadRequest, models.FailedToVerifyFirebaseToken(c.Request.URL.Path, err.Error()))
		return
	}
	isEmailRegistered, err := h.service.IsEmailRegistered(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if !isEmailRegistered {
		c.JSON(http.StatusUnauthorized, models.EmailNotFoundError(email))
		return
	}
	isEmailLinkedToGoogleAccount, err := h.service.IsEmailLinkedToGoogleAccount(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	if isEmailLinkedToGoogleAccount {
		c.JSON(http.StatusConflict, models.GoogleEmailAlreadyLinked(email))
		return
	}

	err = h.service.LinkGoogleEmail(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"description": "Google email linked to account successfully"})
}
