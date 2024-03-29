package core

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/xerrors"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/http"
	"strings"
	"time"
)

type AuthorizationServer struct {
	// The authorization server's identifier.
	Authorization
}

type Authorization struct {
	DB     *gorm.DB
	tracer trace.Tracer
}

// Data models
type AuthToken struct {
	gorm.Model
	Token      string `gorm:"unique"`
	TokenHash  string `gorm:"unique"`
	Label      string
	User       uint
	UploadOnly bool
	Expiry     time.Time
	IsSession  bool
}

type User struct {
	gorm.Model
	UUID     string `gorm:"unique"`
	Username string `gorm:"unique"`
	Salt     string
	PassHash string
	DID      string

	UserEmail string

	AuthToken AuthToken `gorm:"-"`
	Perm      int
	Flags     int

	StorageDisabled bool
}

type Nonce struct {
	gorm.Model
	Address string `gorm:"unique"`
	Message string
}

type InviteCode struct {
	gorm.Model
	Code      string `gorm:"unique"`
	CreatedBy uint
	ClaimedBy uint
}

// Initialize
func Init() *AuthorizationServer {
	return &AuthorizationServer{} // create the authorization server
}

// Sets a database connection.
func (s *AuthorizationServer) SetDB(db *gorm.DB) *AuthorizationServer {
	s.DB = db // connect to the database
	return s
}

// Set database connection with a string dsn
func (s *AuthorizationServer) SetDBWithString(dbConnection string) *AuthorizationServer {

	db, err := gorm.Open(postgres.Open(dbConnection), &gorm.Config{})
	if err != nil {
		panic(err) // database connection is required
	}

	s.DB = db // connect to the database
	return s
}

func (s *AuthorizationServer) SetDBConfig(dbConnection postgres.Config) *AuthorizationServer {

	db, err := gorm.Open(postgres.New(dbConnection), &gorm.Config{})

	if err != nil {
		panic(err) // database connection is required
	}

	s.DB = db // connect to the database
	return s
}

// Connect to the server and return the Authorization object
func (s *AuthorizationServer) Connect() Authorization {
	return s.Authorization
}

// Checking if the token is valid.
func (s Authorization) CheckAuthorizationToken(token string) (*User, error) {
	//cached, ok := s.cacher.Get(token)
	var authToken AuthToken
	tokenHash := GetTokenHash(token)
	if err := s.DB.First(&authToken, "token = ? OR token_hash = ?", token, tokenHash).Error; err != nil {
		if xerrors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &HttpError{
				Code:    http.StatusUnauthorized,
				Reason:  ERR_INVALID_TOKEN,
				Details: "api key does not exist",
			}
		}
		return nil, err
	}

	if authToken.Expiry.Before(time.Now()) {
		return nil, &HttpError{
			Code:    http.StatusUnauthorized,
			Reason:  ERR_TOKEN_EXPIRED,
			Details: fmt.Sprintf("token for user %d expired %s", authToken.User, authToken.Expiry),
		}
	}

	var user User
	if err := s.DB.First(&user, "id = ?", authToken.User).Error; err != nil {
		if xerrors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &HttpError{
				Code:    http.StatusUnauthorized,
				Reason:  ERR_INVALID_TOKEN,
				Details: "no user exists for the spicified api key",
			}
		}
		return nil, err
	}

	user.AuthToken = authToken
	return &user, nil
}

// A middleware that checks if the user is authorized to access the API.
func (s Authorization) AuthRequired(level int) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			//	Check first if the Token is available. We should not continue if the
			//	token isn't even available.
			auth, err := ExtractAuth(c)
			if err != nil {
				return err
			}

			//ctx := c.Request().Context()
			//ctx, span := s.tracer.Start(context, "authCheck")
			//c.SetRequest(c.Request().WithContext(ctx))

			u, err := s.CheckAuthorizationToken(auth)
			if err != nil {
				return err
			}

			//span.SetAttributes(attribute.Int("user", int(u.ID)))

			if u.AuthToken.UploadOnly && level >= PermLevelUser {
				return &HttpError{
					Code:    http.StatusForbidden,
					Reason:  ERR_NOT_AUTHORIZED,
					Details: "api key is upload only",
				}
			}

			if u.Perm >= level {
				c.Set("user", u)
				return next(c)
			}

			return &HttpError{
				Code:    http.StatusForbidden,
				Reason:  ERR_NOT_AUTHORIZED,
				Details: "user not authorized",
			}
		}
	}
}

type ApiKeyParam struct {
	Username string
	Token    string `json:"api`
}
type AuthenticationResult struct {
	Username string     `json:"username,omitempty"`
	Password string     `json:"password,omitempty"`
	Salt     string     `json:"salt,omitempty"`
	Result   AuthResult `json:"result"`
}

type AuthResult struct {
	Validated bool   `json:"validated"`
	Details   string `json:"details"`
}
type AuthenticationParam struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func (s Authorization) AuthenticateApiKey(param ApiKeyParam) AuthenticationResult {

	var authToken AuthToken
	tokenHash := GetTokenHash(param.Token)
	if err := s.DB.First(&authToken, "token = ? OR token_hash = ?", param.Token, tokenHash).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return AuthenticationResult{
				Username: param.Username,
				Result: AuthResult{
					Validated: false,
					Details:   "api key does not exists",
				},
			}
		}
	}

	if authToken.Expiry.Before(time.Now()) {
		return AuthenticationResult{
			Username: param.Username,
			Result: AuthResult{
				Validated: false,
				Details:   "api key expired",
			},
		}
	}
	return AuthenticationResult{
		Username: param.Username,
		Result: AuthResult{
			Validated: true,
			Details:   "api key validated",
		},
	}
}

func (s Authorization) AuthenticateApiKeyUser(param ApiKeyParam) AuthenticationResult {
	var authToken AuthToken
	if err := s.DB.First(&authToken, "token = ?", param.Token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return AuthenticationResult{
				Username: param.Username,
				Result: AuthResult{
					Validated: false,
					Details:   "api key does not exists",
				},
			}
		}
	}

	if authToken.Expiry.Before(time.Now()) {
		return AuthenticationResult{
			Username: param.Username,
			Result: AuthResult{
				Validated: false,
				Details:   ERR_TOKEN_EXPIRED,
			},
		}
	}

	var user User
	if err := s.DB.First(&user, "id = ?", authToken.User).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return AuthenticationResult{
				Username: param.Username,
				Result: AuthResult{
					Validated: false,
					Details:   "no user exists for the specified api key",
				},
			}
		}
	}

	return AuthenticationResult{
		Username: param.Username,
		Result: AuthResult{
			Validated: true,
			Details:   "api key and user is validated",
		},
	}
}
func (s Authorization) AuthenticateUserPassword(param AuthenticationParam) AuthenticationResult {

	var user User
	if err := s.DB.First(&user, "username = ?", strings.ToLower(param.Username)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return AuthenticationResult{
				Username: param.Username,
				Result: AuthResult{
					Validated: false,
					Details:   "user not found",
				},
			}
		}
	}

	//	validate password
	//	SQLlite and Postgres has incompatibility in hashing and even though we are dropping support for sqlite later,
	//	we still need to accommodate those who chooses to use SQLite for experimentation purposes.
	var valid = true
	var dbDialect = s.DB.Config.Dialector.Name()

	//	check password hash (this is the way).
	if (user.Salt != "" && (user.PassHash != GetPasswordHash(param.Password, user.Salt, dbDialect))) || (user.Salt == "" && user.PassHash != param.Password) {
		valid = false                                                                            //	assume it's not valid.
		if bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(param.Password)) == nil { //	we are using bcrypt, so we need to rehash it.
			valid = true
		}
	}

	if !valid {
		return AuthenticationResult{
			Username: param.Username,
			Result: AuthResult{
				Validated: false,
				Details:   "user not found",
			},
		}
	}

	// Successful authentication
	return AuthenticationResult{
		Username: param.Username,
		Result: AuthResult{
			Validated: true,
			Details:   "user authenticated",
		},
	}

}

type NonceParams struct {
	Address  string `json:"address"`
	Host     string `json:"host"`
	IssuedAt string `json:"issuedAt"`
	ChainId  int    `json:"chainId"`
	Version  string `json:"version"`
}

type NonceResult struct {
	NonceMsg string `json:"nonceMsg"`
}

const NonceExpiryDuration = time.Hour * 1 // 1 hour

func (s Authorization) GenerateNonce(param NonceParams) (NonceResult, error) {
	var nonceResult NonceResult
	var nonce Nonce
	var authAddress AuthAddress

	if err := s.DB.First(&authAddress, "address = ?", strings.ToLower(param.Address)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nonceResult, &HttpError{
				Code:    http.StatusBadRequest,
				Reason:  ERR_USER_NOT_FOUND,
				Details: "No such user exist",
			}
		}
		return nonceResult, err
	}

	if err := s.DB.First(&nonce, "address = ?", strings.ToLower(param.Address)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Nonce not found, generate a new one
			nonce.Address = authAddress.Address
			nonce.Message = generateNewNonce(authAddress, param)
			if errSave := s.DB.Save(&nonce).Error; errSave != nil {
				return nonceResult, errSave
			}
			return NonceResult{
				NonceMsg: nonce.Message,
			}, nil
		}
		return nonceResult, err
	}

	// If the nonce is not expired, return it.
	if !nonce.UpdatedAt.Add(NonceExpiryDuration).Before(time.Now()) {
		return NonceResult{
			NonceMsg: nonce.Message,
		}, nil
	}

	// Nonce found but expired, generate a new one.
	nonce.Message = generateNewNonce(authAddress, param)
	if err := s.DB.Save(&nonce).Error; err != nil {
		return nonceResult, err
	}

	return NonceResult{
		NonceMsg: nonce.Message,
	}, nil
}

func generateNewNonce(auth AuthAddress, param NonceParams) string {
	msg := "%s wants you to sign in with your Filecoin account:\n%s\n\nURI: %s\nVersion: %s\nChain ID: %d\nNonce: %s\nIssued At: %s;"
	generatedNonce := RandomNonce(16)
	return fmt.Sprintf(msg, param.Host, auth.Address, param.Host, param.Version, param.ChainId, generatedNonce, param.IssuedAt)
}

type MetamaskLoginParams struct {
	Address   string `json:"address"`
	Signature string `json:"signature"`
}

type MetamaskLoginResult struct {
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry"`
}

const TokenExpiryDurationLogin = time.Hour * 24 * 30 // 30 days

func (s Authorization) LoginWithMetamask(params MetamaskLoginParams) (MetamaskLoginResult, error) {
	var result MetamaskLoginResult
	var nonce Nonce
	var user User
	var authAddress AuthAddress

	if err := s.DB.First(&authAddress, "address = ?", strings.ToLower(params.Address)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return result, &HttpError{
				Code:    http.StatusForbidden,
				Reason:  ERR_USER_NOT_FOUND,
				Details: "No such user exist",
			}
		}
	}

	user.ID = authAddress.UserID

	if err := s.DB.First(&nonce, "address = ?", strings.ToLower(params.Address)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return result, &HttpError{
				Code:    http.StatusForbidden,
				Reason:  ERR_USER_NOT_FOUND,
				Details: "No nonce message found, please generate nonce first.",
			}
		}
	}

	// If the nonce is not expired, return it.
	if nonce.UpdatedAt.Add(NonceExpiryDuration).Before(time.Now()) {
		return result, &HttpError{
			Code:    http.StatusForbidden,
			Reason:  ERR_INVALID_AUTH,
			Details: "Nonce expired, please generate new nonce.",
		}
	}

	if !VerifySignature(params.Signature, nonce.Message, params.Address) {
		return result, &HttpError{
			Code:    http.StatusForbidden,
			Reason:  ERR_INVALID_AUTH,
			Details: "Signature verification failed",
		}
	}

	authToken, err := s.newAuthTokenForUser(&user, time.Now().Add(TokenExpiryDurationLogin), nil, "on-login", true)
	if err != nil {
		return result, err
	}

	return MetamaskLoginResult{
		Token:  authToken.Token,
		Expiry: authToken.Expiry,
	}, nil
}

type RegisterWithMetamaskParams struct {
	InviteCode string `json:"inviteCode"`
	Address    string `json:"address"`
}

type RegisterWithMetamaskResult struct {
	Success bool `json:"success"`
}

func (s Authorization) RegisterWithMetamask(params RegisterWithMetamaskParams) (RegisterWithMetamaskResult, error) {
	var result RegisterWithMetamaskResult
	var invite InviteCode

	if err := s.DB.First(&invite, "code = ?", params.InviteCode).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return result, &HttpError{
				Code:    http.StatusNotFound,
				Reason:  ERR_INVALID_INVITE,
				Details: "No such invite code was found",
			}
		}
	}

	if invite.ClaimedBy != 0 {
		return result, &HttpError{
			Code:    http.StatusBadRequest,
			Reason:  ERR_INVITE_ALREADY_USED,
			Details: "The invite code as already been claimed",
		}
	}

	username := strings.ToLower(params.Address)

	var exist *User
	if err := s.DB.First(&exist, "username = ?", username).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return result, err
		}
		exist = nil
	}

	var authExist *AuthAddress
	if err := s.DB.First(&authExist, "address = ?", username).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return result, err
		}
		authExist = nil
	}

	if exist != nil {
		return result, &HttpError{
			Code:    http.StatusBadRequest,
			Reason:  ERR_USERNAME_TAKEN,
			Details: "Address already exist",
		}
	}

	if authExist != nil {
		return result, &HttpError{
			Code:    http.StatusBadRequest,
			Reason:  ERR_USERNAME_TAKEN,
			Details: "Address already linked to an account",
		}
	}

	newUser := &User{
		Username: username,
		UUID:     uuid.New().String(),
		Perm:     PermLevelUser,
	}

	if err := s.DB.Create(&newUser).Error; err != nil {
		return result, &HttpError{
			Code:    http.StatusInternalServerError,
			Reason:  ERR_USER_CREATION_FAILED,
			Details: err.Error(),
		}
	}

	newAuthAddress := &AuthAddress{
		UserID:  newUser.ID,
		Address: username,
	}

	if err := s.DB.Create(newAuthAddress).Error; err != nil {
		return result, &HttpError{
			Code:    http.StatusInternalServerError,
			Reason:  ERR_USER_CREATION_FAILED,
			Details: err.Error(),
		}
	}

	invite.ClaimedBy = newUser.ID
	if err := s.DB.Save(&invite).Error; err != nil {
		return result, err
	}

	return RegisterWithMetamaskResult{
		Success: true,
	}, nil
}

func (s Authorization) newAuthTokenForUser(user *User, expiry time.Time, perms []string, label string, isSession bool) (*AuthToken, error) {
	if len(perms) > 1 {
		return nil, fmt.Errorf("invalid perms")
	}

	var uploadOnly bool
	if len(perms) == 1 {
		switch perms[0] {
		case "all":
			uploadOnly = false
		case "upload":
			uploadOnly = true
		default:
			return nil, fmt.Errorf("invalid perm: %q", perms[0])
		}
	}

	token := "EST" + uuid.New().String() + "ARY"
	authToken := &AuthToken{
		Token:      token,
		TokenHash:  GetTokenHash(token),
		Label:      label,
		User:       user.ID,
		Expiry:     expiry,
		UploadOnly: uploadOnly,
		IsSession:  isSession,
	}
	if err := s.DB.Create(authToken).Error; err != nil {
		return nil, err
	}

	return authToken, nil
}

type AuthAddressParams struct {
	Address string `json:"address"`
}

type AuthAddressResult struct {
	Success bool `json:"success"`
}

type AuthAddress struct {
	gorm.Model
	Address string
	UserID  uint `gorm:"index"`
}

func (s Authorization) AddAuthAddress(params AuthAddressParams, u *User) (AuthAddressResult, error) {
	var result AuthAddressResult
	var authAddress AuthAddress

	if err := s.DB.First(&authAddress, "address = ?", params.Address).Error; err == nil {
		return result, &HttpError{
			Code:    http.StatusNotFound,
			Reason:  ERR_INVALID_REQUEST,
			Details: "Address is already linked to a user",
		}
	}

	authAddress.Address = params.Address
	authAddress.UserID = u.ID

	if err := s.DB.Create(&authAddress).Error; err != nil {
		return result, &HttpError{
			Code:    http.StatusNotFound,
			Reason:  ERR_INTERNAL_ERROR,
			Details: err.Error(),
		}
	}

	return AuthAddressResult{
		Success: true,
	}, nil
}

func (s Authorization) RemoveAuthAddress(params AuthAddressParams, u *User) (AuthAddressResult, error) {
	var result AuthAddressResult
	var authAddress AuthAddress

	if params.Address == u.Username {
		return result, &HttpError{
			Code:    http.StatusBadRequest,
			Reason:  ERR_INVALID_REQUEST,
			Details: "Can't remove main account address",
		}
	}

	if err := s.DB.First(&authAddress, "address = ?", params.Address).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return result, &HttpError{
				Code:    http.StatusBadRequest,
				Reason:  ERR_INVALID_REQUEST,
				Details: "Address not found",
			}
		}
	}

	authAddress.Address = params.Address
	authAddress.UserID = u.ID

	if err := s.DB.Delete(&authAddress).Error; err != nil {
		return result, &HttpError{
			Code:    http.StatusBadRequest,
			Reason:  ERR_INTERNAL_ERROR,
			Details: err.Error(),
		}
	}

	return AuthAddressResult{
		Success: true,
	}, nil
}

func (s Authorization) GetAuthAddress(u *User) (AuthAddressParams, error) {
	var authAddress AuthAddress

	if err := s.DB.First(&authAddress, "user_id = ?", u.ID).Error; err != nil {
		authAddress.Address = ""
	}

	return AuthAddressParams{
		Address: authAddress.Address,
	}, nil
}
