package core

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	ERR_INVALID_TOKEN              = "ERR_INVALID_TOKEN"
	ERR_TOKEN_EXPIRED              = "ERR_TOKEN_EXPIRED"
	ERR_AUTH_MISSING               = "ERR_AUTH_MISSING"
	ERR_WRONG_AUTH_FORMAT          = "ERR_WRONG_AUTH_FORMAT"
	ERR_INVALID_AUTH               = "ERR_INVALID_AUTH"
	ERR_AUTH_MISSING_BEARER        = "ERR_AUTH_MISSING_BEARER"
	ERR_NOT_AUTHORIZED             = "ERR_NOT_AUTHORIZED"
	ERR_MINER_NOT_OWNED            = "ERR_MINER_NOT_OWNED"
	ERR_INVALID_INVITE             = "ERR_INVALID_INVITE"
	ERR_USERNAME_TAKEN             = "ERR_USERNAME_TAKEN"
	ERR_USER_CREATION_FAILED       = "ERR_USER_CREATION_FAILED"
	ERR_USER_NOT_FOUND             = "ERR_USER_NOT_FOUND"
	ERR_INVALID_PASSWORD           = "ERR_INVALID_PASSWORD"
	ERR_INVITE_ALREADY_USED        = "ERR_INVITE_ALREADY_USED"
	ERR_CONTENT_ADDING_DISABLED    = "ERR_CONTENT_ADDING_DISABLED"
	ERR_INVALID_INPUT              = "ERR_INVALID_INPUT"
	ERR_CONTENT_SIZE_OVER_LIMIT    = "ERR_CONTENT_SIZE_OVER_LIMIT"
	ERR_PEERING_PEERS_ADD_ERROR    = "ERR_PEERING_PEERS_ADD_ERROR"
	ERR_PEERING_PEERS_REMOVE_ERROR = "ERR_PEERING_PEERS_REMOVE_ERROR"
	ERR_PEERING_PEERS_START_ERROR  = "ERR_PEERING_PEERS_START_ERROR"
	ERR_PEERING_PEERS_STOP_ERROR   = "ERR_PEERING_PEERS_STOP_ERROR"
	ERR_CONTENT_NOT_FOUND          = "ERR_CONTENT_NOT_FOUND"
	ERR_INVALID_PINNING_STATUS     = "ERR_INVALID_PINNING_STATUS"
)

type HttpError struct {
	Code    int    `json:"code,omitempty"`
	Reason  string `json:"reason"`
	Details string `json:"details"`
}

func (he HttpError) Error() string {
	if he.Details == "" {
		return he.Reason
	}
	return he.Reason + ": " + he.Details
}

type HttpErrorResponse struct {
	Error HttpError `json:"error"`
}

const (
	PermLevelUpload = 1
	PermLevelUser   = 2
	PermLevelAdmin  = 10
)

// isValidAuth checks if authStr is a valid
// returns false if authStr is not in a valid format
// returns true otherwise
func IsValidAuth(authStr string) bool {
	matchEst, _ := regexp.MatchString("^EST(.+)ARY$", authStr)
	matchSecret, _ := regexp.MatchString("^SECRET(.+)SECRET$", authStr)
	if !matchEst && !matchSecret {
		return false
	}

	// only get the uuid from the string
	uuidStr := strings.ReplaceAll(authStr, "SECRET", "")
	uuidStr = strings.ReplaceAll(uuidStr, "EST", "")
	uuidStr = strings.ReplaceAll(uuidStr, "ARY", "")

	// check if uuid is valid
	_, err := uuid.Parse(uuidStr)
	if err != nil {
		return false
	}
	return true
}

func ExtractAuth(c echo.Context) (string, error) {
	auth := c.Request().Header.Get("Authorization")
	//	undefined will be the auth value if ESTUARY_TOKEN cookie is removed.
	if auth == "" || auth == "undefined" {
		return "", &HttpError{
			Code:    http.StatusUnauthorized,
			Reason:  ERR_AUTH_MISSING,
			Details: "no api key was specified",
		}
	}

	parts := strings.Split(auth, " ")
	if len(parts) != 2 {
		return "", &HttpError{
			Code:    http.StatusUnauthorized,
			Reason:  ERR_INVALID_AUTH,
			Details: "invalid api key was specified",
		}
	}

	if parts[0] != "Bearer" {
		return "", &HttpError{
			Code:    http.StatusUnauthorized,
			Reason:  ERR_AUTH_MISSING_BEARER,
			Details: "invalid api key was specified",
		}
	}
	return parts[1], nil
}

func GetPasswordHash(password, salt string, dialector string) string {
	switch dialector { // can be "postgres", "sqlite"
	case "sqlite": // for sqlite, embedded db.
		return GetPasswordHashBase(password, salt)
	default: // default (postgres or other rdbms)
		return GetPasswordHashBase64(password, salt)
	}
}

func GetPasswordHashBase(password, salt string) string {
	passHashBytes := sha256.Sum256([]byte(password + "." + salt))
	return string(passHashBytes[:])
}

func GetPasswordHashBase64(password, salt string) string {
	passHashBytes := sha256.Sum256([]byte(password + "." + salt))
	return b64.StdEncoding.EncodeToString(passHashBytes[:])
}

func GetTokenHash(token string) string {
	tokenHashBytes := sha256.Sum256([]byte(token))
	// needs to be URL-encodable to send revoke token requests by hash
	return b64.RawURLEncoding.EncodeToString(tokenHashBytes[:])
}

func RandomNonce(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func VerifySignature(sign string, msg string, address string) bool {
	sig := hexutil.MustDecode(sign)
	if sig[crypto.RecoveryIDOffset] == 27 || sig[crypto.RecoveryIDOffset] == 28 {
		sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
	}
	msgBytes := accounts.TextHash([]byte(msg))
	recovered, err := crypto.SigToPub(msgBytes, sig)
	if err != nil {
		return false
	}

	recoveredAddr := crypto.PubkeyToAddress(*recovered)

	if address != strings.ToLower(recoveredAddr.Hex()) {
		return false
	}

	return true
}
