package providers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/schema"
	log "github.com/sirupsen/logrus"
	"github.com/synctv-org/synctv/internal/provider"
	"golang.org/x/oauth2"
)

var decoder = schema.NewDecoder()

type DiscourseProvider struct {
	config       oauth2.Config
	ssoSecret    string
	discourseURL string
	nonceStore   *nonceStorage
}

type discourseUserInfo struct {
	Nonce      string `form:"nonce"`
	ExternalID string `form:"external_id"`
	Username   string `form:"username"`
	Name       string `form:"name"`
	Email      string `form:"email"`
	AvatarURL  string `form:"avatar_url"`
	Admin      bool   `form:"admin"`
	Moderator  bool   `form:"moderator"`
	Groups     string `form:"groups"`
	Failed     bool   `form:"failed"`
}

type nonceStorage struct {
	store map[string]time.Time
	mu    sync.Mutex
}

func newNonceStorage() *nonceStorage {
	return &nonceStorage{
		store: make(map[string]time.Time),
	}
}

func (ns *nonceStorage) Add(nonce string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.store[nonce] = time.Now().Add(5 * time.Minute)
}

func (ns *nonceStorage) Validate(nonce string) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if expiry, exists := ns.store[nonce]; exists {
		delete(ns.store, nonce)
		return time.Now().Before(expiry)
	}
	return false
}

func newDiscourseProvider() provider.Interface {
	return &DiscourseProvider{
		nonceStore: newNonceStorage(),
		config: oauth2.Config{
			Endpoint: oauth2.Endpoint{},
		},
	}
}

func (p *DiscourseProvider) Init(c provider.Oauth2Option) {
	p.config.ClientID = c.ClientID
	p.config.ClientSecret = c.ClientSecret
	p.config.RedirectURL = c.RedirectURL
	p.ssoSecret = c.ClientSecret // Discourse使用同一个secret作为SSO密钥
	p.discourseURL = c.ClientID  // 使用AuthURL字段存储Discourse根URL
}

func (p *DiscourseProvider) Provider() provider.OAuth2Provider {
	return "bbzlb"
}

func (p *DiscourseProvider) NewAuthURL(ctx context.Context, state string) (string, error) {
	nonce := generateRandomString(16)
	p.nonceStore.Add(nonce)

	payload := url.Values{}
	payload.Set("nonce", nonce)
	payload.Set("return_sso_url", p.config.RedirectURL)

	base64Payload := base64.StdEncoding.EncodeToString([]byte(payload.Encode()))
	urlEncodedPayload := url.QueryEscape(base64Payload)

	mac := hmac.New(sha256.New, []byte(p.ssoSecret))
	mac.Write([]byte(base64Payload))
	signature := hex.EncodeToString(mac.Sum(nil))

	return p.discourseURL + "/session/sso_provider?sso=" + urlEncodedPayload + "&sig=" + signature, nil
}

func (p *DiscourseProvider) GetToken(ctx context.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil // Discourse不需要传统OAuth2 token
}

func (p *DiscourseProvider) RefreshToken(ctx context.Context, tk string) (*oauth2.Token, error) {
	return nil, errors.New("discourse provider does not support token refresh")
}

func (p *DiscourseProvider) GetUserInfo(ctx context.Context, code string) (*provider.UserInfo, error) {
	log.Infof("Discourse SSO callback received: %s", code)
	params, err := url.ParseQuery(code)
	if err != nil {
		return nil, err
	}

	sso := params.Get("sso")
	sig := params.Get("sig")

	// 验证签名
	mac := hmac.New(sha256.New, []byte(p.ssoSecret))
	mac.Write([]byte(sso))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	log.Infof("SSO signature verification: expected=%s, received=%s", expectedSig, sig)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		log.Infof("SSO signature verification failed")
		return nil, errors.New("invalid signature")
	}

	// Base64解码
	decoded, err := base64.StdEncoding.DecodeString(sso)
	if err != nil {
		return nil, err
	}

	query, err := url.ParseQuery(string(decoded))
	if err != nil {
		return nil, err
	}

	var dui discourseUserInfo
	if err := decoder.Decode(&dui, query); err != nil {
		return nil, err
	}

	if dui.Failed {
		log.Infof("SSO authentication failed")
		return nil, errors.New("sso authentication failed")
	}

	if !p.nonceStore.Validate(dui.Nonce) {
		log.Infof("SSO nonce validation failed: %s", dui.Nonce)
		return nil, errors.New("invalid nonce")
	}
	log.Infof("Successfully retrieved user info: username=%s, id=%s", dui.Username, dui.ExternalID)
	return &provider.UserInfo{
		Username:       dui.Username,
		ProviderUserID: dui.ExternalID,
		//Email:          dui.Email,
	}, nil
}

func init() {
	decoder.IgnoreUnknownKeys(true)
	RegisterProvider(newDiscourseProvider())
}

// helper函数生成随机字符串
func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err) // 在实际生产环境中应更优雅地处理错误
		}
		b[i] = letters[num.Int64()]
	}
	return string(b)
}
