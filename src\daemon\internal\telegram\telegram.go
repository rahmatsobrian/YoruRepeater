package telegram

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Send sends a text message to a Telegram chat via the Bot API.
func Send(botToken, chatID, text string) error {
	if botToken == "" || chatID == "" {
		return fmt.Errorf("telegram bot token or chat ID is empty")
	}
	apiURL := "https://api.telegram.org/bot" + botToken + "/sendMessage"
	data := url.Values{}
	data.Set("chat_id", chatID)
	data.Set("text", text)
	data.Set("parse_mode", "HTML")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	resp, err := client.PostForm(apiURL, data)
	if err != nil {
		return fmt.Errorf("telegram send failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
