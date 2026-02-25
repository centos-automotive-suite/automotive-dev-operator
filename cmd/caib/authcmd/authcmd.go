// Package authcmd provides the `caib auth` CLI command group for token management.
package authcmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

var (
	verbose bool
)

// NewAuthCmd creates the `caib auth` command with subcommands.
func NewAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication tokens",
		Long:  `Commands for inspecting and refreshing OIDC authentication tokens.`,
	}

	cmd.AddCommand(newStatusCmd())
	cmd.AddCommand(newRefreshCmd())

	return cmd
}

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display token status and expiry information",
		Run:   runStatus,
	}
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show additional token details")
	return cmd
}

func newRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Refresh the access token using a stored refresh token",
		Run:   runRefresh,
	}
}

func getInsecureSkipTLS(cmd *cobra.Command) bool {
	if cmd.Root() != nil {
		if flag := cmd.Root().PersistentFlags().Lookup("insecure"); flag != nil {
			if val, err := strconv.ParseBool(flag.Value.String()); err == nil {
				return val
			}
		}
	}
	v := strings.TrimSpace(os.Getenv("CAIB_INSECURE"))
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

func runStatus(_ *cobra.Command, _ []string) {
	cache, err := auth.LoadTokenCache()
	if err != nil {
		fmt.Println(color.RedString("No cached token found."))
		fmt.Println("Run 'caib login <server-url>' to authenticate.")
		return
	}

	if cache.Token == "" {
		fmt.Println(color.RedString("Token cache is empty."))
		fmt.Println("Run 'caib login <server-url>' to authenticate.")
		return
	}

	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err = parser.ParseUnverified(cache.Token, claims)
	if err != nil {
		fmt.Printf(color.RedString("Failed to parse cached token: %v\n"), err)
		return
	}

	exp, hasExp := claims["exp"].(float64)
	if !hasExp {
		fmt.Println(color.YellowString("Token has no expiration claim."))
	} else {
		expTime := time.Unix(int64(exp), 0)
		remaining := time.Until(expTime)
		duration := formatDuration(remaining)

		fmt.Printf("Token expiry: %s\n", expTime.UTC().Format("2006-01-02 15:04:05 UTC"))
		printTokenStatus(remaining, duration)
	}

	if sub, ok := claims["sub"].(string); ok && sub != "" {
		fmt.Printf("Subject: %s\n", sub)
	}
	if iss, ok := claims["iss"].(string); ok && iss != "" {
		fmt.Printf("Issuer: %s\n", iss)
	}

	if verbose {
		if iat, ok := claims["iat"].(float64); ok {
			t := time.Unix(int64(iat), 0)
			fmt.Printf("Issued at: %s\n", t.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
		if authTime, ok := claims["auth_time"].(float64); ok {
			t := time.Unix(int64(authTime), 0)
			fmt.Printf("Auth time: %s\n", t.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
		if cache.RefreshToken != "" {
			fmt.Println("Refresh token stored: yes")
		} else {
			fmt.Println("Refresh token stored: no")
		}
	}
}

func runRefresh(cmd *cobra.Command, _ []string) {
	serverURL := config.DefaultServer()
	if serverURL == "" {
		fmt.Println(color.RedString("No server configured."))
		fmt.Println("Run 'caib login <server-url>' first.")
		return
	}

	insecure := getInsecureSkipTLS(cmd)
	ctx := context.Background()

	token, err := auth.RefreshCachedToken(ctx, serverURL, insecure)
	if err != nil {
		fmt.Printf(color.RedString("Refresh failed: %v\n"), err)
		fmt.Println("Run 'caib login <server-url>' to re-authenticate.")
		return
	}

	if token == "" {
		fmt.Println(color.RedString("Refresh returned an empty token."))
		fmt.Println("Run 'caib login <server-url>' to re-authenticate.")
		return
	}
	fmt.Println("Access token refreshed successfully.")
}

const tokenExpiryWarningSeconds = 300

func printTokenStatus(remaining time.Duration, duration string) {
	hint := "Run 'caib auth refresh' or 'caib login <server-url>' to refresh."

	switch {
	case remaining < 0:
		fmt.Println(color.RedString("Status: EXPIRED (%s ago)", duration))
		fmt.Println(color.YellowString(hint))
	case remaining.Seconds() < tokenExpiryWarningSeconds:
		fmt.Println(color.RedString("Status: EXPIRING SOON (%s remaining)", duration))
		fmt.Println(color.YellowString(hint))
	case remaining < time.Hour:
		fmt.Println(color.YellowString("Status: Valid (%s remaining)", duration))
	default:
		fmt.Println(color.GreenString("Status: Valid (%s remaining)", duration))
	}
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
