package main

import (
	"log"
	"net/http"

	"github.com/BNPrashanth/poc-go-oauth2/internal/configs"
	"github.com/BNPrashanth/poc-go-oauth2/internal/logger"
	"github.com/BNPrashanth/poc-go-oauth2/internal/services"

	"github.com/spf13/viper"
)

func main() {
	// Initialize Viper across the application
	configs.InitializeViper()

	// Initialize Logger across the application
	logger.InitializeZapCustomLogger()

	// Initialize Oauth2 Services
	services.InitializeOAuthFacebook()
	services.InitializeOAuthGoogle()
	services.InitializeOAuthIAM()

	// Routes for the application
	http.HandleFunc("/", services.HandleMain)
	//http.HandleFunc("/login-fb", services.HandleFacebookLogin)
	//http.HandleFunc("/callback-fb", services.CallBackFromFacebook)
	http.HandleFunc("/login-gl", services.HandleGoogleLogin)
	//http.HandleFunc("/callback-gl", services.CallBackFromGoogle)
	http.HandleFunc("/login-iam", services.HandleIAMLogin)
	http.HandleFunc("/callback-gl", services.CallBackToIAM)

	logger.Log.Info("Started running on http://localhost:" + viper.GetString("port"))
	log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), nil))
}
