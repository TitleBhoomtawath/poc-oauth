# POC-GO-OAUTH2

This is a tool for exchanging a token for IAM access token.
It's originally forked from github.com/BNPrashanth/poc-go-oauth2.

To learn more about Ops Portal Plugin, please read [Ops Portal Introduction](https://ops-portal-docs.deliveryhero.io/#/).

# Instruction

# Dependencies

* Go
* Nodejs
* https://github.com/TitleBhoomtawath/google-oauth-react

## Config

1. Copy config.example and rename it to config.yml.
1. In the IAM section, change `hmacKey` to a valid hmacKey.
1. If you want to authenticate to production, then change `authUrl` to https://iam.dh-auth.io/api/v1/oauth2/token.

## Usage

1. Request access to the application in `appID` with this [here](https://jira.deliveryhero.com/plugins/servlet/desk/portal/65/create/2296).
1. Running poc-oauth. It will start an HTTP server on port 9090.
1. Clone https://github.com/TitleBhoomtawath/google-oauth-react to be used as a GUI tool.
1. Running a google-oauth-react with `npm start` command. This will open a web page on localhost:3000.
1. On localhost:3000, login with your Foodpanda/Delivery account.
1. You should get your access token to be used to authenticate against an Ops-Portal Plugin.

# Troubleshooting

## Get 403 when logging with Google

If you can't login with your Google account, please check that your account has permissions to the `appID`.
It's set to `ops-portal-pd-corporate-api` by default.
