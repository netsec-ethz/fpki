

# Populate the log DB (~ 5 min):
go run ./clone/cmd/ctclone --alsologtostderr --v=1  --mysql_uri 'clonetool:letmein@tcp(localhost)/google_xenon2022' --log_url https://testflume.ct.letsencrypt.org/2022/ --workers=32
