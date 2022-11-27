# password-reset-backend

## [Deployed URL](https://password-reset-api.onrender.com)

## [Frontend Source code](https://github.com/SaiPraneethPegada/password-reset-frontend.git)

## API End-Points:

| Method | End point | Description |
| ---- | ---- | ---- |
| POST | /auth/signup | signup requirements -> username(unique, min 6 characters length), email(unregistered), password(Min 8 characters length). Activation mail will be sent after requirements met. |
| POST | /auth/activate | Activation mail contains a link(valid for 5mins). User needs to open that link for successful account activation. After successful activation user will be redirected to login page. |
| POST | /auth/signin | signin requirements -> email(registered), password. |
| POST | /auth/forgot | user enter registered mail ID -> Recieves mail which contains password reset link(valid for 5mins) -> onclick redirect to reset password page. |
| POST | /auth/reset | user enters password(min 8 characters) and confirm password -> Both password and confirm password should match -> password should not be same as old password -> Password reset successful. |
