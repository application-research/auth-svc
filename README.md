# EV2 Auth Service API

[![Go](https://github.com/application-research/estuary-auth/actions/workflows/go.yml/badge.svg)](https://github.com/application-research/estuary-auth/actions/workflows/go.yml)

Auth Service is a service that provides a generic authentication.

![image](https://user-images.githubusercontent.com/4479171/179639246-2ae8c27c-fd9b-416f-8dda-be443f3d7526.png)


## Running
create a .env with the following
```
DB_DSN=<DSN>
```

run the node
```
./auth-svc
```

This opens up a port at 1313 by default

## Usage
### /check-api-key
- URL: https://estuary-auth-api.onrender.com/check/api-key
- Method: POST
```
{
    "Token":"<token>"
}
```

### /check-user-api-key
- URL: https://estuary-auth-api.onrender.com/check/user-api-key
- Method: POST
```
{
    "Username":"alvinreyes",
    "Token":"<token>"
}
```
### /check-user-pass
- URL: https://estuary-auth-api.onrender.com/check/user-pass
- Method: POST
```
{
    "Username":"alvinreyes",
    "Password":"<password>"
}
```

# Remote endpoint
This service api is currently available here `https://auth-svc.onrender.com/`