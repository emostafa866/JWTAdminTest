**JWTAdminTest**

- task details >>customize filter to verify JWT sent to admin after login so he can access all resources 

**hints**

- u will use the same collection attached with the task and the same api to login >> localhost:8080/api/admin

- after login u will only recieve a JWT in the response then u can intercept with each request header .

- the key of the header will be " Auth" and the value of JWT will starts with "Bearer " .
