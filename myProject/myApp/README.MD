API Documentation

User Authentication and Profile Management Endpoints
1. Sign Up
URL: /signup/
HTTP Method: POST
Description: Registers a new user.
Request Headers:
Content-Type: application/json
Request Payload:

{
    "username": "string",
    "password": "string",
    "email": "string"
}
Response: Success
Status Code: 201 Created
Body:
{
    "message": "User registered successfully",
    "user_id": "integer"
}

Response:Error
Status Code: 400 Bad Request
Body:

{
    "error": "Error message",
    "details": "Additional details about the error"
}

2. Login
URL: /login/
HTTP Method: POST
Description: Logs in an existing user.
Request Headers:
Content-Type: application/json
Request Payload:

{
    "username": "string",
    "password": "string"
}
Response:Success
Status Code: 200 OK
Body:

{
    "message": "Login successful",
    "token": "string"
}
Response:Error:
Status Code: 401 Unauthorized
Body:

{
    "error": "Invalid credentials",
    "details": "Username or password is incorrect"
}

3. Logout
URL: /logout/
HTTP Method: POST
Description: Logs out the current user.
Request Headers:
Authorization:  <token>
Request Payload: None
Response:Success
Status Code: 200 OK
Body:

{
    "message": "Logout successful"
}
Response:Error:
Status Code: 401 Unauthorized
Body:

{
    "error": "Unauthorized",
    "details": "Authentication token is missing or invalid"
}

4. Change Password
URL: /change_password/
HTTP Method: POST
Description: Changes the user's password.
Request Headers:
Authorization:  <token>
Content-Type: application/json
Request Payload:

{
    "old_password": "string",
    "new_password": "string"
}
Response:Success
Status Code: 200 OK
Body:

{
    "message": "Password changed successfully"
}
Response:Error
Status Code: 400 Bad Request
Body:

{
    "error": "Invalid request",
    "details": "Old password is incorrect or new password does not meet criteria"
}

5. Forget Password
URL: /forget_password/
HTTP Method: POST
Description: Initiates the password reset process.
Request Headers:
Content-Type: application/json
Request Payload:
{
    "email": "string"
}
Response:Success
Status Code: 200 OK
Body:

{
    "message": "Password reset instructions sent to email"
}
Response:Error
Status Code: 404 Not Found
Body:

{
    "error": "Email not found",
    "details": "No account associated with the provided email"
}

6. Update Email
URL: /update_email/
HTTP Method: POST
Description: Updates the user's email address.
Request Headers:
Authorization:  <token>
Content-Type: application/json
Request Payload:

{
    "new_email": "string",
    "password": "string"
}
Response:Success
Status Code: 200 OK
Body:

{
    "message": "Email updated successfully"
}
Response:Error
Status Code: 400 Bad Request
Body:

{
    "error": "Invalid request",
    "details": "Password is incorrect or new email is invalid"
}