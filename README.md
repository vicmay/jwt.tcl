# TCL JWT Package

A TCL implementation of JSON Web Tokens (JWT) that provides token generation, verification, and payload management.

## Features

- JWT token generation with HMAC-SHA256 signatures
- Token verification and validation
- Expiration checking
- Base64URL encoding/decoding
- Custom JSON encoding/decoding for JWT compatibility

## Installation

1. Add the JWT package directory to your `auto_path`:
```tcl
lappend auto_path [file dirname [info script]]
```

2. Load the package:
```tcl
package require jwt
```

## Usage

### Basic Token Creation and Verification

```tcl
# Create a token
set payload [dict create \
    sub "user123" \
    exp [expr {[clock seconds] + 3600}]]
set token [jwt::encode $payload "your-secret-key"]

# Verify and decode a token
if {[catch {set payload [jwt::decode $token "your-secret-key"]} err]} {
    # Handle invalid token
    puts "Error: $err"
} else {
    # Use payload data
    set user_id [dict get $payload sub]
}
```

## Payload Structure

The payload in a JWT is a JSON object that contains claims. Here are the different types of claims:

### 1. Registered Claims (Recommended)

```tcl
set payload [dict create \
    # Subject - Unique identifier for the user
    sub "user123" \
    
    # Issued At - Timestamp when the token was issued
    iat [clock seconds] \
    
    # Expiration Time - Timestamp when the token should expire
    exp [expr {[clock seconds] + 3600}] \
    
    # Not Before - Timestamp before which token should not be accepted
    nbf [clock seconds] \
    
    # JWT ID - Unique identifier for the token
    jti "unique-token-id" \
    
    # Issuer - Who issued the token
    iss "your-auth-server" \
    
    # Audience - Who the token is intended for
    aud "your-app"
]
```

### 2. Public Claims

Use URI format to avoid collisions:

```tcl
set payload [dict create \
    "https://your-domain.com/roles" "admin" \
    "https://your-domain.com/permissions" "read write"
]
```

### 3. Private Claims

Custom claims for sharing information:

```tcl
set payload [dict create \
    # User information
    name "John Doe" \
    email "john@example.com" \
    
    # Application-specific data
    user_preferences [dict create \
        theme "dark" \
        language "en"
    ] \
    
    # Access control
    roles "admin moderator" \
    permissions "read write delete"
]
```

### Complete Example

```tcl
# Create a comprehensive payload
set payload [dict create \
    # Registered claims
    sub "user123" \
    iat [clock seconds] \
    exp [expr {[clock seconds] + 3600}] \
    iss "auth-server" \
    
    # User information
    name "John Doe" \
    email "john@example.com" \
    
    # Access control
    roles "admin" \
    permissions "read write" \
    
    # Custom application data
    last_login [clock seconds] \
    account_type "premium"
]

# Create the token
set token [jwt::encode $payload $secret_key]
```

## Security Considerations

1. **Payload Security**
   - Never include sensitive information (passwords, keys) in the payload
   - The payload is Base64Url encoded, not encrypted
   - Anyone can decode and read the payload without the secret key

2. **Payload Size**
   - Keep payloads small as they're included in every request
   - Only include necessary information
   - Use references instead of embedding large data structures

3. **Token Expiration**
   - Always include an `exp` claim
   - Use reasonable expiration times (e.g., 1 hour for access tokens)
   - Consider using refresh tokens for longer sessions

4. **Claim Validation**
   - Validate all claims when decoding tokens
   - Check expiration time
   - Verify issuer and audience if used
   - Validate custom claims specific to your application

### Example of Claim Validation

```tcl
if {[catch {set payload [jwt::decode $token $secret_key]} err]} {
    error "Invalid token: $err"
}

# Check required claims
foreach claim {sub name roles} {
    if {![dict exists $payload $claim]} {
        error "Missing required claim: $claim"
    }
}

# Validate roles
set roles [dict get $payload roles]
if {$roles ni {"admin" "user" "moderator"}} {
    error "Invalid role: $roles"
}

# Check permissions for specific actions
set permissions [dict get $payload permissions]
if {"write" ni [split $permissions " "]} {
    error "Insufficient permissions: write access required"
}
```

## Dependencies

- TCL 8.6 or higher
- `sha256` package
- `base64` package

## License

This package is provided under "The Unlicense" license.
