#!/usr/bin/tclsh

# Add current directory to auto_path
lappend auto_path [file dirname [info script]]

package require jwt

# Test key
set secret_key "your-256-bit-secret"

# Test payload
set payload [dict create \
    sub "1234567890" \
    name "John Doe" \
    iat [clock seconds] \
    exp [expr {[clock seconds] + 3600}]]

puts "Testing JWT Package:"
puts "==================="

# Test 1: Encode token
puts "\nTest 1: Encoding JWT"
puts "--------------------"
set token [jwt::encode $payload $secret_key]
puts "Generated Token: $token"

# Test 2: Decode token
puts "\nTest 2: Decoding JWT"
puts "--------------------"
set decoded [jwt::decode $token $secret_key]
puts "Decoded Payload: [jwt::dict2json $decoded]"

# Test 3: Verify valid token
puts "\nTest 3: Verifying valid JWT"
puts "-------------------------"
if {[jwt::verify $token $secret_key]} {
    puts "Token verification successful"
} else {
    puts "Token verification failed"
}

# Test 4: Verify invalid token
puts "\nTest 4: Verifying invalid JWT"
puts "--------------------------"
set invalid_token "${token}x"
if {[catch {jwt::decode $invalid_token $secret_key} err]} {
    puts "Successfully caught invalid token: $err"
}

# Test 5: Test expired token
puts "\nTest 5: Testing expired token"
puts "-------------------------"
set expired_payload [dict create \
    sub "1234567890" \
    exp [expr {[clock seconds] - 3600}]]
set expired_token [jwt::encode $expired_payload $secret_key]
if {[catch {jwt::decode $expired_token $secret_key} err]} {
    puts "Successfully caught expired token: $err"
}
