package provide jwt 1.0

package require sha256
package require base64

namespace eval ::jwt {
    namespace export encode decode verify
    namespace ensemble create

    # Base64URL encode
    proc base64url_encode {data} {
        set encoded [::base64::encode -wrapchar "" $data]
        set encoded [string map {+ - / _ = {}} $encoded]
        return $encoded
    }

    # Base64URL decode
    proc base64url_decode {data} {
        # Add padding if necessary
        set pad_len [expr {4 - ([string length $data] % 4)}]
        if {$pad_len < 4} {
            append data [string repeat = $pad_len]
        }
        set data [string map {- + _ /} $data]
        return [::base64::decode $data]
    }

    # Create HMAC-SHA256 signature
    proc hmac_sha256 {key message} {
        return [binary format H* [sha2::hmac $message $key]]
    }

    # Convert dict to compact JSON
    proc dict2json {dict} {
        set json ""
        append json "\{"
        set first 1
        dict for {key value} $dict {
            if {!$first} {
                append json ","
            }
            append json "\"$key\":\"$value\""
            set first 0
        }
        append json "\}"
        return $json
    }

    # Convert JSON to dict
    proc json2dict {json} {
        # Remove whitespace and quotes
        set json [string map {" " {} "\n" {} "\r" {} "\t" {}} $json]
        # Remove outer braces
        set json [string range $json 1 end-1]
        # Split into key-value pairs
        set pairs [split $json ","]
        set result [dict create]
        foreach pair $pairs {
            set kv [split $pair ":"]
            set key [string trim [lindex $kv 0] "\{\}\""]
            set value [string trim [lindex $kv 1] "\{\}\""]
            dict set result $key $value
        }
        return $result
    }

    # Encode JWT
    proc encode {payload key {alg "HS256"}} {
        # Create header
        set header [dict create \
            typ "JWT" \
            alg $alg]

        # Base64URL encode header and payload
        set header_encoded [base64url_encode [dict2json $header]]
        set payload_encoded [base64url_encode [dict2json $payload]]

        # Create signature input
        set signature_input "$header_encoded.$payload_encoded"

        # Create signature based on algorithm
        switch -- $alg {
            "HS256" {
                set signature [hmac_sha256 $key $signature_input]
                set signature_encoded [base64url_encode $signature]
            }
            default {
                error "Unsupported algorithm: $alg"
            }
        }

        # Return complete JWT
        return "$signature_input.$signature_encoded"
    }

    # Decode JWT without verification
    proc decode_unverified {token} {
        # Split token into parts
        set parts [split $token .]
        if {[llength $parts] != 3} {
            error "Invalid token format"
        }
        
        lassign $parts header_b64 payload_b64 signature_b64
        
        # Decode header and payload
        set header [json2dict [base64url_decode $header_b64]]
        set payload [json2dict [base64url_decode $payload_b64]]
        
        return [list $header $payload $signature_b64]
    }

    # Decode and verify JWT
    proc decode {token key} {
        # Decode token parts
        lassign [decode_unverified $token] header payload signature_b64
        
        # Verify algorithm
        set alg [dict get $header alg]
        if {$alg ne "HS256"} {
            error "Unsupported algorithm: $alg"
        }
        
        # Verify signature
        set parts [split $token .]
        set signature_input "[lindex $parts 0].[lindex $parts 1]"
        set expected_signature [base64url_encode [hmac_sha256 $key $signature_input]]
        
        if {$signature_b64 ne $expected_signature} {
            error "Invalid signature"
        }
        
        # Verify expiration
        if {[dict exists $payload exp]} {
            set exp [dict get $payload exp]
            if {$exp < [clock seconds]} {
                error "Token has expired"
            }
        }
        
        return $payload
    }

    # Verify JWT without decoding payload
    proc verify {token key} {
        try {
            decode $token $key
            return 1
        } trap {JWT INVALID} {} {
            return 0
        } trap {TCL LOOKUP} {} {
            return 0
        }
    }
}
