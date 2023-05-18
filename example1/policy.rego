package main

default allow = false

# Allow users to get their own salaries.
allow {
    some username
    input.method == "GET"
    input.path = ["finance", "salary", username]
    token.payload.user == username
    user_owns_token
}

# Allow managers to get their subordinate' salaries.
allow {
    some username
    input.method == "GET"
    input.path = ["finance", "salary", username]
    token.payload.subordinates[_] == username
    user_owns_token
}

# Allow HR members to get anyone's salary.
allow {
    input.method == "GET"
    input.path = ["finance", "salary", _]
    token.payload.hr == true
    user_owns_token
}

# Ensure that the token was issued to the user supplying it.
user_owns_token { input.user == token.payload.azp }

# Helper to get the token payload.
token := {"payload": payload} {
    [header, payload, signature] := io.jwt.decode(input.token)
}

########
# user-role assignments
user_roles := {
    "alice": ["engineering", "webdev"],
    "bob": ["hr"]
}

# role-permissions assignments
role_permissions := {
    "engineering": [{"action": "read",  "object": "server123"}],
    "webdev":      [{"action": "read",  "object": "server123"},
                    {"action": "write", "object": "server123"}],
    "hr":          [{"action": "read",  "object": "database456"}]
}

# logic that implements RBAC.
default allow = false
allow {
    # lookup the list of roles for the user
    roles := user_roles[input.user]
    # for each role in that list
    r := roles[_]
    # lookup the permissions list for role r
    permissions := role_permissions[r]
    # for each permission
    p := permissions[_]
    # check if the permission granted to r matches the user's request
    p == {"action": input.action, "object": input.object}
}

allow := true {
    input.request.method == "GET"
    input.request.path == ["users", input.request.user.name]
}

