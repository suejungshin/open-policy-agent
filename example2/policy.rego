package play

import future.keywords.if

default allow = false

methodRoles := {
  "GET": "reader",
  "HEAD": "reader",
  "OPTIONS": "reader",
  "PUT": "writer",
  "POST": "writer",
  "PATCH": "writer",
  "DELETE": "writer",
}

scopes := {
  "activities:reader": "workflow:read",
  "activities:writer": "workflow:write",
  "api-keys:reader": "apikey:read",
  "api-keys:writer": "apikey:write",
  "app-developers:writer": "appdev:write",
  "app-instances:reader": "marketplace:read",
  "app-instances:writer": "marketplace:write",
  "applications:reader": "property:read",
  "applications:writer": "property:write"
}

contains(arr, elem) {
  arr[_] = elem
}

tokenScopes = split(input.claims.scope, " ")

allow {
  input.path[0] == "api"
  area := input.path[1]
  role := methodRoles[input.method]
  scope := concat(":", [area, role])
  contains(tokenScopes, scopes[scope])
}
