let input = {}

let allow
if (input.request.method === "GET" &&
    input.request.path[0] === "users" &&
    input.request.path[1] === input.request.user.name) {
    allow = true
}

if (input.request.method === "POST" &&
    input.request.path[0] === "users" &&
    input.request.path[1] === input.request.user.name) {
    allow = true
}

