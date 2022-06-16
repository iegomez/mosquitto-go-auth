function checkUser(token, username, claims) {
    if(claims.username != username) {
        return false;
    }
    if(claims.iss != "jwt-test") {
        return false;
    }
    if(username == "test") {
        return true;
    }
    return false;
}

checkUser(token, username, claims);
