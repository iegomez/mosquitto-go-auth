function checkSuperuser(token) {
    if(token == "admin") {
        return true;
    }
    return false;
}

checkSuperuser(token);
